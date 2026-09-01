"""Orchestrate profile mapping, safe generation, logging, and optional validation."""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from traffic_generator.config import DEFAULT_LOG_DIR
from traffic_generator.parameter_mapper import map_profile_to_parameters
from traffic_generator.profile_loader import load_profiles
from traffic_generator.safety import (
    SafetyError,
    is_loopback_target,
    require_lab_confirmation,
    resolve_target_host,
    validate_port,
    validate_test_limits,
)
from traffic_generator.traffic_generator import build_generator
from traffic_generator.traffic_profile import GeneratorRunLog, GeneratorStats, TrafficParameters
from traffic_generator.lab_server import LabEchoServer
from traffic_generator.validation import LocalValidationRunner, ValidationRecord

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[float, str], None]
StatusCallback = Callable[[str], None]


class TrafficGeneratorController:
    """
    High-level controller for one laboratory IDS test session.

    Separate from M1→M5 — only generates traffic toward an authorized receiver.
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._progress = 0.0
        self._status = "Idle"
        self._last_log: GeneratorRunLog | None = None
        self._validation_runner: LocalValidationRunner | None = None
        self._lab_server: LabEchoServer | None = None
        self._validation_records: list[ValidationRecord] = []
        self._stats = GeneratorStats()
        self._parameters: TrafficParameters | None = None
        self._log_lines: list[str] = []
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def progress(self) -> float:
        with self._lock:
            return self._progress

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def stats(self) -> GeneratorStats:
        with self._lock:
            return GeneratorStats(**self._stats.as_dict())

    @property
    def last_log(self) -> GeneratorRunLog | None:
        return self._last_log

    @property
    def validation_records(self) -> tuple[ValidationRecord, ...]:
        with self._lock:
            return tuple(self._validation_records)

    @property
    def log_lines(self) -> tuple[str, ...]:
        """Thread-safe status/log lines (safe to read from Streamlit main thread)."""
        with self._lock:
            return tuple(self._log_lines)

    def append_log(self, line: str) -> None:
        """Append a log line from any thread without touching Streamlit session state."""
        with self._lock:
            self._log_lines.append(line)
            if len(self._log_lines) > 200:
                self._log_lines = self._log_lines[-200:]

    def stop(self, reason: str = "user_stop") -> None:
        self._stop_event.set()
        with self._lock:
            self._status = f"Stopping ({reason})..."
        if self._validation_runner and self._validation_runner.running:
            self._validation_runner.stop()
            if self._parameters:
                self._validation_records.extend(
                    self._validation_runner.flush_records(self._parameters.profile_name)
                )
        if self._lab_server:
            self._lab_server.stop()
            self._lab_server = None

    def start(
        self,
        *,
        profile_name: str,
        target: str,
        target_port: int,
        duration_seconds: float,
        intensity: float,
        port_scan_start: int,
        port_scan_end: int,
        confirmed: bool,
        confirmation_phrase: str,
        enable_validation: bool = False,
        validation_interface: str | None = None,
        on_progress: ProgressCallback | None = None,
        on_status: StatusCallback | None = None,
    ) -> None:
        if self._running:
            raise RuntimeError("generator already running")

        require_lab_confirmation(confirmed, confirmation_phrase)
        resolved_target = resolve_target_host(target)
        validate_port(target_port)

        document = load_profiles()
        params = map_profile_to_parameters(
            profile_name,
            target_host=resolved_target,
            target_port=target_port,
            duration_seconds=duration_seconds,
            intensity=intensity,
            port_scan_start=port_scan_start,
            port_scan_end=port_scan_end,
            profiles_document=document,
        )
        validate_test_limits(
            duration_seconds=params.duration_seconds,
            connection_rate=params.connection_rate_per_sec,
            port_scan_start=params.port_scan_start if profile_name == "Port Scan" else None,
            port_scan_end=params.port_scan_end if profile_name == "Port Scan" else None,
        )

        self._parameters = params
        self._stop_event.clear()
        self._validation_records.clear()
        self._stats = GeneratorStats()
        with self._lock:
            self._log_lines.clear()
        started_at = datetime.now(timezone.utc)

        run_log = GeneratorRunLog(
            profile_name=profile_name,
            target=f"{resolved_target}:{target_port}",
            started_at=started_at,
            parameters=params.as_dict(),
        )

        if enable_validation:
            if not is_loopback_target(resolved_target):
                raise SafetyError(
                    "validation mode auto-capture only supports loopback/local targets — "
                    "run the receiver pipeline separately for remote Laptop B tests"
                )
            self._lab_server = LabEchoServer(host="127.0.0.1", port=target_port)
            self._lab_server.start()
            self._validation_runner = LocalValidationRunner(interface=validation_interface)
            self._validation_runner.start()
            with self._lock:
                self._status = "Validation receiver + lab echo server started"

        def _progress(fraction: float, message: str) -> None:
            with self._lock:
                self._progress = fraction
                self._status = message
            if on_progress:
                on_progress(fraction, message)
            if on_status:
                on_status(message)

        def _worker() -> None:
            nonlocal run_log
            self._running = True
            _progress(0.0, f"Starting {profile_name} lab test → {resolved_target}")
            try:
                generator = build_generator(params, self._stop_event, _progress)
                stats = generator.run()
                with self._lock:
                    self._stats = stats
                stop_reason = "completed" if not self._stop_event.is_set() else "stopped"
            except Exception as exc:
                stop_reason = "error"
                run_log.error_messages.append(str(exc))
                logger.exception("traffic generator failed")
                _progress(self.progress, f"Error: {exc}")
            else:
                _progress(1.0, "Test complete")
            finally:
                if self._validation_runner and self._validation_runner.running:
                    self._validation_runner.stop()
                    if self._parameters:
                        self._validation_records = self._validation_runner.flush_records(
                            self._parameters.profile_name
                        )
                if self._lab_server:
                    self._lab_server.stop()
                    self._lab_server = None
                run_log.ended_at = datetime.now(timezone.utc)
                run_log.stats = self._stats.as_dict()
                run_log.stop_reason = stop_reason
                self._last_log = run_log
                self._write_log(run_log)
                self._running = False
                with self._lock:
                    self._status = f"Finished ({stop_reason})"

        self._thread = threading.Thread(target=_worker, name="mlcn-traffic-gen", daemon=True)
        self._thread.start()

    def _write_log(self, run_log: GeneratorRunLog) -> None:
        stamp = run_log.started_at.strftime("%Y%m%dT%H%M%S")
        path = self.log_dir / f"run_{run_log.profile_name.replace(' ', '_')}_{stamp}.json"
        try:
            path.write_text(json.dumps(run_log.as_dict(), indent=2), encoding="utf-8")
            logger.info("wrote generator log: %s", path)
        except OSError:
            logger.debug("failed to write generator log", exc_info=True)

    def wait(self, timeout: float | None = None) -> bool:
        if not self._thread:
            return True
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()
