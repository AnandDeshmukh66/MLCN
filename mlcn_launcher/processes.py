"""Child process commands and lifecycle for the MLCN launcher."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from demo_fallback.fallback import DEMO_FALLBACK_ENV
from demo_fallback.session import SESSION_FILE_ENV
from traffic_generator.connectivity import SINGLE_PC_ENV

REPO_ROOT = Path(__file__).resolve().parents[1]
STREAMLIT_APP = Path("traffic_generator") / "streamlit_app.py"


@dataclass(frozen=True)
class LaunchConfig:
    python: str
    capture_interfaces: tuple[str, ...]
    repo_root: Path = REPO_ROOT
    lab_port: int = 8080
    lab_port_span: int = 50
    inactivity_timeout: float = 5.0
    streamlit_port: int = 8501
    demo_fallback: bool = True
    detections_file: str = "detections.jsonl"

    @property
    def logs_dir(self) -> Path:
        return self.repo_root / "logs" / "launcher"

    @property
    def detections_log(self) -> Path:
        return self.logs_dir / self.detections_file

    @property
    def demo_session_file(self) -> Path:
        return self.logs_dir / "demo_session.json"

    @property
    def streamlit_log(self) -> Path:
        return self.logs_dir / "streamlit.log"

    @property
    def streamlit_url(self) -> str:
        return f"http://localhost:{self.streamlit_port}"


def pipeline_command(cfg: LaunchConfig) -> list[str]:
    command = [
        cfg.python,
        "-u",
        "-m",
        "pipeline",
        "-i",
        ",".join(cfg.capture_interfaces),
        "--lab-port",
        str(cfg.lab_port),
        "--lab-port-span",
        str(cfg.lab_port_span),
        "--inactivity-timeout",
        f"{cfg.inactivity_timeout:g}",
        "--detections-log",
        str(cfg.detections_log),
    ]
    if cfg.demo_fallback:
        command.append("--demo-fallback")
    return command


def streamlit_command(cfg: LaunchConfig) -> list[str]:
    return [
        cfg.python,
        "-m",
        "streamlit",
        "run",
        str(STREAMLIT_APP),
        "--server.port",
        str(cfg.streamlit_port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]


def child_environment(cfg: LaunchConfig, base: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            # Child stdout is a pipe/file; force UTF-8 so non-ASCII output cannot crash it.
            "PYTHONUTF8": "1",
            SINGLE_PC_ENV: "1",
            DEMO_FALLBACK_ENV: "1" if cfg.demo_fallback else "0",
            SESSION_FILE_ENV: str(cfg.demo_session_file),
        }
    )
    return env


def creation_flags() -> int:
    """Own process group (no new window) so Ctrl+Break can target one child."""
    if sys.platform == "win32":
        return subprocess.CREATE_NEW_PROCESS_GROUP
    return 0


class ManagedProcess:
    """A child process with prefixed output streaming and graceful stop."""

    def __init__(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        log_file: Path | None = None,
        sink: Callable[[str], None] = print,
    ) -> None:
        self.name = name
        self.command = command
        self._cwd = cwd
        self._env = dict(env)
        self._log_file = log_file
        self._sink = sink
        self._process: subprocess.Popen[str] | None = None
        self._log_handle: IO[str] | None = None
        self._reader: threading.Thread | None = None

    @property
    def returncode(self) -> int | None:
        return None if self._process is None else self._process.poll()

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> None:
        if self._log_file is not None:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = self._log_file.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            self.command,
            cwd=self._cwd,
            env=self._env,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle or subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creation_flags(),
        )
        if self._log_handle is None:
            self._reader = threading.Thread(target=self._pump, name=f"{self.name}-output", daemon=True)
            self._reader.start()

    def _pump(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        for line in self._process.stdout:
            self._sink(f"[{self.name}] {line.rstrip()}")

    def stop(self, timeout: float = 8.0) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            try:
                if sys.platform == "win32":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.send_signal(signal.SIGINT)
                process.wait(timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3.0)
        if self._reader is not None:
            self._reader.join(timeout=2.0)
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
