"""Optional local validation: correlate generator profile with receiver M1→M5 output."""

from __future__ import annotations

import logging
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable

from feature_engineering import FEATURE_ORDER
from pipeline import IntrusionDetectionPipeline, PipelineResult
from traffic_generator.traffic_profile import ValidationRecord

logger = logging.getLogger(__name__)


def default_loopback_interface() -> str:
    """Best-effort loopback capture interface for single-machine lab validation."""
    if sys.platform == "win32":
        return r"\Device\NPF_Loopback"
    if sys.platform == "darwin":
        return "lo0"
    return "lo"


class LocalValidationRunner:
    """
    Run the existing receiver pipeline on loopback while lab traffic is generated.

    This does not modify M1→M5 — it only wraps ``IntrusionDetectionPipeline``.
    Cross-machine validation requires running the receiver separately on Laptop B.
    """

    def __init__(
        self,
        *,
        interface: str | None = None,
        inactivity_timeout: float = 10.0,
    ) -> None:
        self.interface = interface or default_loopback_interface()
        self.inactivity_timeout = inactivity_timeout
        self._pipeline: IntrusionDetectionPipeline | None = None
        self._thread: threading.Thread | None = None
        self._results: list[PipelineResult] = []
        self._lock = threading.Lock()
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return

        def on_detection(result: PipelineResult) -> None:
            with self._lock:
                self._results.append(result)
            logger.info(
                "validation capture: %s (conf=%.4f, pkts=%s)",
                result.predicted_class,
                result.confidence,
                result.flow.packet_count,
            )

        self._pipeline = IntrusionDetectionPipeline(
            interface=self.interface,
            inactivity_timeout=self.inactivity_timeout,
            max_duration=120.0,
            on_detection=on_detection,
        )
        self._results.clear()
        self._running = True

        def _run() -> None:
            assert self._pipeline is not None
            try:
                self._pipeline.run_live()
            except Exception:
                logger.debug("validation pipeline stopped", exc_info=True)
            finally:
                self._running = False

        self._thread = threading.Thread(target=_run, name="mlcn-validation", daemon=True)
        self._thread.start()
        # Allow capture engine to initialize.
        time.sleep(0.5)

    def stop(self) -> list[PipelineResult]:
        if not self._pipeline:
            return []
        try:
            self._pipeline.close()
        except Exception:
            logger.debug("validation pipeline close failed", exc_info=True)
        if self._thread:
            self._thread.join(timeout=5.0)
        self._running = False
        with self._lock:
            return list(self._results)

    def flush_records(
        self,
        target_profile: str,
    ) -> list[ValidationRecord]:
        """Convert captured pipeline results into validation records."""
        with self._lock:
            results = list(self._results)
        records: list[ValidationRecord] = []
        for result in results:
            features = result.features.as_dict()
            records.append(
                ValidationRecord(
                    target_profile=target_profile,
                    predicted_class=result.predicted_class,
                    confidence=result.confidence,
                    probabilities=dict(result.detection.probabilities),
                    observed_features={name: float(features[name]) for name in FEATURE_ORDER},
                    flow_packet_count=result.flow.packet_count,
                    flow_byte_count=float(result.flow.byte_count),
                    flow_duration=float(result.flow.duration),
                    recorded_at=datetime.now(timezone.utc),
                )
            )
        return records


def summarize_validation(records: list[ValidationRecord]) -> dict[str, object]:
    """Aggregate validation outcomes for UI display."""
    if not records:
        return {
            "count": 0,
            "matches": 0,
            "match_rate": 0.0,
            "predictions": {},
        }
    predictions: dict[str, int] = {}
    matches = 0
    for record in records:
        predictions[record.predicted_class] = predictions.get(record.predicted_class, 0) + 1
        if record.predicted_class == record.target_profile:
            matches += 1
    return {
        "count": len(records),
        "matches": matches,
        "match_rate": matches / len(records),
        "predictions": predictions,
    }


def format_validation_table(records: list[ValidationRecord]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for record in records:
        rows.append(
            {
                "target_profile": record.target_profile,
                "predicted_class": record.predicted_class,
                "confidence": round(record.confidence, 4),
                "match": record.predicted_class == record.target_profile,
                "flow_packets": record.flow_packet_count,
                "flow_duration_s": round(record.flow_duration, 3),
            }
        )
    return rows
