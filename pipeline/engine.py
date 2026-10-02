"""
MLCN end-to-end orchestration: Modules 1–5 wired through existing public APIs.

Does not reimplement capture, parsing, flow assembly, feature engineering, or
detection — it only connects them and manages lifecycle (flush / cleanup).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from feature_engineering import FeatureEngineeringEngine, FeatureVector
from feature_engineering.contract import (
    CLASSIFIED_PROTOCOLS,
    FLOW_TIMEOUT_SECONDS,
    MIN_FLOW_PACKETS,
    TERMINATE_FLOW_ON_FIN,
)
from flow_builder import Flow, FlowBuilder
from ml_detection import DetectionResult, MLDetectionEngine
from packet_capture import PacketCaptureEngine
from packet_parsing import PacketMetadata, parse_packet

from pipeline.models import PipelineResult

logger = logging.getLogger(__name__)

DetectionCallback = Callable[[PipelineResult], None]
# Display-only hook applied to results just before ``on_detection``; stored
# ``results`` always keep the genuine model output.
DisplayTransform = Callable[[PipelineResult], PipelineResult]


def _lab_port_range(port: int, span: int) -> range:
    return range(port, port + max(1, span))


def _flow_involves_port(flow: Flow, port: int, span: int = 1) -> bool:
    ports = _lab_port_range(port, span)
    return flow.src_port in ports or flow.dst_port in ports


def _lab_bpf_filter(port: int, span: int = 1) -> str:
    if span <= 1:
        return f"tcp port {port}"
    return f"tcp portrange {port}-{port + span - 1}"


def _is_classifiable(flow: Flow) -> bool:
    """Flows CICFlowMeter would have emitted into the training CSVs."""
    return flow.packet_count >= MIN_FLOW_PACKETS and flow.protocol in CLASSIFIED_PROTOCOLS


class IntrusionDetectionPipeline:
    """
    Orchestrate:

    raw packet / live capture
      → Module 2 ``PacketMetadata``
      → Module 3 ``Flow``
      → Module 4 ``FeatureVector``
      → Module 5 ``DetectionResult``
    """

    def __init__(
        self,
        *,
        interface: str | None = None,
        inactivity_timeout: float = 60.0,
        max_duration: float = FLOW_TIMEOUT_SECONDS,
        max_active_flows: int = 100_000,
        model_path: str | Path | None = None,
        features_meta_path: str | Path | None = None,
        on_detection: DetectionCallback | None = None,
        lab_port: int | None = None,
        lab_port_span: int = 1,
        display_transform: DisplayTransform | None = None,
    ) -> None:
        self.interface = interface
        self.lab_port = lab_port
        self.lab_port_span = max(1, int(lab_port_span))
        self._bpf_filter = _lab_bpf_filter(lab_port, self.lab_port_span) if lab_port else None
        self._display_transform = display_transform
        self._builder = FlowBuilder(
            inactivity_timeout=inactivity_timeout,
            max_duration=max_duration,
            max_active_flows=max_active_flows,
            terminate_on_fin=TERMINATE_FLOW_ON_FIN,
        )
        self._features = FeatureEngineeringEngine()
        self._detector = MLDetectionEngine(
            model_path=model_path,
            features_meta_path=features_meta_path,
        )
        self._on_detection = on_detection
        self._results: list[PipelineResult] = []
        self._packets_accepted = 0
        self._packets_skipped = 0
        self._flows_detected = 0
        self._flows_skipped = 0
        self._closed = False

    @property
    def active_flow_count(self) -> int:
        return self._builder.active_count

    @property
    def results(self) -> tuple[PipelineResult, ...]:
        """All detections produced since construction or :meth:`reset`."""
        return tuple(self._results)

    @property
    def packets_accepted(self) -> int:
        return self._packets_accepted

    @property
    def packets_skipped(self) -> int:
        return self._packets_skipped

    @property
    def flows_detected(self) -> int:
        return self._flows_detected

    @property
    def flows_skipped(self) -> int:
        """Completed flows not classified (too few packets or non TCP/UDP)."""
        return self._flows_skipped

    def reset(self) -> None:
        """Drop accumulated results and reopen for a new run (flushes active flows)."""
        if self._builder.active_count:
            self.flush()
        self._results.clear()
        self._packets_accepted = 0
        self._packets_skipped = 0
        self._flows_detected = 0
        self._flows_skipped = 0
        self._closed = False

    def process_metadata(self, metadata: PacketMetadata | None) -> list[PipelineResult]:
        """
        Feed one Module 2 packet into Module 3 and detect any completed flows.

        ``None`` / invalid inputs are skipped (same policy as Module 3).
        """
        if self._closed:
            raise RuntimeError("pipeline is closed; create a new instance or call reset()")

        if metadata is None or not isinstance(metadata, PacketMetadata):
            self._packets_skipped += 1
            return []

        self._packets_accepted += 1
        completed = self._builder.add_packet(metadata)
        return self._detect_flows(completed)

    def process_raw_packet(self, raw_packet: Any) -> list[PipelineResult]:
        """Parse a raw Scapy packet via Module 2, then process metadata."""
        metadata = parse_packet(raw_packet)
        if metadata is None:
            self._packets_skipped += 1
            return []
        return self.process_metadata(metadata)

    def process_raw_packets(
        self,
        raw_packets: Iterable[Any],
        *,
        flush: bool = True,
    ) -> list[PipelineResult]:
        """
        Offline batch path: raw packets → full M2–M5 pipeline.

        When ``flush`` is True (default), remaining active flows are closed and
        detected at the end of the batch.
        """
        results: list[PipelineResult] = []
        for raw in raw_packets:
            results.extend(self.process_raw_packet(raw))
        if flush:
            results.extend(self.flush())
        return results

    def process_metadata_batch(
        self,
        packets: Iterable[PacketMetadata | None],
        *,
        flush: bool = True,
    ) -> list[PipelineResult]:
        """Offline path starting from already-parsed Module 2 metadata."""
        results: list[PipelineResult] = []
        for metadata in packets:
            results.extend(self.process_metadata(metadata))
        if flush:
            results.extend(self.flush())
        return results

    def flush(self) -> list[PipelineResult]:
        """Close all active Module 3 flows and run M4→M5 on each."""
        completed = self._builder.flush()
        return self._detect_flows(completed)

    def close(self) -> list[PipelineResult]:
        """
        End-of-run cleanup: flush remaining flows and mark the pipeline closed.

        Safe to call multiple times; subsequent process_* calls raise until
        :meth:`reset`.
        """
        results = self.flush() if not self._closed else []
        self._closed = True
        logger.debug(
            "pipeline closed accepted=%s skipped=%s flows=%s active=%s",
            self._packets_accepted,
            self._packets_skipped,
            self._flows_detected,
            self._builder.active_count,
        )
        return results

    def run_live(self) -> list[PipelineResult]:
        """
        Live path: Module 1 capture → M2–M5 until Ctrl+C / SIGTERM, then flush.

        Requires elevated privileges / Npcap on Windows. Returns all detections
        from the session including the shutdown flush.
        """
        if self._closed:
            raise RuntimeError("pipeline is closed; create a new instance or call reset()")

        capture = PacketCaptureEngine(
            interface=self.interface,
            bpf_filter=self._bpf_filter,
        )
        session: list[PipelineResult] = []

        def on_metadata(metadata: PacketMetadata) -> None:
            for result in self.process_metadata(metadata):
                session.append(result)

        try:
            logger.debug(
                "starting live pipeline on interface=%s",
                self.interface or "default",
            )
            capture.capture_metadata(on_metadata)
        finally:
            session.extend(self.close())
        return session

    def _detect_flows(self, flows: Sequence[Flow]) -> list[PipelineResult]:
        results: list[PipelineResult] = []
        for flow in flows:
            if not _is_classifiable(flow):
                self._flows_skipped += 1
                continue
            try:
                result = self._detect_one(flow)
            except Exception:
                logger.debug(
                    "detection failed for flow protocol=%s packets=%s",
                    getattr(flow, "protocol", None),
                    getattr(flow, "packet_count", None),
                    exc_info=True,
                )
                continue
            results.append(result)
            self._results.append(result)
            self._flows_detected += 1
            self._emit(result)
        return results

    def _detect_one(self, flow: Flow) -> PipelineResult:
        features: FeatureVector = self._features.extract(flow)
        detection: DetectionResult = self._detector.predict(features)
        return PipelineResult(flow=flow, features=features, detection=detection)

    def _emit(self, result: PipelineResult) -> None:
        if self._on_detection is None:
            return
        if self.lab_port is not None and not _flow_involves_port(
            result.flow, self.lab_port, self.lab_port_span
        ):
            return
        if self._display_transform is not None:
            try:
                result = self._display_transform(result)
            except Exception:
                logger.debug("display transform failed; showing genuine result", exc_info=True)
        try:
            self._on_detection(result)
        except Exception:
            logger.debug("on_detection callback failed", exc_info=True)
