"""Feature Engineering Engine — Module 4 of the MLCN pipeline.

Converts completed Module 3 ``Flow`` objects into the 24-feature numerical
vector defined by ``data/common_feature_schema.json``.
"""

from __future__ import annotations

import logging
import statistics
from typing import Iterable, Sequence

from flow_builder.models import Flow
from packet_parsing.models import PacketMetadata

from feature_engineering.models import FeatureVector, coerce_feature_value
from feature_engineering.schema import (
    ACTIVITY_TIMEOUT_SECONDS,
    FEATURE_ORDER,
)

logger = logging.getLogger(__name__)


def _is_forward_packet(flow: Flow, packet: PacketMetadata) -> bool:
    """True when ``packet`` shares the first packet's 5-tuple orientation."""
    if not flow.packets:
        return False
    anchor = flow.packets[0]
    return (
        packet.src_ip == anchor.src_ip
        and packet.dst_ip == anchor.dst_ip
        and packet.src_port == anchor.src_port
        and packet.dst_port == anchor.dst_port
    )


def _ordered_packets(packets: Sequence[PacketMetadata]) -> list[PacketMetadata]:
    """Return packets ordered by timestamp (stable for equal timestamps)."""
    return sorted(packets, key=lambda packet: packet.timestamp.timestamp())


def _timestamps(packets: Sequence[PacketMetadata]) -> list[float]:
    return [packet.timestamp.timestamp() for packet in packets]


def _iat_series(timestamps: Sequence[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]


def _mean_or_zero(values: Sequence[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _sample_std_or_zero(values: Sequence[float]) -> float:
    """Sample standard deviation with ddof=1; 0.0 when fewer than 2 samples."""
    if len(values) < 2:
        return 0.0
    return float(statistics.stdev(values))


def _flag_count(packets: Sequence[PacketMetadata], flag: str) -> int:
    count = 0
    for packet in packets:
        flags = packet.tcp_flags
        if flags and flag in flags.upper():
            count += 1
    return count


def _safe_duration(flow: Flow) -> float:
    """Flow duration in seconds, clamped to >= 0 for clock skew."""
    return max(0.0, float(flow.duration))


def _active_idle_durations(
    packets: Sequence[PacketMetadata],
    *,
    activity_timeout: float = ACTIVITY_TIMEOUT_SECONDS,
) -> tuple[list[float], list[float]]:
    """
    Split a flow into active and idle periods using the schema threshold.

    Active periods are contiguous spans where consecutive packet gaps are
    ``<= activity_timeout``. When a gap exceeds the threshold the current
    active span (if duration > 0) is recorded, the gap is recorded as idle,
    and a new active span starts. The trailing active period is finalized
    at the last packet. No synthetic idle is appended at flow close.
    """
    if not packets:
        return [], []

    ordered = _ordered_packets(packets)
    times = _timestamps(ordered)
    active_periods: list[float] = []
    idle_periods: list[float] = []
    start_active = times[0]
    end_active = times[0]

    for current in times[1:]:
        gap = current - end_active
        if gap > activity_timeout:
            active_span = end_active - start_active
            if active_span > 0:
                active_periods.append(active_span)
            idle_periods.append(gap)
            start_active = current
            end_active = current
        else:
            end_active = current

    final_active = end_active - start_active
    if final_active > 0:
        active_periods.append(final_active)
    return active_periods, idle_periods


def compute_feature_map(
    flow: Flow,
    *,
    activity_timeout: float = ACTIVITY_TIMEOUT_SECONDS,
) -> dict[str, float]:
    """
    Compute the 24 retained features as a name→value mapping.

    Edge cases follow ``data/common_feature_schema.json`` (zero division,
    empty/single-packet flows, missing TCP flags, active/idle threshold).
    """
    packets = list(flow.packets)
    ordered = _ordered_packets(packets) if packets else []
    duration = _safe_duration(flow)
    lengths = [max(0, int(packet.length)) for packet in ordered]
    all_iat = _iat_series(_timestamps(ordered))

    forward_packets = [p for p in ordered if _is_forward_packet(flow, p)]
    reverse_packets = [p for p in ordered if not _is_forward_packet(flow, p)]
    fwd_iat = _iat_series(_timestamps(forward_packets))
    bwd_iat = _iat_series(_timestamps(reverse_packets))
    active_periods, idle_periods = _active_idle_durations(
        ordered,
        activity_timeout=activity_timeout,
    )

    fwd_count = int(flow.forward_packet_count)
    rev_count = int(flow.reverse_packet_count)

    return {
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_count,
        "Total Backward Packets": rev_count,
        "Fwd Packets Length Total": int(flow.forward_byte_count),
        "Bwd Packets Length Total": int(flow.reverse_byte_count),
        "Fwd Packet Length Mean": (
            flow.forward_byte_count / fwd_count if fwd_count else 0.0
        ),
        "Bwd Packet Length Mean": (
            flow.reverse_byte_count / rev_count if rev_count else 0.0
        ),
        "Flow Bytes/s": (flow.byte_count / duration) if duration > 0 else 0.0,
        "Flow Packets/s": (flow.packet_count / duration) if duration > 0 else 0.0,
        "Flow IAT Mean": _mean_or_zero(all_iat),
        "Flow IAT Std": _sample_std_or_zero(all_iat),
        "Fwd IAT Mean": _mean_or_zero(fwd_iat),
        "Bwd IAT Mean": _mean_or_zero(bwd_iat),
        "Packet Length Mean": _mean_or_zero([float(v) for v in lengths]),
        "Packet Length Std": _sample_std_or_zero([float(v) for v in lengths]),
        "FIN Flag Count": _flag_count(ordered, "F"),
        "SYN Flag Count": _flag_count(ordered, "S"),
        "RST Flag Count": _flag_count(ordered, "R"),
        "PSH Flag Count": _flag_count(ordered, "P"),
        "ACK Flag Count": _flag_count(ordered, "A"),
        "URG Flag Count": _flag_count(ordered, "U"),
        "Down/Up Ratio": (
            (fwd_count / rev_count) if fwd_count > 0 and rev_count > 0 else 0.0
        ),
        "Active Mean": _mean_or_zero(active_periods),
        "Idle Mean": _mean_or_zero(idle_periods),
    }


def extract_features(
    flow: Flow,
    *,
    activity_timeout: float = ACTIVITY_TIMEOUT_SECONDS,
) -> FeatureVector:
    """
    Convert a Module 3 ``Flow`` into a 24-feature ``FeatureVector``.

    Raises:
        TypeError: if ``flow`` is not a ``Flow`` instance.
    """
    if not isinstance(flow, Flow):
        raise TypeError(f"expected Flow, got {type(flow).__name__}")

    try:
        feature_map = compute_feature_map(flow, activity_timeout=activity_timeout)
        values = tuple(
            coerce_feature_value(name, feature_map[name]) for name in FEATURE_ORDER
        )
        return FeatureVector(values=values)
    except Exception:
        logger.debug(
            "feature extraction failed for flow key=%s packet_count=%s",
            getattr(flow, "key", None),
            getattr(flow, "packet_count", None),
            exc_info=True,
        )
        raise


class FeatureEngineeringEngine:
    """
    Stateless engine that maps completed flows to schema-ordered feature vectors.

    ``activity_timeout`` defaults to the schema's 5.0s CICFlowMeter threshold.
    """

    def __init__(self, *, activity_timeout: float = ACTIVITY_TIMEOUT_SECONDS) -> None:
        if activity_timeout <= 0:
            raise ValueError("activity_timeout must be positive")
        self.activity_timeout = float(activity_timeout)

    def extract(self, flow: Flow) -> FeatureVector:
        """Extract features from a single completed flow."""
        return extract_features(flow, activity_timeout=self.activity_timeout)

    def extract_many(self, flows: Iterable[Flow]) -> list[FeatureVector]:
        """Extract features from an iterable of flows, preserving order."""
        results: list[FeatureVector] = []
        for flow in flows:
            results.append(self.extract(flow))
        return results

    def try_extract(self, flow: Flow) -> FeatureVector | None:
        """
        Extract features, returning ``None`` on unexpected failures.

        TypeErrors for non-Flow input still propagate; computation errors
        are logged at DEBUG and yield ``None`` so a live pipeline can continue.
        """
        if not isinstance(flow, Flow):
            raise TypeError(f"expected Flow, got {type(flow).__name__}")
        try:
            return self.extract(flow)
        except Exception:
            logger.debug(
                "try_extract suppressed failure for flow key=%s",
                getattr(flow, "key", None),
                exc_info=True,
            )
            return None
