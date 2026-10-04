"""Feature Engineering Engine — Module 4 of the MLCN pipeline.

Converts completed Module 3 ``Flow`` objects into the 24-feature vector defined
by :mod:`feature_engineering.contract` (CICFlowMeter / CIC-IDS2017 semantics:
microsecond timings, payload-byte lengths, first-packet binary flags).
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from flow_builder.models import Flow
from packet_parsing.models import PacketMetadata

from feature_engineering.contract import (
    CIC_FLAG_COLUMN_SOURCE,
    MICROSECONDS_PER_SECOND,
    ZERO_DURATION_RATE_FILL,
)
from feature_engineering.models import FeatureVector, coerce_feature_value
from feature_engineering.schema import (
    ACTIVITY_TIMEOUT_SECONDS,
    FEATURE_ORDER,
)

logger = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_MICROSECOND = timedelta(microseconds=1)


def _micros(ts: datetime) -> int:
    """Exact integer microseconds since the epoch (CICFlowMeter timestamp unit)."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (ts - _EPOCH) // _ONE_MICROSECOND


def _same_orientation(anchor: PacketMetadata, packet: PacketMetadata) -> bool:
    return (
        packet.src_ip == anchor.src_ip
        and packet.dst_ip == anchor.dst_ip
        and packet.src_port == anchor.src_port
        and packet.dst_port == anchor.dst_port
    )


def _payload_bytes(packet: PacketMetadata) -> int:
    value = packet.payload_length if packet.payload_length is not None else packet.length
    return max(0, int(value))


def _ordered_packets(packets: Sequence[PacketMetadata]) -> list[PacketMetadata]:
    """Return packets ordered by timestamp (stable for equal timestamps)."""
    return sorted(packets, key=lambda packet: _micros(packet.timestamp))


def _gaps(times: Sequence[int]) -> list[int]:
    return [times[i] - times[i - 1] for i in range(1, len(times))]


def _mean_or_zero(values: Sequence[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _sample_std_or_zero(values: Sequence[float]) -> float:
    """Sample standard deviation (ddof=1), 0.0 with fewer than 2 samples."""
    if len(values) < 2:
        return 0.0
    return float(statistics.stdev(values))


def _first_packet_flags(first: PacketMetadata) -> dict[str, int]:
    flags = (first.tcp_flags or "").upper() if first.protocol == "TCP" else ""
    return {
        column: int(letter in flags) for column, letter in CIC_FLAG_COLUMN_SOURCE.items()
    }


def _active_idle_periods(
    times: Sequence[int],
    *,
    activity_timeout_us: int,
    closed_by_fin: bool,
) -> tuple[list[int], list[int]]:
    """
    CICFlowMeter active/idle: a gap > threshold records the preceding active span
    (if > 0) and the gap as idle. The trailing active span is never recorded and
    the FIN packet that closed the flow does not update the state.
    """
    if not times:
        return [], []
    updates = times[1:-1] if closed_by_fin else times[1:]
    active: list[int] = []
    idle: list[int] = []
    start_active = end_active = times[0]
    for current in updates:
        gap = current - end_active
        if gap > activity_timeout_us:
            if end_active - start_active > 0:
                active.append(end_active - start_active)
            idle.append(gap)
            start_active = end_active = current
        else:
            end_active = current
    return active, idle


def compute_feature_map(
    flow: Flow,
    *,
    activity_timeout: float = ACTIVITY_TIMEOUT_SECONDS,
) -> dict[str, float]:
    """Compute the 24 contract features as a name→value mapping."""
    packets = _ordered_packets(flow.packets)
    if not packets:
        return {name: 0.0 for name in FEATURE_ORDER}

    first = packets[0]
    times = [_micros(packet.timestamp) for packet in packets]
    payloads = [_payload_bytes(packet) for packet in packets]
    forward = [_same_orientation(first, packet) for packet in packets]

    fwd_times = [t for t, is_fwd in zip(times, forward) if is_fwd]
    bwd_times = [t for t, is_fwd in zip(times, forward) if not is_fwd]
    fwd_payload = [b for b, is_fwd in zip(payloads, forward) if is_fwd]
    bwd_payload = [b for b, is_fwd in zip(payloads, forward) if not is_fwd]
    fwd_count = len(fwd_payload)
    bwd_count = len(bwd_payload)

    duration_us = max(0, times[-1] - times[0])
    duration_s = duration_us / MICROSECONDS_PER_SECOND
    flow_iat = _gaps(times)
    length_series = [float(payloads[0])] + [float(b) for b in payloads]
    active, idle = _active_idle_periods(
        times,
        activity_timeout_us=int(round(activity_timeout * MICROSECONDS_PER_SECOND)),
        closed_by_fin=bool(getattr(flow, "closed_by_fin", False)),
    )

    if duration_us > 0:
        bytes_per_s = sum(payloads) / duration_s
        packets_per_s = len(packets) / duration_s
    else:
        bytes_per_s = ZERO_DURATION_RATE_FILL["Flow Bytes/s"]
        packets_per_s = ZERO_DURATION_RATE_FILL["Flow Packets/s"]

    features: dict[str, float] = {
        "Flow Duration": duration_us,
        "Total Fwd Packets": fwd_count,
        "Total Backward Packets": bwd_count,
        "Fwd Packets Length Total": sum(fwd_payload),
        "Bwd Packets Length Total": sum(bwd_payload),
        "Fwd Packet Length Mean": _mean_or_zero(fwd_payload),
        "Bwd Packet Length Mean": _mean_or_zero(bwd_payload),
        "Flow Bytes/s": bytes_per_s,
        "Flow Packets/s": packets_per_s,
        "Flow IAT Mean": _mean_or_zero(flow_iat),
        "Flow IAT Std": _sample_std_or_zero(flow_iat),
        "Fwd IAT Mean": _mean_or_zero(_gaps(fwd_times)),
        "Bwd IAT Mean": _mean_or_zero(_gaps(bwd_times)),
        "Packet Length Mean": _mean_or_zero(length_series),
        "Packet Length Std": _sample_std_or_zero(length_series),
        "Down/Up Ratio": float(bwd_count // fwd_count) if fwd_count else 0.0,
        "Active Mean": _mean_or_zero(active),
        "Idle Mean": _mean_or_zero(idle),
    }
    features.update(_first_packet_flags(first))
    return features


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
