"""
Common feature schema specification and validation for MLCN Step 8.

Documents the 24 CIC-IDS2017 (CICFlowMeter) features the XGBoost model was
trained on and how each is derived from Module 2 PacketMetadata and Module 3
Flow. Units and data types come from ``feature_engineering.contract`` (the
contract verified against the training data), so this document cannot drift
from what the live pipeline produces. ``_reference_feature_values`` is an
independent re-implementation used to cross-check Module 4.
"""

from __future__ import annotations

import dataclasses
import json
import math
import statistics
import sys
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from feature_engineering.contract import (
    ACTIVITY_TIMEOUT_SECONDS,
    CLASSIFIED_PROTOCOLS,
    FEATURE_SPECS,
    FLOW_TIMEOUT_SECONDS,
    MIN_FLOW_PACKETS,
    TERMINATE_FLOW_ON_FIN,
    ZERO_DURATION_RATE_FILL,
)
from flow_builder.models import Flow, FlowKey
from packet_parsing.models import PacketMetadata

SCHEMA_VERSION = "2.0.0"

# Stable artifact paths relative to the repository root.
DEFAULT_SCHEMA_PATH = Path("data/common_feature_schema.json")
DEFAULT_REPORT_PATH = Path("data/common_feature_schema_report.md")

_CONTRACT = {spec.name: spec for spec in FEATURE_SPECS}

# Rejected candidate (not in the contract): same payload sum as Packet Length Mean.
_AVERAGE_PACKET_SIZE = ("float", "payload bytes")

_PAYLOAD_SOURCES = ("Flow.packets", "Flow.packets[].payload_length", "Flow.packets[].length")
_DIRECTION_SOURCES = (
    "Flow.packets",
    "Flow.packets[].timestamp",
    "Flow.packets[].src_ip",
    "Flow.packets[].dst_ip",
    "Flow.packets[].src_port",
    "Flow.packets[].dst_port",
)
_FIRST_PACKET_FLAG_SOURCES = ("Flow.packets", "Flow.packets[].tcp_flags", "Flow.packets[].protocol")

# CICFlowMeter 2017 writes first-packet TCP bits into permuted columns
# (column -> Scapy flag letter). Kept here independently of Module 4 on purpose.
_REFERENCE_FLAG_SOURCE = {
    "FIN Flag Count": "R",
    "SYN Flag Count": "P",
    "RST Flag Count": "C",
    "PSH Flag Count": "S",
    "ACK Flag Count": "A",
    "URG Flag Count": "F",
}


class DerivationKind(str, Enum):
    DIRECT = "direct"
    DERIVED = "derived"


class CICCompatibility(str, Enum):
    COMPATIBLE = "compatible"
    COMPATIBLE_WITH_NOTES = "compatible_with_notes"
    MODIFIED = "modified"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class FeatureDefinition:
    """One finalized common-schema feature."""

    canonical_name: str
    formula: str
    source_fields: tuple[str, ...]
    data_type: str
    unit: str
    derivation: DerivationKind
    edge_case_rules: dict[str, str]
    cicflowmeter: dict[str, str]
    candidate_index: int | None = None
    status: str = "retained"
    modification_notes: str | None = None


@dataclass(frozen=True)
class RejectedFeature:
    candidate_index: int
    canonical_name: str
    reason: str


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    module2_fields_present: tuple[str, ...]
    module3_fields_present: tuple[str, ...]
    derivation_probe_passed: bool


def _packet_metadata_field_names() -> frozenset[str]:
    return frozenset(field.name for field in fields(PacketMetadata))


def _flow_field_names() -> frozenset[str]:
    names = {field.name for field in fields(Flow)}
    names.update({"duration", "protocol", "src_ip", "dst_ip", "src_port", "dst_port"})
    return frozenset(names)


def _resolve_source_field(field_ref: str) -> bool:
    if field_ref.startswith("Flow.packets[]."):
        packet_field = field_ref.removeprefix("Flow.packets[].")
        return packet_field in _packet_metadata_field_names()
    if field_ref.startswith("Flow."):
        return field_ref.removeprefix("Flow.") in _flow_field_names()
    if field_ref.startswith("PacketMetadata."):
        return field_ref.removeprefix("PacketMetadata.") in _packet_metadata_field_names()
    return False


def _edge(*pairs: tuple[str, str]) -> dict[str, str]:
    return dict(pairs)


def _cic(status: CICCompatibility, notes: str) -> dict[str, str]:
    return {"status": status.value, "notes": notes}


def _feature(
    index: int,
    name: str,
    formula: str,
    sources: tuple[str, ...],
    derivation: DerivationKind,
    edges: dict[str, str],
    cic_notes: str,
    *,
    status: CICCompatibility = CICCompatibility.COMPATIBLE,
) -> FeatureDefinition:
    if name in _CONTRACT:
        data_type, unit = _CONTRACT[name].dtype, _CONTRACT[name].unit
    else:
        data_type, unit = _AVERAGE_PACKET_SIZE
    return FeatureDefinition(
        candidate_index=index,
        canonical_name=name,
        formula=formula,
        source_fields=sources,
        data_type=data_type,
        unit=unit,
        derivation=derivation,
        edge_case_rules=edges,
        cicflowmeter=_cic(status, cic_notes),
    )


def _flag_feature(index: int, name: str) -> FeatureDefinition:
    letter = _REFERENCE_FLAG_SOURCE[name]
    return _feature(
        index,
        name,
        f"1 if the first packet is TCP and has flag '{letter}', else 0",
        _FIRST_PACKET_FLAG_SOURCES,
        DerivationKind.DERIVED,
        _edge(
            ("non_tcp_flow", "0 for UDP / non-TCP flows"),
            ("later_packets", "flags of packets after the first are ignored"),
            ("empty_packet_collection", "0 when packet_count is 0"),
        ),
        "CIC-IDS2017 flag columns are binary first-packet bits written into permuted "
        f"columns; this column carries the '{letter}' bit (verified on training rows).",
    )


def build_candidate_feature_definitions() -> list[FeatureDefinition]:
    """Return all 25 candidate features in fixed candidate order."""
    D, R = DerivationKind.DIRECT, DerivationKind.DERIVED
    zero_rate = ZERO_DURATION_RATE_FILL
    return [
        _feature(
            1,
            "Flow Duration",
            "last packet timestamp - first packet timestamp, integer microseconds",
            ("Flow.start_time", "Flow.end_time"),
            D,
            _edge(
                ("zero_duration_flow", "0 when all packets share one timestamp"),
                ("negative_clock_skew", "clamp to 0 if computed duration is negative"),
            ),
            "CICFlowMeter flow duration in microseconds.",
        ),
        _feature(
            2,
            "Total Fwd Packets",
            "count of packets with the first packet's orientation",
            ("Flow.forward_packet_count",),
            D,
            _edge(("empty_packet_collection", "0 when packet_count is 0")),
            "Forward = direction of the first captured packet.",
        ),
        _feature(
            3,
            "Total Backward Packets",
            "count of packets with the opposite orientation",
            ("Flow.reverse_packet_count",),
            D,
            _edge(
                ("zero_backward_packets", "0 when no reverse-direction packets observed"),
                ("empty_packet_collection", "0 when packet_count is 0"),
            ),
            "CIC backward packet count.",
        ),
        _feature(
            4,
            "Fwd Packets Length Total",
            "sum of forward transport payload bytes (Ethernet padding included)",
            _PAYLOAD_SOURCES,
            R,
            _edge(
                ("zero_forward_packets", "0 when forward_packet_count is 0"),
                ("payload_length_missing", "fall back to PacketMetadata.length"),
            ),
            "CIC counts TCP/UDP payload bytes, not wire length.",
        ),
        _feature(
            5,
            "Bwd Packets Length Total",
            "sum of backward transport payload bytes (Ethernet padding included)",
            _PAYLOAD_SOURCES,
            R,
            _edge(
                ("zero_backward_packets", "0 when reverse_packet_count is 0"),
                ("payload_length_missing", "fall back to PacketMetadata.length"),
            ),
            "CIC counts TCP/UDP payload bytes, not wire length.",
        ),
        _feature(
            6,
            "Fwd Packet Length Mean",
            "Fwd Packets Length Total / Total Fwd Packets",
            _PAYLOAD_SOURCES,
            R,
            _edge(("zero_forward_packets", "0.0 when forward_packet_count is 0")),
            "Mean forward payload length.",
        ),
        _feature(
            7,
            "Bwd Packet Length Mean",
            "Bwd Packets Length Total / Total Backward Packets",
            _PAYLOAD_SOURCES,
            R,
            _edge(("zero_backward_packets", "0.0 when reverse_packet_count is 0")),
            "Mean backward payload length.",
        ),
        _feature(
            8,
            "Flow Bytes/s",
            "total payload bytes / (Flow Duration / 1e6)",
            (*_PAYLOAD_SOURCES, "Flow.start_time", "Flow.end_time"),
            R,
            _edge(
                (
                    "zero_duration_flow",
                    f"{zero_rate['Flow Bytes/s']} (training-set median used to fill NaN/inf)",
                ),
            ),
            "Per second although durations are microseconds.",
        ),
        _feature(
            9,
            "Flow Packets/s",
            "packet_count / (Flow Duration / 1e6)",
            ("Flow.packet_count", "Flow.start_time", "Flow.end_time"),
            R,
            _edge(
                (
                    "zero_duration_flow",
                    f"{zero_rate['Flow Packets/s']} (training-set median used to fill NaN/inf)",
                ),
            ),
            "Per second although durations are microseconds.",
        ),
        _feature(
            10,
            "Flow IAT Mean",
            "mean of consecutive packet timestamp gaps, microseconds",
            ("Flow.packets", "Flow.packets[].timestamp"),
            R,
            _edge(("one_packet_flow", "0.0 when packet_count < 2")),
            "Mean inter-arrival time across all flow packets.",
        ),
        _feature(
            11,
            "Flow IAT Std",
            "sample std (ddof=1) of consecutive packet gaps, microseconds",
            ("Flow.packets", "Flow.packets[].timestamp"),
            R,
            _edge(("few_intervals", "0.0 when fewer than 2 inter-arrival intervals exist")),
            "Sample standard deviation of flow inter-arrival times.",
        ),
        _feature(
            12,
            "Fwd IAT Mean",
            "mean gap between consecutive forward packets, microseconds",
            _DIRECTION_SOURCES,
            R,
            _edge(("one_forward_packet", "0.0 when fewer than 2 forward packets exist")),
            "Mean forward-direction inter-arrival time.",
        ),
        _feature(
            13,
            "Bwd IAT Mean",
            "mean gap between consecutive backward packets, microseconds",
            _DIRECTION_SOURCES,
            R,
            _edge(("one_backward_packet", "0.0 when fewer than 2 reverse packets exist")),
            "Mean backward-direction inter-arrival time.",
        ),
        _feature(
            14,
            "Packet Length Mean",
            "mean of [first payload] + every payload (n + 1 values)",
            _PAYLOAD_SOURCES,
            R,
            _edge(("empty_packet_collection", "0.0 when packet_count is 0")),
            "CICFlowMeter adds the first packet's payload twice.",
        ),
        _feature(
            15,
            "Packet Length Std",
            "sample std (ddof=1) of [first payload] + every payload",
            _PAYLOAD_SOURCES,
            R,
            _edge(("empty_packet_collection", "0.0 when packet_count is 0")),
            "Computed over the same n + 1 values as Packet Length Mean.",
        ),
        _flag_feature(16, "FIN Flag Count"),
        _flag_feature(17, "SYN Flag Count"),
        _flag_feature(18, "RST Flag Count"),
        _flag_feature(19, "PSH Flag Count"),
        _flag_feature(20, "ACK Flag Count"),
        _flag_feature(21, "URG Flag Count"),
        _feature(
            22,
            "Average Packet Size",
            "total payload bytes / packet_count",
            (*_PAYLOAD_SOURCES, "Flow.packet_count"),
            R,
            _edge(("empty_packet_collection", "0.0 when packet_count is 0")),
            "CIC Average Packet Size.",
        ),
        _feature(
            23,
            "Down/Up Ratio",
            "floor(Total Backward Packets / Total Fwd Packets)",
            ("Flow.forward_packet_count", "Flow.reverse_packet_count"),
            R,
            _edge(("zero_forward_packets", "0.0 when forward_packet_count is 0")),
            "CICFlowMeter integer division backward / forward.",
        ),
        _feature(
            24,
            "Active Mean",
            (
                "mean active span recorded when a gap > "
                f"{ACTIVITY_TIMEOUT_SECONDS:g} s starts an idle period, microseconds; the "
                "trailing active span is never recorded"
            ),
            ("Flow.packets", "Flow.packets[].timestamp", "Flow.closed_by_fin"),
            R,
            _edge(
                ("no_idle_gap", "0.0 when no gap exceeds the activity timeout"),
                ("closing_fin", "the FIN packet that closed the flow does not update activity"),
            ),
            f"CICFlowMeter {ACTIVITY_TIMEOUT_SECONDS:g} s activity timeout.",
        ),
        _feature(
            25,
            "Idle Mean",
            f"mean gap > {ACTIVITY_TIMEOUT_SECONDS:g} s between packets, microseconds",
            ("Flow.packets", "Flow.packets[].timestamp", "Flow.closed_by_fin"),
            R,
            _edge(
                ("no_idle_gap", "0.0 when no gap exceeds the activity timeout"),
                ("closing_fin", "the FIN packet that closed the flow does not update activity"),
            ),
            f"CICFlowMeter {ACTIVITY_TIMEOUT_SECONDS:g} s activity timeout.",
        ),
    ]


def build_rejected_features() -> list[RejectedFeature]:
    return [
        RejectedFeature(
            candidate_index=22,
            canonical_name="Average Packet Size",
            reason=(
                "Near-duplicate of Packet Length Mean (same payload sum; n instead of "
                "n + 1 values). The trained model uses only Packet Length Mean."
            ),
        ),
    ]


def finalize_feature_list(
    candidates: Sequence[FeatureDefinition],
    rejected: Sequence[RejectedFeature],
) -> list[FeatureDefinition]:
    rejected_indices = {item.candidate_index for item in rejected}
    retained = [
        dataclasses.replace(feature, status="retained")
        for feature in candidates
        if feature.candidate_index not in rejected_indices
    ]
    return retained


def _is_forward_packet(flow: Flow, packet: PacketMetadata) -> bool:
    if not flow.packets:
        return False
    anchor = flow.packets[0]
    return (
        packet.src_ip == anchor.src_ip
        and packet.dst_ip == anchor.dst_ip
        and packet.src_port == anchor.src_port
        and packet.dst_port == anchor.dst_port
    )


def _microsecond_timestamps(packets: Sequence[PacketMetadata]) -> list[int]:
    return [int(round(packet.timestamp.timestamp() * 1_000_000)) for packet in packets]


def _gaps(timestamps: Sequence[int]) -> list[int]:
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]


def _mean_or_zero(values: Sequence[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _sample_std_or_zero(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    return float(statistics.stdev(values))


def _payload(packet: PacketMetadata) -> int:
    value = packet.payload_length if packet.payload_length is not None else packet.length
    return max(0, int(value))


def _active_idle_durations(flow: Flow) -> tuple[list[int], list[int]]:
    times = _microsecond_timestamps(flow.packets)
    if not times:
        return [], []
    threshold = ACTIVITY_TIMEOUT_SECONDS * 1_000_000
    updates = times[1:-1] if flow.closed_by_fin else times[1:]
    active_periods: list[int] = []
    idle_periods: list[int] = []
    start_active = end_active = times[0]
    for current in updates:
        gap = current - end_active
        if gap > threshold:
            if end_active - start_active > 0:
                active_periods.append(end_active - start_active)
            idle_periods.append(gap)
            start_active = end_active = current
        else:
            end_active = current
    return active_periods, idle_periods


def _reference_feature_values(flow: Flow) -> dict[str, float | int]:
    """Independent CIC-semantics computation used to cross-check Module 4."""
    packets = flow.packets
    if not packets:
        return {spec.name: 0 for spec in FEATURE_SPECS}

    times = _microsecond_timestamps(packets)
    duration_us = max(0, max(times) - min(times))
    payloads = [_payload(packet) for packet in packets]
    forward = [_is_forward_packet(flow, packet) for packet in packets]
    fwd_payload = [b for b, is_fwd in zip(payloads, forward) if is_fwd]
    bwd_payload = [b for b, is_fwd in zip(payloads, forward) if not is_fwd]
    fwd_times = [t for t, is_fwd in zip(times, forward) if is_fwd]
    bwd_times = [t for t, is_fwd in zip(times, forward) if not is_fwd]
    lengths = [payloads[0], *payloads]
    active_periods, idle_periods = _active_idle_durations(flow)

    first = packets[0]
    first_flags = (first.tcp_flags or "").upper() if first.protocol == "TCP" else ""
    seconds = duration_us / 1_000_000

    values: dict[str, float | int] = {
        "Flow Duration": duration_us,
        "Total Fwd Packets": len(fwd_payload),
        "Total Backward Packets": len(bwd_payload),
        "Fwd Packets Length Total": sum(fwd_payload),
        "Bwd Packets Length Total": sum(bwd_payload),
        "Fwd Packet Length Mean": _mean_or_zero(fwd_payload),
        "Bwd Packet Length Mean": _mean_or_zero(bwd_payload),
        "Flow Bytes/s": (
            sum(payloads) / seconds if duration_us else ZERO_DURATION_RATE_FILL["Flow Bytes/s"]
        ),
        "Flow Packets/s": (
            len(packets) / seconds if duration_us else ZERO_DURATION_RATE_FILL["Flow Packets/s"]
        ),
        "Flow IAT Mean": _mean_or_zero(_gaps(times)),
        "Flow IAT Std": _sample_std_or_zero(_gaps(times)),
        "Fwd IAT Mean": _mean_or_zero(_gaps(fwd_times)),
        "Bwd IAT Mean": _mean_or_zero(_gaps(bwd_times)),
        "Packet Length Mean": _mean_or_zero(lengths),
        "Packet Length Std": _sample_std_or_zero(lengths),
        "Down/Up Ratio": float(len(bwd_payload) // len(fwd_payload)) if fwd_payload else 0.0,
        "Active Mean": _mean_or_zero(active_periods),
        "Idle Mean": _mean_or_zero(idle_periods),
    }
    for column, letter in _REFERENCE_FLAG_SOURCE.items():
        values[column] = int(letter in first_flags)
    return values


def _probe_ts(seconds: float) -> datetime:
    return datetime.fromtimestamp(1_700_000_000.0 + seconds, tz=timezone.utc)


def _probe_meta(
    *,
    at: float,
    length: int = 100,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int | None = 54321,
    dst_port: int | None = 80,
    tcp_flags: str | None = "A",
    protocol: str = "TCP",
    payload_length: int | None = None,
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=_probe_ts(at),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        tcp_flags=tcp_flags if protocol == "TCP" else None,
        ttl=64,
        tcp_window=8192 if protocol == "TCP" else None,
        payload_length=payload_length,
    )


def _probe_reverse(**kwargs: Any) -> PacketMetadata:
    return _probe_meta(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=54321, **kwargs)


def _probe_flow(packets: Sequence[PacketMetadata], *, closed_by_fin: bool = False) -> Flow:
    anchor = packets[0]
    key = FlowKey(
        src_ip=anchor.src_ip or "",
        dst_ip=anchor.dst_ip or "",
        src_port=anchor.src_port,
        dst_port=anchor.dst_port,
        protocol=anchor.protocol,
    )
    forward = [
        (p.src_ip, p.dst_ip, p.src_port, p.dst_port)
        == (anchor.src_ip, anchor.dst_ip, anchor.src_port, anchor.dst_port)
        for p in packets
    ]
    fwd_bytes = sum(p.length for p, is_fwd in zip(packets, forward) if is_fwd)
    rev_bytes = sum(p.length for p, is_fwd in zip(packets, forward) if not is_fwd)
    return Flow(
        key=key,
        start_time=packets[0].timestamp,
        end_time=packets[-1].timestamp,
        packet_count=len(packets),
        byte_count=fwd_bytes + rev_bytes,
        forward_packet_count=sum(forward),
        reverse_packet_count=len(packets) - sum(forward),
        forward_byte_count=fwd_bytes,
        reverse_byte_count=rev_bytes,
        packets=tuple(packets),
        closed_by_fin=closed_by_fin,
    )


def _make_probe_flows() -> list[Flow]:
    """Synthetic flows covering the contract's edge cases."""
    return [
        _probe_flow((_probe_meta(at=0.0, length=60, tcp_flags="S"),)),
        _probe_flow(
            (
                _probe_meta(at=0.0, length=0, tcp_flags="S"),
                _probe_reverse(at=0.000066, length=6, tcp_flags="RA"),
            )
        ),
        _probe_flow(
            (
                _probe_meta(at=0.0, length=60, tcp_flags="S"),
                _probe_reverse(at=1.0, length=40, tcp_flags="SA"),
                _probe_meta(at=2.0, length=80, tcp_flags="PA", payload_length=26),
                _probe_reverse(at=2.5, length=11607, tcp_flags="PA"),
                _probe_reverse(at=2.6, length=0, tcp_flags="A"),
            )
        ),
        _probe_flow(
            (
                _probe_meta(at=0.0, length=50, tcp_flags="S"),
                _probe_meta(at=1.0, length=50, tcp_flags="A"),
                _probe_meta(at=10.0, length=50, tcp_flags="A"),
                _probe_meta(at=11.0, length=50, tcp_flags="A"),
                _probe_meta(at=30.0, length=0, tcp_flags="FA"),
            ),
            closed_by_fin=True,
        ),
        _probe_flow(
            (
                _probe_meta(at=5.0, length=80, tcp_flags="PA"),
                _probe_meta(at=5.0, length=120, tcp_flags="A"),
            )
        ),
        _probe_flow(
            (
                _probe_meta(at=0.0, length=200, protocol="UDP", src_port=1000, dst_port=53),
                _probe_meta(
                    at=0.2,
                    length=300,
                    protocol="UDP",
                    src_ip="10.0.0.2",
                    dst_ip="10.0.0.1",
                    src_port=53,
                    dst_port=1000,
                ),
            )
        ),
    ]


def probe_derivation(
    retained: Sequence[FeatureDefinition],
    flows: Sequence[Flow] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    probe_flows = list(flows or _make_probe_flows())
    retained_names = [feature.canonical_name for feature in retained]

    for flow in probe_flows:
        try:
            values = _reference_feature_values(flow)
        except Exception as exc:  # noqa: BLE001 - collect probe failures
            errors.append(f"derivation probe raised on sample flow: {exc}")
            continue

        for name in retained_names:
            if name not in values:
                errors.append(f"derivation probe missing value for {name!r}")
                continue
            value = values[name]
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                errors.append(
                    f"derivation probe produced non-finite value for {name!r}: {value}"
                )

    return (len(errors) == 0, tuple(errors))


def validate_schema(
    candidates: Sequence[FeatureDefinition],
    retained: Sequence[FeatureDefinition],
    rejected: Sequence[RejectedFeature],
) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    module2_fields = tuple(sorted(_packet_metadata_field_names()))
    module3_fields = tuple(sorted(_flow_field_names()))

    required_packet_fields = {
        "timestamp",
        "length",
        "payload_length",
        "tcp_flags",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
    }
    required_flow_fields = {
        "start_time",
        "end_time",
        "packet_count",
        "byte_count",
        "forward_packet_count",
        "reverse_packet_count",
        "forward_byte_count",
        "reverse_byte_count",
        "packets",
        "closed_by_fin",
    }

    missing_packet = sorted(required_packet_fields - _packet_metadata_field_names())
    missing_flow = sorted(required_flow_fields - _flow_field_names())
    if missing_packet:
        errors.append(f"Module 2 missing required fields: {missing_packet}")
    if missing_flow:
        errors.append(f"Module 3 missing required fields: {missing_flow}")

    if len(candidates) != 25:
        errors.append(f"expected 25 candidate features, got {len(candidates)}")

    retained_names = [feature.canonical_name for feature in retained]
    if len(retained_names) != len(set(retained_names)):
        errors.append("duplicate canonical feature names in retained list")

    expected_order = [
        feature.canonical_name
        for feature in candidates
        if feature.candidate_index not in {r.candidate_index for r in rejected}
    ]
    if retained_names != expected_order:
        errors.append("retained feature ordering is unstable or does not match candidate order")
    if retained_names != [spec.name for spec in FEATURE_SPECS]:
        errors.append("retained features do not match the model contract order")

    for feature in retained:
        if not feature.formula.strip():
            errors.append(f"{feature.canonical_name}: missing formula")
        if not feature.edge_case_rules:
            errors.append(f"{feature.canonical_name}: missing edge-case rules")
        if not feature.source_fields:
            errors.append(f"{feature.canonical_name}: missing source fields")
        for source in feature.source_fields:
            if not _resolve_source_field(source):
                errors.append(f"{feature.canonical_name}: unknown source field {source!r}")
        if feature.data_type == "duration":
            errors.append(f"{feature.canonical_name}: invalid data_type 'duration'")
        spec = _CONTRACT.get(feature.canonical_name)
        if spec is not None and (feature.unit, feature.data_type) != (spec.unit, spec.dtype):
            errors.append(
                f"{feature.canonical_name}: unit/type {feature.unit}/{feature.data_type} "
                f"differs from contract {spec.unit}/{spec.dtype}"
            )

    rejected_indices = {item.candidate_index for item in rejected}
    for feature in candidates:
        if feature.candidate_index in rejected_indices and feature.canonical_name not in {
            r.canonical_name for r in rejected
        }:
            errors.append(
                f"rejected index {feature.candidate_index} lacks rejection record"
            )

    probe_ok, probe_errors = probe_derivation(retained)
    errors.extend(probe_errors)

    if len(retained) + len(rejected) != len(candidates):
        errors.append("retained plus rejected counts do not cover all candidates")

    return ValidationResult(
        passed=len(errors) == 0,
        errors=tuple(errors),
        warnings=tuple(warnings),
        module2_fields_present=module2_fields,
        module3_fields_present=module3_fields,
        derivation_probe_passed=probe_ok,
    )


def _feature_to_dict(feature: FeatureDefinition) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "canonical_name": feature.canonical_name,
        "formula": feature.formula,
        "source_fields": list(feature.source_fields),
        "data_type": feature.data_type,
        "unit": feature.unit,
        "derivation": feature.derivation.value,
        "edge_case_rules": feature.edge_case_rules,
        "cicflowmeter_compatibility": feature.cicflowmeter,
        "status": feature.status,
        "candidate_index": feature.candidate_index,
    }
    if feature.modification_notes:
        payload["modification_notes"] = feature.modification_notes
    return payload


def build_schema_document(
    candidates: Sequence[FeatureDefinition],
    retained: Sequence[FeatureDefinition],
    rejected: Sequence[RejectedFeature],
    validation: ValidationResult,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "description": (
            "MLCN 24-feature schema: the CIC-IDS2017 (CICFlowMeter) columns the XGBoost "
            "model was trained on, derived from Module 2 PacketMetadata and Module 3 Flow. "
            "Times are microseconds, rates per second, lengths are payload bytes."
        ),
        "activity_timeout_seconds": ACTIVITY_TIMEOUT_SECONDS,
        "flow_rules": {
            "terminate_on_first_fin": TERMINATE_FLOW_ON_FIN,
            "flow_timeout_seconds": FLOW_TIMEOUT_SECONDS,
            "min_flow_packets": MIN_FLOW_PACKETS,
            "classified_protocols": sorted(CLASSIFIED_PROTOCOLS),
            "zero_duration_rate_fill": dict(ZERO_DURATION_RATE_FILL),
        },
        "direction_conventions": {
            "forward": "Same orientation as the first packet observed in the flow.",
            "backward": "Opposite orientation from the forward direction.",
            "down_up_ratio": (
                "floor(reverse_packet_count / forward_packet_count), 0.0 when there are "
                "no forward packets."
            ),
        },
        "candidate_features_evaluated": len(candidates),
        "features_retained": len(retained),
        "features_removed": len(rejected),
        "feature_order": [feature.canonical_name for feature in retained],
        "features": [_feature_to_dict(feature) for feature in retained],
        "removed_or_rejected_candidates": [
            {
                "candidate_index": item.candidate_index,
                "canonical_name": item.canonical_name,
                "reason": item.reason,
            }
            for item in rejected
        ],
        "validation": {
            "passed": validation.passed,
            "derivation_probe_passed": validation.derivation_probe_passed,
            "errors": list(validation.errors),
            "warnings": list(validation.warnings),
            "module2_fields_present": list(validation.module2_fields_present),
            "module3_fields_present": list(validation.module3_fields_present),
        },
    }


def render_report(
    schema: dict[str, Any],
    validation: ValidationResult,
) -> str:
    retained = schema["feature_order"]
    rejected = schema["removed_or_rejected_candidates"]
    units = {feature["canonical_name"]: feature["unit"] for feature in schema["features"]}
    lines = [
        "# MLCN Common Feature Schema Report",
        "",
        f"Schema version: **{schema['schema_version']}**",
        "",
        "## Summary",
        "",
        f"- Candidate features evaluated: **{schema['candidate_features_evaluated']}**",
        f"- Features retained: **{schema['features_retained']}**",
        f"- Features removed: **{schema['features_removed']}**",
        f"- Validation status: **{'PASSED' if validation.passed else 'FAILED'}**",
        "",
        "## Retained features (fixed model order)",
        "",
    ]
    for index, name in enumerate(retained, start=1):
        lines.append(f"{index}. {name} ({units[name]})")
    lines.extend(["", "## Removed / rejected candidates", ""])
    if rejected:
        for item in rejected:
            lines.append(
                f"- **{item['canonical_name']}** (candidate #{item['candidate_index']}): "
                f"{item['reason']}"
            )
    else:
        lines.append("- None")
    lines.extend(["", "## Validation", ""])
    if validation.errors:
        lines.append("### Errors")
        for error in validation.errors:
            lines.append(f"- {error}")
        lines.append("")
    else:
        lines.append("- No validation errors.")
        lines.append("")
    rules = schema["flow_rules"]
    lines.extend(
        [
            "## CIC-IDS2017 semantics",
            "",
            "- Time features are microseconds; Flow Bytes/s and Flow Packets/s are per second.",
            "- Lengths are transport payload bytes, including Ethernet padding.",
            "- Packet Length Mean/Std use n + 1 values (first payload counted twice).",
            "- Flag columns are binary bits of the first packet in CICFlowMeter's permuted columns.",
            "- Down/Up Ratio is floor(backward / forward).",
            f"- Active/Idle use a {ACTIVITY_TIMEOUT_SECONDS:g} s threshold; the trailing active "
            "span is not recorded and the closing FIN does not update activity.",
            f"- Flows end on the first FIN or after {rules['flow_timeout_seconds']:g} s; flows "
            f"with fewer than {rules['min_flow_packets']} packets or other than "
            f"{'/'.join(rules['classified_protocols'])} are not classified.",
            "",
            "Units and types come from `feature_engineering/contract.py`.",
            "",
            "## Artifacts",
            "",
            f"- Machine-readable schema: `{DEFAULT_SCHEMA_PATH.as_posix()}`",
            f"- This report: `{DEFAULT_REPORT_PATH.as_posix()}`",
        ]
    )
    return "\n".join(lines) + "\n"


def write_schema_artifacts(
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
) -> tuple[dict[str, Any], ValidationResult]:
    candidates = build_candidate_feature_definitions()
    rejected = build_rejected_features()
    retained = finalize_feature_list(candidates, rejected)
    validation = validate_schema(candidates, retained, rejected)

    if not validation.passed:
        raise RuntimeError(
            "Common feature schema validation failed:\n- "
            + "\n- ".join(validation.errors)
        )

    schema = build_schema_document(candidates, retained, rejected, validation)
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    schema_json = json.dumps(schema, indent=2, sort_keys=False)
    schema_json += "\n"
    schema_path.write_text(schema_json, encoding="utf-8")
    report_path.write_text(render_report(schema, validation), encoding="utf-8")
    return schema, validation


def print_completion_summary(
    schema: dict[str, Any],
    validation: ValidationResult,
    schema_path: Path,
    report_path: Path,
) -> None:
    print("STEP 8 COMPLETE")
    print(f"Candidate features evaluated: {schema['candidate_features_evaluated']}")
    print(f"Features retained: {schema['features_retained']}")
    print(f"Features removed/modified: {schema['features_removed']}")
    print(f"Validation status: {'PASSED' if validation.passed else 'FAILED'}")
    print(f"Final schema path: {schema_path.resolve()}")
    print(f"Report path: {report_path.resolve()}")


def main(argv: Sequence[str] | None = None) -> int:
    schema_path = DEFAULT_SCHEMA_PATH
    report_path = DEFAULT_REPORT_PATH
    if argv:
        for arg in argv:
            if arg.startswith("--schema="):
                schema_path = Path(arg.split("=", 1)[1])
            elif arg.startswith("--report="):
                report_path = Path(arg.split("=", 1)[1])

    try:
        schema, validation = write_schema_artifacts(schema_path, report_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print_completion_summary(schema, validation, schema_path, report_path)
    return 0
