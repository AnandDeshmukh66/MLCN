"""
Common feature schema specification and validation for MLCN Step 8.

Finalizes CICIDS-style flow features derivable from Module 2 PacketMetadata
and Module 3 Flow without implementing Module 4 feature engineering.
"""

from __future__ import annotations

import dataclasses
import json
import math
import statistics
import sys
from dataclasses import dataclass, fields
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from flow_builder.models import Flow
from packet_parsing.models import PacketMetadata

SCHEMA_VERSION = "1.0.0"

# CICFlowMeter default activity timeout (5_000_000 microseconds).
ACTIVITY_TIMEOUT_SECONDS = 5.0

# Stable artifact paths relative to the repository root.
DEFAULT_SCHEMA_PATH = Path("data/common_feature_schema.json")
DEFAULT_REPORT_PATH = Path("data/common_feature_schema_report.md")


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


def build_candidate_feature_definitions() -> list[FeatureDefinition]:
    """Return all 25 candidate features in fixed candidate order."""
    defs: list[FeatureDefinition] = [
        FeatureDefinition(
            candidate_index=1,
            canonical_name="Flow Duration",
            formula="max(0, (Flow.end_time - Flow.start_time) in seconds)",
            source_fields=("Flow.start_time", "Flow.end_time"),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DIRECT,
            edge_case_rules=_edge(
                ("zero_duration_flow", "0.0 when start_time equals end_time"),
                ("negative_clock_skew", "clamp to 0.0 if computed duration is negative"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Matches CICFlowMeter flow duration (last_seen - flow_start).",
            },
        ),
        FeatureDefinition(
            candidate_index=2,
            canonical_name="Total Fwd Packets",
            formula="Flow.forward_packet_count",
            source_fields=("Flow.forward_packet_count",),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DIRECT,
            edge_case_rules=_edge(
                ("empty_packet_collection", "0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "CIC forward (client-to-server) packet count.",
            },
        ),
        FeatureDefinition(
            candidate_index=3,
            canonical_name="Total Backward Packets",
            formula="Flow.reverse_packet_count",
            source_fields=("Flow.reverse_packet_count",),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DIRECT,
            edge_case_rules=_edge(
                ("zero_backward_packets", "0 when no reverse-direction packets observed"),
                ("empty_packet_collection", "0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "CIC backward packet count.",
            },
        ),
        FeatureDefinition(
            candidate_index=4,
            canonical_name="Fwd Packets Length Total",
            formula="Flow.forward_byte_count",
            source_fields=("Flow.forward_byte_count",),
            data_type="int",
            unit="bytes",
            derivation=DerivationKind.DIRECT,
            edge_case_rules=_edge(
                ("zero_forward_packets", "0 when forward_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Total forward payload length.",
            },
        ),
        FeatureDefinition(
            candidate_index=5,
            canonical_name="Bwd Packets Length Total",
            formula="Flow.reverse_byte_count",
            source_fields=("Flow.reverse_byte_count",),
            data_type="int",
            unit="bytes",
            derivation=DerivationKind.DIRECT,
            edge_case_rules=_edge(
                ("zero_backward_packets", "0 when reverse_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Total backward payload length.",
            },
        ),
        FeatureDefinition(
            candidate_index=6,
            canonical_name="Fwd Packet Length Mean",
            formula="Flow.forward_byte_count / Flow.forward_packet_count",
            source_fields=("Flow.forward_byte_count", "Flow.forward_packet_count"),
            data_type="float",
            unit="bytes",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_forward_packets", "0.0 when forward_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean forward packet length.",
            },
        ),
        FeatureDefinition(
            candidate_index=7,
            canonical_name="Bwd Packet Length Mean",
            formula="Flow.reverse_byte_count / Flow.reverse_packet_count",
            source_fields=("Flow.reverse_byte_count", "Flow.reverse_packet_count"),
            data_type="float",
            unit="bytes",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_backward_packets", "0.0 when reverse_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean backward packet length.",
            },
        ),
        FeatureDefinition(
            candidate_index=8,
            canonical_name="Flow Bytes/s",
            formula="Flow.byte_count / Flow.duration",
            source_fields=("Flow.byte_count", "Flow.start_time", "Flow.end_time"),
            data_type="float",
            unit="bytes_per_second",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_duration_flow", "0.0 when duration is 0"),
                ("one_packet_flow", "0.0 when the sole packet yields zero duration"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Total bytes divided by duration in seconds.",
            },
        ),
        FeatureDefinition(
            candidate_index=9,
            canonical_name="Flow Packets/s",
            formula="Flow.packet_count / Flow.duration",
            source_fields=("Flow.packet_count", "Flow.start_time", "Flow.end_time"),
            data_type="float",
            unit="packets_per_second",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_duration_flow", "0.0 when duration is 0"),
                ("one_packet_flow", "0.0 when the sole packet yields zero duration"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Total packets divided by duration in seconds.",
            },
        ),
        FeatureDefinition(
            candidate_index=10,
            canonical_name="Flow IAT Mean",
            formula=(
                "mean([t_i - t_{i-1} for i in 1..n-1]) over Flow.packets ordered by "
                "PacketMetadata.timestamp"
            ),
            source_fields=("Flow.packets", "Flow.packets[].timestamp"),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when packet_count < 2"),
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean inter-arrival time across all flow packets.",
            },
        ),
        FeatureDefinition(
            candidate_index=11,
            canonical_name="Flow IAT Std",
            formula="sample_std([t_i - t_{i-1} for i in 1..n-1]) with ddof=1",
            source_fields=("Flow.packets", "Flow.packets[].timestamp"),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when fewer than 2 inter-arrival intervals exist"),
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Sample standard deviation (n-1) of flow inter-arrival times.",
            },
        ),
        FeatureDefinition(
            candidate_index=12,
            canonical_name="Fwd IAT Mean",
            formula=(
                "mean inter-arrival times between consecutive forward-direction packets "
                "(same 5-tuple orientation as the first packet in the flow)"
            ),
            source_fields=(
                "Flow.packets",
                "Flow.packets[].timestamp",
                "Flow.packets[].src_ip",
                "Flow.packets[].dst_ip",
                "Flow.packets[].src_port",
                "Flow.packets[].dst_port",
            ),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when fewer than 2 forward packets exist"),
                ("zero_forward_packets", "0.0 when forward_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean forward-direction inter-arrival time.",
            },
        ),
        FeatureDefinition(
            candidate_index=13,
            canonical_name="Bwd IAT Mean",
            formula=(
                "mean inter-arrival times between consecutive reverse-direction packets"
            ),
            source_fields=(
                "Flow.packets",
                "Flow.packets[].timestamp",
                "Flow.packets[].src_ip",
                "Flow.packets[].dst_ip",
                "Flow.packets[].src_port",
                "Flow.packets[].dst_port",
            ),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_backward_packets", "0.0 when fewer than 2 reverse packets exist"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean backward-direction inter-arrival time.",
            },
        ),
        FeatureDefinition(
            candidate_index=14,
            canonical_name="Packet Length Mean",
            formula="mean([PacketMetadata.length for each packet in Flow.packets])",
            source_fields=("Flow.packets", "Flow.packets[].length"),
            data_type="float",
            unit="bytes",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("empty_packet_collection", "0.0 when packet_count is 0"),
                ("one_packet_flow", "equals the single packet length"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Mean of all packet lengths in the flow.",
            },
        ),
        FeatureDefinition(
            candidate_index=15,
            canonical_name="Packet Length Std",
            formula="sample_std([PacketMetadata.length ...]) with ddof=1",
            source_fields=("Flow.packets", "Flow.packets[].length"),
            data_type="float",
            unit="bytes",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when fewer than 2 packets exist"),
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Sample standard deviation of packet lengths.",
            },
        ),
        FeatureDefinition(
            candidate_index=16,
            canonical_name="FIN Flag Count",
            formula="count(packets where 'F' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
                ("empty_packet_collection", "0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with FIN set.",
            },
        ),
        FeatureDefinition(
            candidate_index=17,
            canonical_name="SYN Flag Count",
            formula="count(packets where 'S' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with SYN set.",
            },
        ),
        FeatureDefinition(
            candidate_index=18,
            canonical_name="RST Flag Count",
            formula="count(packets where 'R' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with RST set.",
            },
        ),
        FeatureDefinition(
            candidate_index=19,
            canonical_name="PSH Flag Count",
            formula="count(packets where 'P' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with PSH set.",
            },
        ),
        FeatureDefinition(
            candidate_index=20,
            canonical_name="ACK Flag Count",
            formula="count(packets where 'A' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with ACK set.",
            },
        ),
        FeatureDefinition(
            candidate_index=21,
            canonical_name="URG Flag Count",
            formula="count(packets where 'U' in PacketMetadata.tcp_flags)",
            source_fields=("Flow.packets", "Flow.packets[].tcp_flags"),
            data_type="int",
            unit="count",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("missing_tcp_flags", "non-TCP packets (tcp_flags is None) contribute 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "Count of packets with URG set.",
            },
        ),
        FeatureDefinition(
            candidate_index=22,
            canonical_name="Average Packet Size",
            formula="Flow.byte_count / Flow.packet_count",
            source_fields=("Flow.byte_count", "Flow.packet_count"),
            data_type="float",
            unit="bytes",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE.value,
                "notes": "CIC Avg Packet Size = total length / packet count.",
            },
        ),
        FeatureDefinition(
            candidate_index=23,
            canonical_name="Down/Up Ratio",
            formula="Flow.forward_packet_count / Flow.reverse_packet_count",
            source_fields=("Flow.forward_packet_count", "Flow.reverse_packet_count"),
            data_type="float",
            unit="ratio",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("zero_backward_packets", "0.0 when reverse_packet_count is 0"),
                ("zero_forward_packets", "0.0 when forward_packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.MODIFIED.value,
                "notes": (
                    "CICFlowMeter uses backward/forward (integer division). MLCN common "
                    "schema uses forward/backward (float division) per project convention."
                ),
            },
            modification_notes=(
                "Inverted ratio direction relative to CICFlowMeter; safe 0.0 when "
                "either direction count is zero."
            ),
        ),
        FeatureDefinition(
            candidate_index=24,
            canonical_name="Active Mean",
            formula=(
                "mean duration of active periods where consecutive packet gaps are "
                f"<= {ACTIVITY_TIMEOUT_SECONDS} seconds; active periods split when gap "
                "exceeds threshold; finalize trailing active period at flow end"
            ),
            source_fields=("Flow.packets", "Flow.packets[].timestamp", "Flow.end_time"),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when no completed active period spans > 0 seconds"),
                ("zero_duration_flow", "0.0 when all packets share one timestamp"),
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE_WITH_NOTES.value,
                "notes": (
                    f"Uses CICFlowMeter activity timeout ({ACTIVITY_TIMEOUT_SECONDS}s). "
                    "Does not append synthetic trailing idle to flow timeout because "
                    "Module 3 already closes flows explicitly."
                ),
            },
        ),
        FeatureDefinition(
            candidate_index=25,
            canonical_name="Idle Mean",
            formula=(
                f"mean duration of idle gaps where consecutive packet gap > "
                f"{ACTIVITY_TIMEOUT_SECONDS} seconds"
            ),
            source_fields=("Flow.packets", "Flow.packets[].timestamp"),
            data_type="float",
            unit="seconds",
            derivation=DerivationKind.DERIVED,
            edge_case_rules=_edge(
                ("one_packet_flow", "0.0 when no idle gap exceeds activity threshold"),
                ("empty_packet_collection", "0.0 when packet_count is 0"),
            ),
            cicflowmeter={
                "status": CICCompatibility.COMPATIBLE_WITH_NOTES.value,
                "notes": (
                    "Idle segments derived only from observed inter-packet gaps; no "
                    "synthetic idle padding at flow close."
                ),
            },
        ),
    ]
    return defs


def build_rejected_features() -> list[RejectedFeature]:
    return [
        RejectedFeature(
            candidate_index=22,
            canonical_name="Average Packet Size",
            reason=(
                "Algebraically equivalent to Packet Length Mean when Module 3 maintains "
                "byte_count == sum(PacketMetadata.length). Retain Packet Length Mean only "
                "to avoid duplicate schema columns."
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


def _timestamps(packets: Sequence[PacketMetadata]) -> list[float]:
    return [packet.timestamp.timestamp() for packet in packets]


def _iat_series(timestamps: Sequence[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]


def _mean_or_zero(values: Sequence[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _sample_std_or_zero(values: Sequence[float]) -> float:
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


def _active_idle_durations(flow: Flow) -> tuple[list[float], list[float]]:
    packets = flow.packets
    if not packets:
        return [], []

    active_periods: list[float] = []
    idle_periods: list[float] = []
    times = _timestamps(packets)
    start_active = times[0]
    end_active = times[0]

    for current in times[1:]:
        gap = current - end_active
        if gap > ACTIVITY_TIMEOUT_SECONDS:
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


def _safe_duration(flow: Flow) -> float:
    duration = flow.duration
    return max(0.0, duration)


def _reference_feature_values(flow: Flow) -> dict[str, float | int]:
    """Compute probe values for derivability validation (not Module 4 API)."""
    packets = flow.packets
    duration = _safe_duration(flow)
    lengths = [max(0, int(packet.length)) for packet in packets]
    all_iat = _iat_series(_timestamps(packets))

    forward_packets = [p for p in packets if _is_forward_packet(flow, p)]
    reverse_packets = [p for p in packets if not _is_forward_packet(flow, p)]
    fwd_iat = _iat_series(_timestamps(forward_packets))
    bwd_iat = _iat_series(_timestamps(reverse_packets))
    active_periods, idle_periods = _active_idle_durations(flow)

    fwd_count = flow.forward_packet_count
    rev_count = flow.reverse_packet_count

    return {
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_count,
        "Total Backward Packets": rev_count,
        "Fwd Packets Length Total": flow.forward_byte_count,
        "Bwd Packets Length Total": flow.reverse_byte_count,
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
        "Packet Length Mean": _mean_or_zero(lengths),
        "Packet Length Std": _sample_std_or_zero(lengths),
        "FIN Flag Count": _flag_count(packets, "F"),
        "SYN Flag Count": _flag_count(packets, "S"),
        "RST Flag Count": _flag_count(packets, "R"),
        "PSH Flag Count": _flag_count(packets, "P"),
        "ACK Flag Count": _flag_count(packets, "A"),
        "URG Flag Count": _flag_count(packets, "U"),
        "Down/Up Ratio": (
            (fwd_count / rev_count)
            if fwd_count > 0 and rev_count > 0
            else 0.0
        ),
        "Active Mean": _mean_or_zero(active_periods),
        "Idle Mean": _mean_or_zero(idle_periods),
    }


def _make_probe_flows() -> list[Flow]:
    """Synthetic flows covering Step 8 edge cases."""
    from datetime import timezone

    def ts(seconds: float) -> datetime:
        return datetime.fromtimestamp(1_700_000_000.0 + seconds, tz=timezone.utc)

    def meta(
        *,
        at: float,
        length: int = 100,
        src_ip: str = "10.0.0.1",
        dst_ip: str = "10.0.0.2",
        src_port: int | None = 54321,
        dst_port: int | None = 80,
        tcp_flags: str | None = "A",
    ) -> PacketMetadata:
        return PacketMetadata(
            timestamp=ts(at),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            tcp_flags=tcp_flags,
            ttl=64,
            tcp_window=8192,
        )

    one_packet = (
        meta(at=0.0, length=60, tcp_flags="S"),
    )
    bidirectional = (
        meta(at=0.0, length=60, tcp_flags="S"),
        meta(
            at=1.0,
            length=40,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=54321,
            tcp_flags="SA",
        ),
    )
    idle_gap = (
        meta(at=0.0, length=50, tcp_flags="S"),
        meta(at=1.0, length=50, tcp_flags="A"),
        meta(at=10.0, length=50, tcp_flags="A"),
    )
    zero_duration = (
        meta(at=5.0, length=80, tcp_flags="PA"),
        meta(at=5.0, length=120, tcp_flags="A"),
    )
    udp_no_flags = (
        PacketMetadata(
            timestamp=ts(0.0),
            src_ip="192.168.0.1",
            dst_ip="192.168.0.2",
            protocol="UDP",
            src_port=1000,
            dst_port=53,
            length=200,
            tcp_flags=None,
            ttl=64,
            tcp_window=None,
        ),
    )

    def flow_from_packets(packets: Sequence[PacketMetadata]) -> Flow:
        from flow_builder.models import FlowKey

        anchor = packets[0]
        key = FlowKey(
            src_ip=min(anchor.src_ip or "", "z"),
            dst_ip=anchor.dst_ip or "",
            src_port=anchor.src_port,
            dst_port=anchor.dst_port,
            protocol=anchor.protocol,
        )
        fwd = rev = fwd_bytes = rev_bytes = 0
        for packet in packets:
            if (
                packet.src_ip == anchor.src_ip
                and packet.dst_ip == anchor.dst_ip
                and packet.src_port == anchor.src_port
                and packet.dst_port == anchor.dst_port
            ):
                fwd += 1
                fwd_bytes += packet.length
            else:
                rev += 1
                rev_bytes += packet.length
        return Flow(
            key=key,
            start_time=packets[0].timestamp,
            end_time=packets[-1].timestamp,
            packet_count=len(packets),
            byte_count=sum(p.length for p in packets),
            forward_packet_count=fwd,
            reverse_packet_count=rev,
            forward_byte_count=fwd_bytes,
            reverse_byte_count=rev_bytes,
            packets=tuple(packets),
        )

    return [
        flow_from_packets(one_packet),
        flow_from_packets(bidirectional),
        flow_from_packets(idle_gap),
        flow_from_packets(zero_duration),
        flow_from_packets(udp_no_flags),
    ]


def _feature_to_probe_key(canonical_name: str) -> str:
    return canonical_name


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
            key = _feature_to_probe_key(name)
            if key not in values:
                errors.append(f"derivation probe missing value for {name!r}")
                continue
            value = values[key]
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
            "MLCN common flow feature schema for CICIDS2017, CIC-DDoS2019, and CTU-13 "
            "normalization. Derived from Module 2 PacketMetadata and Module 3 Flow."
        ),
        "activity_timeout_seconds": ACTIVITY_TIMEOUT_SECONDS,
        "direction_conventions": {
            "forward": "Same orientation as the first packet observed in the flow.",
            "backward": "Opposite orientation from the forward direction.",
            "down_up_ratio": (
                "forward_packet_count / reverse_packet_count with 0.0 when either count is zero."
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
        "## Retained features (fixed order)",
        "",
    ]
    for index, name in enumerate(retained, start=1):
        lines.append(f"{index}. {name}")
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
    lines.extend(
        [
            "## Module compatibility",
            "",
            "All retained features are derivable from `PacketMetadata` and `Flow` without "
            "changing Module 3. Activity/idle statistics use a fixed "
            f"{ACTIVITY_TIMEOUT_SECONDS}s threshold aligned with CICFlowMeter defaults, "
            "but omit synthetic trailing idle padding at flow close.",
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
