"""Data models for mapped laboratory traffic parameters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class FeatureSnapshot:
    """Empirical reference values taken from the profile JSON (for logging only)."""

    profile_name: str
    reference_features: dict[str, float]


@dataclass(frozen=True)
class TrafficParameters:
    """
    Safe, rate-limited traffic knobs derived from an attack profile.

    These control ordinary socket/HTTP test traffic — not the 24 ML features.
    """

    profile_name: str
    target_host: str
    target_port: int
    duration_seconds: float
    intensity: float  # 0.1 – 1.0 user scale applied on top of mapped defaults

    connection_rate_per_sec: float
    packets_per_flow: int
    payload_size_bytes: int
    inter_message_delay_seconds: float
    forward_inter_delay_seconds: float
    idle_gap_seconds: float
    timing_jitter_seconds: float
    max_concurrent_connections: int
    port_scan_start: int
    port_scan_end: int
    request_response_cycles: int
    use_http: bool
    send_syn_only: bool

    reference: FeatureSnapshot

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "duration_seconds": self.duration_seconds,
            "intensity": self.intensity,
            "connection_rate_per_sec": self.connection_rate_per_sec,
            "packets_per_flow": self.packets_per_flow,
            "payload_size_bytes": self.payload_size_bytes,
            "inter_message_delay_seconds": self.inter_message_delay_seconds,
            "forward_inter_delay_seconds": self.forward_inter_delay_seconds,
            "idle_gap_seconds": self.idle_gap_seconds,
            "timing_jitter_seconds": self.timing_jitter_seconds,
            "max_concurrent_connections": self.max_concurrent_connections,
            "port_scan_start": self.port_scan_start,
            "port_scan_end": self.port_scan_end,
            "request_response_cycles": self.request_response_cycles,
            "use_http": self.use_http,
            "send_syn_only": self.send_syn_only,
        }


@dataclass
class GeneratorStats:
    """Runtime counters emitted by a traffic generator run."""

    connections_attempted: int = 0
    connections_completed: int = 0
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    last_error: str = ""

    def as_dict(self) -> dict[str, int | str]:
        return {
            "connections_attempted": self.connections_attempted,
            "connections_completed": self.connections_completed,
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "errors": self.errors,
            "last_error": self.last_error,
        }


@dataclass
class GeneratorRunLog:
    """Structured log entry for one generator session."""

    profile_name: str
    target: str
    started_at: datetime
    ended_at: datetime | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)
    stop_reason: str = ""
    error_messages: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "parameters": self.parameters,
            "stats": self.stats,
            "stop_reason": self.stop_reason,
            "error_messages": self.error_messages,
        }


@dataclass(frozen=True)
class ValidationRecord:
    """Compare target profile → observed receiver classification."""

    target_profile: str
    predicted_class: str
    confidence: float
    probabilities: dict[str, float]
    observed_features: dict[str, float]
    flow_packet_count: int
    flow_byte_count: float
    flow_duration: float
    recorded_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_profile": self.target_profile,
            "predicted_class": self.predicted_class,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "observed_features": self.observed_features,
            "flow_packet_count": self.flow_packet_count,
            "flow_byte_count": self.flow_byte_count,
            "flow_duration": self.flow_duration,
            "recorded_at": self.recorded_at.isoformat(),
            "profile_match": self.predicted_class == self.target_profile,
        }
