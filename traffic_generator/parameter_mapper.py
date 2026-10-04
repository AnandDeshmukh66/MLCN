"""Translate empirical profile characteristics into safe lab traffic parameters."""

from __future__ import annotations

import math
from typing import Any

from traffic_generator.config import (
    DEFAULT_HTTP_PORT,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_CONNECTION_RATE_PER_SEC,
    MAX_PACKET_RATE_PER_SEC,
    MAX_PAYLOAD_BYTES,
    MAX_PORT_SCAN_PORTS,
    MAX_TEST_DURATION_SECONDS,
    PROFILE_TIME_UNIT_MICROSECONDS,
)
from traffic_generator.profile_loader import (
    extract_reference_features,
    feature_value_from_profile,
    load_profiles,
)
from traffic_generator.traffic_profile import FeatureSnapshot, TrafficParameters


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _microseconds_to_seconds(value: float) -> float:
    """Convert CIC-style microsecond timings to seconds."""
    if value <= 0:
        return 0.0
    return value / PROFILE_TIME_UNIT_MICROSECONDS


def _safe_packet_rate(raw_packets_per_sec: float, intensity: float) -> float:
    """Map empirical Flow Packets/s to a conservative lab packet rate."""
    if raw_packets_per_sec <= 0 or not math.isfinite(raw_packets_per_sec):
        base = 1.0
    else:
        # Dataset values can be huge; log-scale compress before capping.
        base = math.log1p(raw_packets_per_sec) * 0.5
    scaled = base * intensity
    return _clamp(scaled, 0.2, MAX_PACKET_RATE_PER_SEC)


def _safe_connection_rate(raw_rate: float, intensity: float) -> float:
    if raw_rate <= 0 or not math.isfinite(raw_rate):
        base = 1.0
    else:
        base = min(raw_rate, MAX_CONNECTION_RATE_PER_SEC)
    return _clamp(base * intensity, 0.1, MAX_CONNECTION_RATE_PER_SEC)


def map_profile_to_parameters(
    profile_name: str,
    *,
    target_host: str,
    target_port: int = DEFAULT_HTTP_PORT,
    duration_seconds: float = 30.0,
    intensity: float = 0.5,
    port_scan_start: int = 8080,
    port_scan_end: int = 8099,
    profiles_document: dict[str, Any] | None = None,
) -> TrafficParameters:
    """
    Map one IDS test profile to bounded, configurable traffic parameters.

    Values are derived from ``MLCN_compact_attack_traffic_profiles.json`` medians
    and control-variable hints — never from hand-written 24-feature vectors.
    """
    document = profiles_document or load_profiles()
    intensity = _clamp(float(intensity), 0.1, 1.0)
    duration_seconds = _clamp(float(duration_seconds), 1.0, MAX_TEST_DURATION_SECONDS)

    refs = extract_reference_features(document, profile_name)
    snapshot = FeatureSnapshot(profile_name=profile_name, reference_features=refs)

    # Shared empirical reads (microseconds in profile JSON for timing features).
    flow_iat_mean_us = feature_value_from_profile(document, profile_name, "Flow IAT Mean")
    flow_iat_std_us = feature_value_from_profile(document, profile_name, "Flow IAT Std")
    fwd_iat_mean_us = feature_value_from_profile(document, profile_name, "Fwd IAT Mean")
    flow_packets_per_sec = feature_value_from_profile(document, profile_name, "Flow Packets/s")
    packet_len_mean = feature_value_from_profile(document, profile_name, "Packet Length Mean")
    fwd_packet_len_mean = feature_value_from_profile(
        document, profile_name, "Fwd Packet Length Mean"
    )
    total_fwd = int(
        _clamp(
            feature_value_from_profile(document, profile_name, "Total Fwd Packets") or 2,
            1,
            20,
        )
    )
    total_bwd = int(
        _clamp(
            feature_value_from_profile(document, profile_name, "Total Backward Packets") or 1,
            0,
            20,
        )
    )
    idle_mean_us = feature_value_from_profile(document, profile_name, "Idle Mean")
    flow_duration_us = feature_value_from_profile(document, profile_name, "Flow Duration")

    inter_message = _microseconds_to_seconds(flow_iat_mean_us)
    forward_inter = _microseconds_to_seconds(fwd_iat_mean_us)
    idle_gap = _microseconds_to_seconds(idle_mean_us)
    jitter = _microseconds_to_seconds(flow_iat_std_us)

    # Fallbacks when profile medians are zero/unhelpful for short flows.
    if inter_message <= 0:
        inter_message = 0.05
    if forward_inter <= 0:
        forward_inter = inter_message
    if jitter <= 0:
        jitter = inter_message * 0.1

    payload = int(
        _clamp(
            fwd_packet_len_mean or packet_len_mean or 64,
            0,
            MAX_PAYLOAD_BYTES,
        )
    )
    packet_rate = _safe_packet_rate(flow_packets_per_sec, intensity)
    connection_rate = _safe_connection_rate(packet_rate, intensity)

    # Profile-specific shaping (still bounded).
    use_http = True
    send_syn_only = False
    request_cycles = max(1, total_fwd)
    max_concurrent = max(1, min(MAX_CONCURRENT_CONNECTIONS, int(2 + intensity * 4)))
    scan_start = port_scan_start
    scan_end = min(port_scan_end, port_scan_start + MAX_PORT_SCAN_PORTS - 1)

    if profile_name == "BENIGN":
        inter_message = _clamp(_microseconds_to_seconds(flow_iat_mean_us) or 0.2, 0.05, 2.0)
        forward_inter = inter_message
        payload = int(_clamp(packet_len_mean or 128, 32, MAX_PAYLOAD_BYTES))
        connection_rate = _clamp(connection_rate, 0.5, 5.0 * intensity)
        request_cycles = max(2, min(total_fwd, 6))
        max_concurrent = 2
        idle_gap = 0.0
        jitter = inter_message * 0.05

    elif profile_name == "Port Scan":
        send_syn_only = True
        use_http = False
        inter_message = _clamp(_microseconds_to_seconds(flow_iat_mean_us) or 0.05, 0.01, 0.5)
        forward_inter = 0.0
        payload = 0
        connection_rate = _clamp(connection_rate * 2, 1.0, MAX_CONNECTION_RATE_PER_SEC)
        request_cycles = 1
        max_concurrent = max(1, min(MAX_CONCURRENT_CONNECTIONS, int(1 + intensity * 3)))
        idle_gap = 0.0
        jitter = 0.0
        # Short probe flows aligned with empirical sub-second duration.
        duration_seconds = min(duration_seconds, 60.0)

    elif profile_name == "DDoS":
        # Empirical: small payloads, few packets per flow, longer gaps / variability.
        payload = int(_clamp(fwd_packet_len_mean or 7, 4, 32))
        request_cycles = max(2, min(total_fwd, 6))
        inter_message = _clamp(inter_message, 0.2, 3.0)
        forward_inter = _clamp(forward_inter or inter_message, 0.2, 5.0)
        jitter = _clamp(jitter, 0.05, 1.0)
        max_concurrent = max(2, min(MAX_CONCURRENT_CONNECTIONS, int(2 + intensity * 6)))
        connection_rate = _clamp(connection_rate * 0.5, 0.2, 3.0)
        idle_gap = 0.0

    elif profile_name == "DoS":
        # Hulk-like: every request is its own short page-fetch connection, so the
        # flow shape comes from the request/response sizes, not from these gaps.
        # Bursts of requests (intensity shortens the in-burst gap) separated by
        # >5 s pauses keep the profile bursty but rate-limited.
        payload = int(_clamp(packet_len_mean or 64, 16, MAX_PAYLOAD_BYTES))
        request_cycles = 8
        inter_message = _clamp(0.5 - 0.35 * intensity, 0.15, 0.5)
        forward_inter = inter_message
        idle_gap = 5.5
        jitter = inter_message * 0.2
        max_concurrent = 1
        connection_rate = request_cycles / (request_cycles * inter_message + idle_gap)
        # Allow longer sessions but still bounded by global max duration.
        duration_seconds = min(
            max(duration_seconds, _microseconds_to_seconds(flow_duration_us) * 0.001),
            MAX_TEST_DURATION_SECONDS,
        )

    elif profile_name == "Brute Force":
        # Empirical: repeated bidirectional exchanges — simulated as HTTP request bursts.
        # No credentials; only repeated small lab requests.
        payload = int(_clamp(fwd_packet_len_mean or packet_len_mean or 32, 8, 128))
        request_cycles = max(3, min(total_fwd, 12))
        inter_message = _clamp(forward_inter or inter_message, 0.3, 2.0)
        forward_inter = inter_message
        idle_gap = 0.0
        jitter = _clamp(jitter, 0.05, 0.5)
        max_concurrent = 1
        connection_rate = _clamp(connection_rate * 0.4, 0.2, 2.0)
        # Emphasize bidirectional pattern via multiple request/response cycles.
        request_cycles = max(request_cycles, max(3, int(total_bwd // 2)))

    return TrafficParameters(
        profile_name=profile_name,
        target_host=target_host,
        target_port=target_port,
        duration_seconds=duration_seconds,
        intensity=intensity,
        connection_rate_per_sec=connection_rate,
        packets_per_flow=max(1, request_cycles),
        payload_size_bytes=payload,
        inter_message_delay_seconds=inter_message,
        forward_inter_delay_seconds=forward_inter,
        idle_gap_seconds=idle_gap,
        timing_jitter_seconds=jitter,
        max_concurrent_connections=max_concurrent,
        port_scan_start=scan_start,
        port_scan_end=scan_end,
        request_response_cycles=max(1, request_cycles),
        use_http=use_http,
        send_syn_only=send_syn_only,
        reference=snapshot,
    )
