"""Laboratory-only safety checks for the traffic generator."""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse

from traffic_generator.config import (
    MAX_CONNECTION_RATE_PER_SEC,
    MAX_PACKET_RATE_PER_SEC,
    MAX_PORT_SCAN_PORTS,
    MAX_TEST_DURATION_SECONDS,
)


class SafetyError(ValueError):
    """Raised when a requested test violates laboratory safety rules."""


# RFC1918 + loopback + link-local.
_ALLOWED_NETWORKS: tuple[ipaddress._BaseNetwork, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def normalize_target(value: str) -> str:
    """Strip URL prefixes and whitespace from a target string."""
    text = value.strip()
    if not text:
        raise SafetyError("target is required")
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
        if not host:
            raise SafetyError(f"could not parse target URL: {value!r}")
        return host
    return text.split("/")[0].split(":")[0]


def resolve_target_host(value: str) -> str:
    """Validate and resolve a laboratory target to an IP string."""
    host = normalize_target(value)
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return "127.0.0.1"

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Hostname — resolve and validate all returned addresses.
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise SafetyError(f"cannot resolve target hostname {host!r}") from exc
        if not infos:
            raise SafetyError(f"no addresses returned for {host!r}")
        for info in infos:
            ip_str = info[4][0]
            _assert_allowed_ip(ip_str)
        return host

    _assert_allowed_ip(str(addr))
    return str(addr)


def _assert_allowed_ip(ip_str: str) -> None:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise SafetyError(f"invalid target IP: {ip_str!r}") from exc

    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        raise SafetyError(f"target IP not permitted for lab tests: {ip_str}")

    if not any(addr in net for net in _ALLOWED_NETWORKS):
        raise SafetyError(
            f"target {ip_str} is outside private/local ranges — "
            "public Internet targets are rejected"
        )


def validate_test_limits(
    *,
    duration_seconds: float,
    connection_rate: float,
    packet_rate: float | None = None,
    port_scan_start: int | None = None,
    port_scan_end: int | None = None,
) -> None:
    """Enforce global hard caps regardless of UI settings."""
    if duration_seconds <= 0 or duration_seconds > MAX_TEST_DURATION_SECONDS:
        raise SafetyError(
            f"duration must be between 0 and {MAX_TEST_DURATION_SECONDS}s, "
            f"got {duration_seconds}"
        )
    if connection_rate <= 0 or connection_rate > MAX_CONNECTION_RATE_PER_SEC:
        raise SafetyError(
            f"connection rate must be <= {MAX_CONNECTION_RATE_PER_SEC}/s, "
            f"got {connection_rate}"
        )
    if packet_rate is not None and (
        packet_rate <= 0 or packet_rate > MAX_PACKET_RATE_PER_SEC
    ):
        raise SafetyError(
            f"packet rate must be <= {MAX_PACKET_RATE_PER_SEC}/s, got {packet_rate}"
        )
    if port_scan_start is not None and port_scan_end is not None:
        if port_scan_start < 1 or port_scan_end > 65535 or port_scan_start > port_scan_end:
            raise SafetyError("invalid port scan range")
        span = port_scan_end - port_scan_start + 1
        if span > MAX_PORT_SCAN_PORTS:
            raise SafetyError(
                f"port scan span exceeds laboratory maximum of {MAX_PORT_SCAN_PORTS} ports"
            )


def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise SafetyError(f"port must be 1–65535, got {port}")


def require_lab_confirmation(confirmed: bool, phrase: str | None = None) -> None:
    """Require explicit UI confirmation before starting a test."""
    if not confirmed:
        raise SafetyError("mandatory laboratory confirmation was not provided")
    if phrase is not None and phrase.strip().upper() != "LAB":
        raise SafetyError("confirmation phrase must be exactly: LAB")


def is_loopback_target(target: str) -> bool:
    """True when the target resolves to loopback (validation mode hint)."""
    host = normalize_target(target)
    if host.lower() == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback
    except ValueError:
        return False


def allowed_targets_hint() -> str:
    return "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local"


def validate_targets_iterable(targets: Iterable[str]) -> list[str]:
    return [resolve_target_host(t) for t in targets]
