"""Field normalization and validation helpers for packet metadata."""

from __future__ import annotations

import ipaddress


def normalize_ip(value: object) -> str | None:
    """Return a canonical IP string, or ``None`` if invalid/missing."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_port(value: object) -> int | None:
    """Return an integer port in ``[0, 65535]``, or ``None`` if invalid."""
    if value is None:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def normalize_ttl(value: object) -> int | None:
    """Return an integer TTL/hop-limit in ``[0, 255]``, or ``None``."""
    if value is None:
        return None
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= ttl <= 255:
        return ttl
    return None


def normalize_tcp_window(value: object) -> int | None:
    """Return an integer TCP window in ``[0, 65535]``, or ``None``."""
    if value is None:
        return None
    try:
        window = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= window <= 65535:
        return window
    return None


def normalize_length(value: object) -> int | None:
    """Return a non-negative packet length, or ``None`` if invalid."""
    if value is None:
        return None
    try:
        length = int(value)
    except (TypeError, ValueError):
        return None
    if length < 0:
        return None
    return length


def normalize_protocol(value: object) -> str:
    """Return a canonical protocol label (``TCP``, ``UDP``, ``ICMP``, or ``Other``)."""
    if value is None:
        return "Other"
    text = str(value).strip().upper()
    if text in {"TCP", "UDP", "ICMP"}:
        return text
    return "Other"
