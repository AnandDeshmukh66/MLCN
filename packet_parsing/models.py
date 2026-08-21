"""Structured packet metadata for downstream MLCN modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PacketMetadata:
    """
    Normalized, validated view of a captured network packet.

    Protocol-specific fields are ``None`` when not applicable.
    This type hides Scapy (and other capture-library) details from
    Module 3 (Flow Builder) and later pipeline stages.
    """

    timestamp: datetime
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    tcp_flags: str | None = None
    ttl: int | None = None
    tcp_window: int | None = None
