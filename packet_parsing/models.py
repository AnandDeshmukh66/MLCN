"""Structured packet metadata for downstream MLCN modules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class PacketMetadata:
    """
    Normalized, validated view of a captured network packet.

    Protocol-specific fields are ``None`` when not applicable.
    This type hides Scapy (and other capture-library) details from
    the Flow Builder and later pipeline stages.
    """

    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    tcp_flags: Optional[str] = None
    ttl: Optional[int] = None
    tcp_window: Optional[int] = None
