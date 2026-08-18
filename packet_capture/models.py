"""Data models for parsed network packets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ParsedPacket:
    """Normalized view of a captured network packet."""

    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    length: int
    tcp_flags: str | None = None
