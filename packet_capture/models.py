"""Data models for parsed network packets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class ParsedPacket:
    """Normalized view of a captured network packet."""

    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    tcp_flags: Optional[str] = None
