"""Flow data models for Module 3 of the MLCN pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from packet_parsing.models import PacketMetadata


@dataclass(frozen=True)
class FlowKey:
    """
    Canonical bidirectional 5-tuple identifying a network conversation.

    Endpoints are ordered so that a packet and its reverse direction share
    the same key. Ports may be ``None`` for protocols without ports (e.g. ICMP).
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str


@dataclass(frozen=True)
class Flow:
    """
    A completed bidirectional network flow ready for Feature Engineering.

    Aggregate counters and the ordered packet list are both preserved so
    Module 4 can derive CICIDS-style statistics without re-parsing packets.
    """

    key: FlowKey
    start_time: datetime
    end_time: datetime
    packet_count: int
    byte_count: int
    forward_packet_count: int
    reverse_packet_count: int
    forward_byte_count: int
    reverse_byte_count: int
    packets: tuple[PacketMetadata, ...]

    @property
    def duration(self) -> float:
        """Flow duration in seconds (``end_time - start_time``)."""
        return (self.end_time - self.start_time).total_seconds()

    @property
    def protocol(self) -> str:
        return self.key.protocol

    @property
    def src_ip(self) -> str:
        return self.key.src_ip

    @property
    def dst_ip(self) -> str:
        return self.key.dst_ip

    @property
    def src_port(self) -> int | None:
        return self.key.src_port

    @property
    def dst_port(self) -> int | None:
        return self.key.dst_port
