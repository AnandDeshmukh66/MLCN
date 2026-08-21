"""
Module 3 — Flow Builder.

Consume :class:`~packet_parsing.models.PacketMetadata` from Module 2 and
assemble bidirectional network flows for Feature Engineering.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from flow_builder.models import Flow, FlowKey
from packet_parsing.models import PacketMetadata

logger = logging.getLogger(__name__)

# Sentinel used only for endpoint ordering when a port is absent.
_MISSING_PORT = -1


def _endpoint_order_key(
    ip: str,
    port: int | None,
) -> tuple[str, int]:
    return (ip, port if port is not None else _MISSING_PORT)


def canonicalize_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> FlowKey:
    """
    Build a bidirectional-stable 5-tuple key.

    The endpoint with the smaller ``(ip, port)`` order key becomes the
    canonical ``src_*`` side so reverse-direction packets hash identically.
    """
    left = _endpoint_order_key(src_ip, src_port)
    right = _endpoint_order_key(dst_ip, dst_port)
    if left <= right:
        return FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
        )
    return FlowKey(
        src_ip=dst_ip,
        dst_ip=src_ip,
        src_port=dst_port,
        dst_port=src_port,
        protocol=protocol,
    )


def flow_key_from_packet(packet: PacketMetadata) -> FlowKey | None:
    """
    Derive a :class:`FlowKey` from packet metadata.

    Returns ``None`` when the packet lacks usable addressing (cannot join a flow).
    """
    if packet.src_ip is None or packet.dst_ip is None:
        return None
    protocol = (packet.protocol or "Other").strip().upper() or "Other"
    return canonicalize_flow_key(
        packet.src_ip,
        packet.dst_ip,
        packet.src_port,
        packet.dst_port,
        protocol,
    )


def _ensure_aware(ts: datetime) -> datetime:
    """Normalize naive datetimes to UTC so timeout math stays consistent."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


@dataclass
class _ActiveFlow:
    """Mutable accumulator for an in-progress flow."""

    key: FlowKey
    start_time: datetime
    end_time: datetime
    last_seen: datetime
    forward_src_ip: str
    forward_dst_ip: str
    forward_src_port: int | None
    forward_dst_port: int | None
    packets: list[PacketMetadata] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    reverse_packet_count: int = 0
    forward_byte_count: int = 0
    reverse_byte_count: int = 0

    def is_forward(self, packet: PacketMetadata) -> bool:
        return (
            packet.src_ip == self.forward_src_ip
            and packet.dst_ip == self.forward_dst_ip
            and packet.src_port == self.forward_src_port
            and packet.dst_port == self.forward_dst_port
        )

    def add(self, packet: PacketMetadata) -> None:
        ts = _ensure_aware(packet.timestamp)
        length = max(0, int(packet.length))
        self.packets.append(packet)
        self.packet_count += 1
        self.byte_count += length
        self.end_time = ts
        self.last_seen = ts
        if self.is_forward(packet):
            self.forward_packet_count += 1
            self.forward_byte_count += length
        else:
            self.reverse_packet_count += 1
            self.reverse_byte_count += length

    def to_flow(self) -> Flow:
        return Flow(
            key=self.key,
            start_time=self.start_time,
            end_time=self.end_time,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            forward_packet_count=self.forward_packet_count,
            reverse_packet_count=self.reverse_packet_count,
            forward_byte_count=self.forward_byte_count,
            reverse_byte_count=self.reverse_byte_count,
            packets=tuple(self.packets),
        )


class FlowBuilder:
    """
    Incrementally assemble bidirectional flows from Module 2 packet metadata.

    Flows are closed by inactivity timeout, maximum duration (active timeout),
    capacity eviction, or an explicit :meth:`flush`.
    """

    def __init__(
        self,
        inactivity_timeout: float = 60.0,
        max_duration: float = 300.0,
        max_active_flows: int = 100_000,
    ) -> None:
        if inactivity_timeout <= 0:
            raise ValueError("inactivity_timeout must be positive")
        if max_duration <= 0:
            raise ValueError("max_duration must be positive")
        if max_active_flows <= 0:
            raise ValueError("max_active_flows must be positive")

        self.inactivity_timeout = float(inactivity_timeout)
        self.max_duration = float(max_duration)
        self.max_active_flows = int(max_active_flows)
        self._active: dict[FlowKey, _ActiveFlow] = {}

    @property
    def active_count(self) -> int:
        """Number of flows currently held in memory."""
        return len(self._active)

    def add_packet(self, packet: PacketMetadata | None) -> list[Flow]:
        """
        Incorporate one parsed packet and return any flows completed as a result.

        Malformed / incomplete inputs are skipped without raising so the
        capture → parse → flow pipeline stays uninterrupted.
        """
        completed: list[Flow] = []
        try:
            if packet is None or not isinstance(packet, PacketMetadata):
                return completed

            key = flow_key_from_packet(packet)
            if key is None:
                return completed

            now = _ensure_aware(packet.timestamp)
            completed.extend(self.expire(now))

            existing = self._active.get(key)
            if existing is not None:
                # Active timeout: close long-lived flows even if still busy.
                if (now - existing.start_time) >= timedelta(seconds=self.max_duration):
                    completed.append(self._close(key))
                    existing = None

            if existing is None:
                self._evict_if_needed(completed)
                self._active[key] = self._start_flow(key, packet, now)
            else:
                existing.add(packet)
        except Exception:
            logger.debug("Skipping packet during flow assembly", exc_info=True)
        return completed

    def add_packets(self, packets: Iterable[PacketMetadata | None]) -> list[Flow]:
        """Feed a batch of packets; return flows completed along the way."""
        completed: list[Flow] = []
        for packet in packets:
            completed.extend(self.add_packet(packet))
        return completed

    def expire(self, now: datetime | None = None) -> list[Flow]:
        """Close flows idle longer than ``inactivity_timeout`` relative to ``now``."""
        if not self._active:
            return []

        reference = _ensure_aware(now) if now is not None else datetime.now(timezone.utc)
        idle_limit = timedelta(seconds=self.inactivity_timeout)
        completed: list[Flow] = []
        for key, active in list(self._active.items()):
            if (reference - active.last_seen) >= idle_limit:
                completed.append(self._close(key))
        return completed

    def flush(self) -> list[Flow]:
        """Close and return every remaining active flow (end-of-capture)."""
        completed = [self._close(key) for key in list(self._active.keys())]
        return completed

    def _start_flow(
        self,
        key: FlowKey,
        packet: PacketMetadata,
        now: datetime,
    ) -> _ActiveFlow:
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        # Caller already rejected packets without addresses via flow_key_from_packet.
        if src_ip is None or dst_ip is None:
            raise ValueError("Cannot start a flow without source and destination IPs")

        active = _ActiveFlow(
            key=key,
            start_time=now,
            end_time=now,
            last_seen=now,
            forward_src_ip=src_ip,
            forward_dst_ip=dst_ip,
            forward_src_port=packet.src_port,
            forward_dst_port=packet.dst_port,
        )
        active.add(packet)
        return active

    def _close(self, key: FlowKey) -> Flow:
        active = self._active.pop(key)
        return active.to_flow()

    def _evict_if_needed(self, completed: list[Flow]) -> None:
        """Evict the oldest idle flow when the active-flow cap is reached."""
        while len(self._active) >= self.max_active_flows:
            oldest_key = min(
                self._active,
                key=lambda k: self._active[k].last_seen,
            )
            completed.append(self._close(oldest_key))
