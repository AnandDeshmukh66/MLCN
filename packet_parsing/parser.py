"""
Module 2 — Packet Parsing.

Interpret raw packets from Module 1, normalize and validate fields, and
emit :class:`~packet_parsing.models.PacketMetadata` for the Flow Builder.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from packet_parsing.models import PacketMetadata
from packet_parsing.validation import (
    normalize_ip,
    normalize_length,
    normalize_port,
    normalize_protocol,
    normalize_tcp_window,
    normalize_ttl,
)

logger = logging.getLogger(__name__)

_TCP_FLAG_BITS = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
)


def _packet_timestamp(packet: Packet) -> datetime:
    """Return packet time as a timezone-aware UTC datetime."""
    raw_time = getattr(packet, "time", None)
    if raw_time is None:
        return datetime.now(timezone.utc)
    epoch = float(raw_time)
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _format_tcp_flags(tcp_layer: TCP) -> str | None:
    """Render TCP flags as a compact string (e.g. ``SA`` for SYN-ACK)."""
    flags = getattr(tcp_layer, "flags", None)
    if flags is None:
        return None

    rendered = str(flags).upper().replace(".", "")
    if rendered:
        return rendered

    try:
        value = int(flags)
    except (TypeError, ValueError):
        return None
    return "".join(name for bit, name in _TCP_FLAG_BITS if value & bit) or None


def _has_icmpv6(packet: Packet) -> bool:
    """Return True when any ICMPv6 layer is present."""
    return any(cls.__name__.startswith("ICMPv6") for cls in packet.layers())


def _packet_length(packet: Packet) -> int | None:
    """
    Measure packet length without crashing the pipeline.

    Prefer ``len(packet)``; if Scapy cannot rebuild the packet, fall back to
    the captured wire bytes. Packets that were never received off the wire
    have empty ``original`` bytes, so they are unusable rather than zero-length.
    """
    try:
        return normalize_length(len(packet))
    except Exception:  # noqa: BLE001 - malformed Scapy packets should fail gracefully
        original = getattr(packet, "original", None)
        if original:
            return normalize_length(len(original))
        return None


def _ip_next_header(ip_layer: IP | IPv6) -> int:
    """Return IPv4 ``proto`` or IPv6 ``nh`` as an integer."""
    if isinstance(ip_layer, IPv6):
        return int(getattr(ip_layer, "nh", 0) or 0)
    return int(getattr(ip_layer, "proto", 0) or 0)


def _extract_ttl(ip_layer: IP | IPv6) -> int | None:
    """Extract TTL (IPv4) or hop limit (IPv6)."""
    if isinstance(ip_layer, IPv6):
        return normalize_ttl(getattr(ip_layer, "hlim", None))
    return normalize_ttl(getattr(ip_layer, "ttl", None))


def _resolve_protocol(
    ip_proto: int,
    has_tcp: bool,
    has_udp: bool,
    has_icmp: bool,
) -> str:
    if has_tcp:
        return "TCP"
    if has_udp:
        return "UDP"
    if has_icmp:
        return "ICMP"
    if ip_proto in (1, 58):  # ICMP / ICMPv6
        return "ICMP"
    if ip_proto == 6:
        return "TCP"
    if ip_proto == 17:
        return "UDP"
    return "Other"


def parse_packet(packet: object) -> PacketMetadata | None:
    """
    Parse a raw (Scapy) packet into :class:`PacketMetadata`.

    Returns ``None`` for malformed or unusable packets instead of raising,
    so Module 1's capture loop is never interrupted by parse errors.
    """
    try:
        if not isinstance(packet, Packet):
            return None

        timestamp = _packet_timestamp(packet)
        length = _packet_length(packet)
        if length is None:
            return None

        ip_layer: IP | IPv6 | None = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return PacketMetadata(
                timestamp=timestamp,
                src_ip=None,
                dst_ip=None,
                protocol="Other",
                src_port=None,
                dst_port=None,
                length=length,
                tcp_flags=None,
                ttl=None,
                tcp_window=None,
            )

        src_ip = normalize_ip(getattr(ip_layer, "src", None))
        dst_ip = normalize_ip(getattr(ip_layer, "dst", None))
        if src_ip is None or dst_ip is None:
            # Unusable for flow building; skip gracefully.
            return None

        tcp_layer = packet.getlayer(TCP)
        udp_layer = packet.getlayer(UDP)
        icmp_layer = packet.getlayer(ICMP)
        has_icmp = icmp_layer is not None or _has_icmpv6(packet)

        ip_proto = _ip_next_header(ip_layer)
        protocol = normalize_protocol(
            _resolve_protocol(
                ip_proto,
                tcp_layer is not None,
                udp_layer is not None,
                has_icmp,
            )
        )

        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: str | None = None
        tcp_window: int | None = None
        ttl = _extract_ttl(ip_layer)

        if tcp_layer is not None:
            src_port = normalize_port(getattr(tcp_layer, "sport", None))
            dst_port = normalize_port(getattr(tcp_layer, "dport", None))
            tcp_flags = _format_tcp_flags(tcp_layer)
            tcp_window = normalize_tcp_window(getattr(tcp_layer, "window", None))
        elif udp_layer is not None:
            src_port = normalize_port(getattr(udp_layer, "sport", None))
            dst_port = normalize_port(getattr(udp_layer, "dport", None))
        # ICMP / Other: ports, flags, and window remain None

        return PacketMetadata(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            tcp_flags=tcp_flags,
            ttl=ttl,
            tcp_window=tcp_window,
        )
    except Exception:
        logger.debug("Skipping malformed packet", exc_info=True)
        return None
