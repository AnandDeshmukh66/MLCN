"""Extract structured fields from raw Scapy packets."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from packet_capture.models import ParsedPacket

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
    """Return packet time as UTC datetime."""
    epoch = float(getattr(packet, "time", datetime.now(timezone.utc).timestamp()))
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _format_tcp_flags(tcp_layer: TCP) -> str:
    """Render TCP flags as a compact string (e.g. ``SA`` for SYN-ACK)."""
    flags = tcp_layer.flags
    rendered = str(flags).upper().replace(".", "")
    if rendered:
        return rendered

    value = int(flags)
    return "".join(name for bit, name in _TCP_FLAG_BITS if value & bit)


def _resolve_protocol(ip_proto: int, has_tcp: bool, has_udp: bool, has_icmp: bool) -> str:
    if has_tcp:
        return "TCP"
    if has_udp:
        return "UDP"
    if has_icmp:
        return "ICMP"
    if ip_proto == 1:
        return "ICMP"
    if ip_proto == 6:
        return "TCP"
    if ip_proto == 17:
        return "UDP"
    return "Other"


def parse_packet(packet: Packet) -> Optional[ParsedPacket]:
    """
    Parse a Scapy packet into a :class:`ParsedPacket`.

    Returns ``None`` for malformed or unsupported packets instead of raising.
    """
    try:
        if not isinstance(packet, Packet):
            return None

        timestamp = _packet_timestamp(packet)
        length = len(packet)

        ip_layer: IP | IPv6 | None = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return ParsedPacket(
                timestamp=timestamp,
                protocol="Other",
                src_ip="-",
                dst_ip="-",
                src_port=None,
                dst_port=None,
                length=length,
            )

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        tcp_layer = packet.getlayer(TCP)
        udp_layer = packet.getlayer(UDP)
        icmp_layer = packet.getlayer(ICMP)

        ip_proto = int(getattr(ip_layer, "proto", 0))
        protocol = _resolve_protocol(
            ip_proto,
            tcp_layer is not None,
            udp_layer is not None,
            icmp_layer is not None,
        )

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None

        if tcp_layer is not None:
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = _format_tcp_flags(tcp_layer)
        elif udp_layer is not None:
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        return ParsedPacket(
            timestamp=timestamp,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            tcp_flags=tcp_flags,
        )
    except Exception:
        logger.debug("Skipping malformed packet", exc_info=True)
        return None
