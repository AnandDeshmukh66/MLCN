"""Tabular formatting for live packet output."""

from __future__ import annotations

from typing import Optional

from packet_capture.models import ParsedPacket

_HEADER = (
    f"{'TIMESTAMP':<26} {'PROTO':<6} {'SRC IP':<16} {'DST IP':<16} "
    f"{'SRC PORT':<9} {'DST PORT':<9} {'LEN':<6} {'TCP FLAGS':<10}"
)
_DIVIDER = "-" * len(_HEADER)


def _format_port(port: Optional[int]) -> str:
    return str(port) if port is not None else "-"


def format_packet_row(packet: ParsedPacket) -> str:
    """Format a single parsed packet as a fixed-width log row."""
    timestamp = packet.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    tcp_flags = packet.tcp_flags if packet.tcp_flags else "-"

    return (
        f"{timestamp:<26} {packet.protocol:<6} {packet.src_ip:<16} {packet.dst_ip:<16} "
        f"{_format_port(packet.src_port):<9} {_format_port(packet.dst_port):<9} "
        f"{packet.length:<6} {tcp_flags:<10}"
    )


def format_header() -> str:
    """Return the column header row."""
    return _HEADER


def format_divider() -> str:
    """Return a divider line beneath the header."""
    return _DIVIDER
