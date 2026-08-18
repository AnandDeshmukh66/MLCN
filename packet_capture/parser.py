"""Extract structured fields from raw Scapy packets.

Parsing, normalization, and validation live in Module 2 (``packet_parsing``).
This module adapts :class:`~packet_parsing.models.PacketMetadata` into the
Module 1 display model :class:`~packet_capture.models.ParsedPacket` so the
existing capture CLI and public API stay unchanged.
"""

from __future__ import annotations

from scapy.packet import Packet

from packet_capture.models import ParsedPacket
from packet_parsing import PacketMetadata
from packet_parsing import parse_packet as parse_metadata


def metadata_to_parsed_packet(metadata: PacketMetadata) -> ParsedPacket:
    """Map Module 2 metadata onto Module 1's display-oriented packet model."""
    return ParsedPacket(
        timestamp=metadata.timestamp,
        protocol=metadata.protocol,
        src_ip=metadata.src_ip if metadata.src_ip is not None else "-",
        dst_ip=metadata.dst_ip if metadata.dst_ip is not None else "-",
        src_port=metadata.src_port,
        dst_port=metadata.dst_port,
        length=metadata.length,
        tcp_flags=metadata.tcp_flags,
    )


def parse_packet(packet: Packet) -> ParsedPacket | None:
    """
    Parse a Scapy packet into a :class:`ParsedPacket`.

    Delegates to Module 2 and returns ``None`` for malformed or unsupported
    packets instead of raising.
    """
    metadata = parse_metadata(packet)
    if metadata is None:
        return None
    return metadata_to_parsed_packet(metadata)
