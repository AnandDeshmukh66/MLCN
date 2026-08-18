"""Deterministic fixtures for Module 2 packet-parsing tests."""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw


def make_tcp_packet(
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 54321,
    dport: int = 80,
    flags: str = "S",
    ttl: int = 64,
    window: int = 8192,
    payload: bytes = b"",
) -> Packet:
    pkt: Packet = IP(src=src, dst=dst, ttl=ttl) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        window=window,
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = 1_700_000_000.123
    return pkt


def make_udp_packet(
    *,
    src: str = "192.168.1.10",
    dst: str = "192.168.1.20",
    sport: int = 53000,
    dport: int = 53,
    ttl: int = 128,
    payload: bytes = b"dns",
) -> Packet:
    pkt: Packet = IP(src=src, dst=dst, ttl=ttl) / UDP(sport=sport, dport=dport) / Raw(
        load=payload
    )
    pkt.time = 1_700_000_001.0
    return pkt


def make_icmp_packet(
    *,
    src: str = "8.8.8.8",
    dst: str = "1.1.1.1",
    ttl: int = 54,
) -> Packet:
    pkt: Packet = IP(src=src, dst=dst, ttl=ttl) / ICMP(type=8, code=0)
    pkt.time = 1_700_000_002.5
    return pkt


def make_ipv6_tcp_packet(
    *,
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    sport: int = 40000,
    dport: int = 443,
    flags: str = "A",
    hlim: int = 64,
    window: int = 65535,
) -> Packet:
    pkt: Packet = IPv6(src=src, dst=dst, hlim=hlim) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        window=window,
    )
    pkt.time = 1_700_000_003.0
    return pkt


def make_ethernet_only_packet() -> Packet:
    """L2 frame with no IP layer."""
    pkt: Packet = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / Raw(
        load=b"hello"
    )
    pkt.time = 1_700_000_004.0
    return pkt


def make_malformed_standin() -> object:
    """Non-packet object that must not crash the parser."""
    return {"not": "a packet"}
