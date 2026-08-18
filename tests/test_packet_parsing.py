"""Unit tests for Module 2 packet parsing, normalization, and validation."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from packet_parsing import PacketMetadata, parse_packet
from packet_parsing.validation import (
    normalize_ip,
    normalize_length,
    normalize_port,
    normalize_protocol,
    normalize_tcp_window,
    normalize_ttl,
)
from tests.fixtures import (
    make_ethernet_only_packet,
    make_icmp_packet,
    make_ipv6_tcp_packet,
    make_malformed_standin,
    make_tcp_packet,
    make_udp_packet,
)


class TestTcpParsing(unittest.TestCase):
    def test_tcp_basic_fields(self) -> None:
        meta = parse_packet(make_tcp_packet())
        self.assertIsInstance(meta, PacketMetadata)
        assert meta is not None
        self.assertEqual(meta.protocol, "TCP")
        self.assertEqual(meta.src_ip, "10.0.0.1")
        self.assertEqual(meta.dst_ip, "10.0.0.2")
        self.assertEqual(meta.src_port, 54321)
        self.assertEqual(meta.dst_port, 80)
        self.assertGreater(meta.length, 0)
        self.assertIsInstance(meta.timestamp, datetime)
        self.assertEqual(meta.timestamp.tzinfo, timezone.utc)

    def test_tcp_flags(self) -> None:
        syn = parse_packet(make_tcp_packet(flags="S"))
        syn_ack = parse_packet(make_tcp_packet(flags="SA"))
        fin_ack = parse_packet(make_tcp_packet(flags="FA"))
        assert syn is not None and syn_ack is not None and fin_ack is not None
        self.assertEqual(syn.tcp_flags, "S")
        self.assertEqual(syn_ack.tcp_flags, "SA")
        self.assertEqual(fin_ack.tcp_flags, "FA")

    def test_tcp_ttl_and_window(self) -> None:
        meta = parse_packet(make_tcp_packet(ttl=64, window=8192))
        assert meta is not None
        self.assertEqual(meta.ttl, 64)
        self.assertEqual(meta.tcp_window, 8192)

    def test_ipv6_tcp_uses_hop_limit_as_ttl(self) -> None:
        meta = parse_packet(make_ipv6_tcp_packet(hlim=42, window=1024))
        assert meta is not None
        self.assertEqual(meta.protocol, "TCP")
        self.assertEqual(meta.src_ip, "2001:db8::1")
        self.assertEqual(meta.dst_ip, "2001:db8::2")
        self.assertEqual(meta.ttl, 42)
        self.assertEqual(meta.tcp_window, 1024)
        self.assertEqual(meta.tcp_flags, "A")


class TestUdpParsing(unittest.TestCase):
    def test_udp_basic_fields(self) -> None:
        meta = parse_packet(make_udp_packet())
        assert meta is not None
        self.assertEqual(meta.protocol, "UDP")
        self.assertEqual(meta.src_ip, "192.168.1.10")
        self.assertEqual(meta.dst_ip, "192.168.1.20")
        self.assertEqual(meta.src_port, 53000)
        self.assertEqual(meta.dst_port, 53)
        self.assertEqual(meta.ttl, 128)

    def test_udp_protocol_specific_fields_are_none(self) -> None:
        meta = parse_packet(make_udp_packet())
        assert meta is not None
        self.assertIsNone(meta.tcp_flags)
        self.assertIsNone(meta.tcp_window)


class TestIcmpParsing(unittest.TestCase):
    def test_icmp_basic_fields(self) -> None:
        meta = parse_packet(make_icmp_packet())
        assert meta is not None
        self.assertEqual(meta.protocol, "ICMP")
        self.assertEqual(meta.src_ip, "8.8.8.8")
        self.assertEqual(meta.dst_ip, "1.1.1.1")
        self.assertEqual(meta.ttl, 54)

    def test_icmp_optional_fields_are_none(self) -> None:
        meta = parse_packet(make_icmp_packet())
        assert meta is not None
        self.assertIsNone(meta.src_port)
        self.assertIsNone(meta.dst_port)
        self.assertIsNone(meta.tcp_flags)
        self.assertIsNone(meta.tcp_window)


class TestOptionalAndMissingFields(unittest.TestCase):
    def test_non_ip_packet_has_null_address_fields(self) -> None:
        meta = parse_packet(make_ethernet_only_packet())
        assert meta is not None
        self.assertEqual(meta.protocol, "Other")
        self.assertIsNone(meta.src_ip)
        self.assertIsNone(meta.dst_ip)
        self.assertIsNone(meta.src_port)
        self.assertIsNone(meta.dst_port)
        self.assertIsNone(meta.ttl)
        self.assertIsNone(meta.tcp_flags)
        self.assertIsNone(meta.tcp_window)

    def test_ip_other_protocol_without_ports(self) -> None:
        # Protocol 89 = OSPF — neither TCP, UDP, nor ICMP.
        pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=16, proto=89) / Raw(load=b"x")
        pkt.time = 1_700_000_010.0
        meta = parse_packet(pkt)
        assert meta is not None
        self.assertEqual(meta.protocol, "Other")
        self.assertIsNone(meta.src_port)
        self.assertIsNone(meta.dst_port)
        self.assertIsNone(meta.tcp_flags)
        self.assertIsNone(meta.tcp_window)
        self.assertEqual(meta.ttl, 16)


class TestNormalizationAndTypes(unittest.TestCase):
    def test_metadata_field_types(self) -> None:
        meta = parse_packet(make_tcp_packet())
        assert meta is not None
        self.assertIsInstance(meta.timestamp, datetime)
        self.assertIsInstance(meta.src_ip, str)
        self.assertIsInstance(meta.dst_ip, str)
        self.assertIsInstance(meta.protocol, str)
        self.assertIsInstance(meta.src_port, int)
        self.assertIsInstance(meta.dst_port, int)
        self.assertIsInstance(meta.length, int)
        self.assertIsInstance(meta.tcp_flags, str)
        self.assertIsInstance(meta.ttl, int)
        self.assertIsInstance(meta.tcp_window, int)

    def test_ip_normalization(self) -> None:
        self.assertEqual(normalize_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(normalize_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(normalize_ip("not-an-ip"))
        self.assertIsNone(normalize_ip("-"))
        self.assertIsNone(normalize_ip(None))

    def test_port_ttl_window_normalization(self) -> None:
        self.assertEqual(normalize_port(80), 80)
        self.assertEqual(normalize_port("443"), 443)
        self.assertIsNone(normalize_port(-1))
        self.assertIsNone(normalize_port(70000))
        self.assertEqual(normalize_ttl(64), 64)
        self.assertIsNone(normalize_ttl(300))
        self.assertEqual(normalize_tcp_window(8192), 8192)
        self.assertIsNone(normalize_tcp_window(70000))
        self.assertEqual(normalize_length(40), 40)
        self.assertIsNone(normalize_length(-5))
        self.assertEqual(normalize_protocol("tcp"), "TCP")
        self.assertEqual(normalize_protocol("weird"), "Other")


class TestMalformedPacketHandling(unittest.TestCase):
    def test_non_packet_object_returns_none(self) -> None:
        self.assertIsNone(parse_packet(make_malformed_standin()))

    def test_none_returns_none(self) -> None:
        self.assertIsNone(parse_packet(None))

    def test_parser_never_raises_on_odd_layers(self) -> None:
        # An out-of-range TCP window makes Scapy unable to build/len the
        # packet; Module 2 must return None rather than propagate the error.
        pkt = IP(src="1.1.1.1", dst="2.2.2.2", ttl=10) / TCP(
            sport=1, dport=2, flags="S", window=8192
        )
        pkt.time = 1_700_000_020.0
        pkt[TCP].window = 999999
        self.assertIsNone(parse_packet(pkt))

    def test_invalid_window_value_normalized_when_buildable(self) -> None:
        # When length can be measured before field access, out-of-range window
        # is dropped to None rather than fabricating a value.
        meta = parse_packet(make_tcp_packet(window=8192))
        assert meta is not None
        self.assertEqual(meta.tcp_window, 8192)
        self.assertIsNone(normalize_tcp_window(999999))
        self.assertIsNone(normalize_tcp_window(-1))



if __name__ == "__main__":
    unittest.main()
