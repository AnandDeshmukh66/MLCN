"""Module 1 → Module 2 integration tests (no live network traffic)."""

from __future__ import annotations

import unittest
from datetime import timezone

from packet_capture import PacketCaptureEngine, ParsedPacket, metadata_to_parsed_packet
from packet_capture.parser import parse_packet as parse_for_module1
from packet_parsing import PacketMetadata, parse_packet as parse_for_module2
from tests.fixtures import (
    make_ethernet_only_packet,
    make_icmp_packet,
    make_malformed_standin,
    make_tcp_packet,
    make_udp_packet,
)


class TestModule1Module2Integration(unittest.TestCase):
    def test_module1_parser_delegates_to_module2(self) -> None:
        raw = make_tcp_packet(flags="SA", ttl=55, window=4096)
        metadata = parse_for_module2(raw)
        display = parse_for_module1(raw)

        self.assertIsInstance(metadata, PacketMetadata)
        self.assertIsInstance(display, ParsedPacket)
        assert metadata is not None and display is not None

        self.assertEqual(display.protocol, metadata.protocol)
        self.assertEqual(display.src_ip, metadata.src_ip)
        self.assertEqual(display.dst_ip, metadata.dst_ip)
        self.assertEqual(display.src_port, metadata.src_port)
        self.assertEqual(display.dst_port, metadata.dst_port)
        self.assertEqual(display.length, metadata.length)
        self.assertEqual(display.tcp_flags, metadata.tcp_flags)
        # Module 2 exposes TTL / window; Module 1 display model does not.
        self.assertEqual(metadata.ttl, 55)
        self.assertEqual(metadata.tcp_window, 4096)

    def test_metadata_to_parsed_packet_maps_missing_ips(self) -> None:
        metadata = parse_for_module2(make_ethernet_only_packet())
        assert metadata is not None
        display = metadata_to_parsed_packet(metadata)
        self.assertEqual(display.src_ip, "-")
        self.assertEqual(display.dst_ip, "-")
        self.assertEqual(display.protocol, "Other")

    def test_engine_parse_path_produces_metadata(self) -> None:
        engine = PacketCaptureEngine.__new__(PacketCaptureEngine)
        engine._packets_seen = 0
        engine._packets_printed = 0

        tcp_meta = engine._parse_raw_packet(make_tcp_packet())
        udp_meta = engine._parse_raw_packet(make_udp_packet())
        icmp_meta = engine._parse_raw_packet(make_icmp_packet())
        bad = engine._parse_raw_packet(make_malformed_standin())

        self.assertIsInstance(tcp_meta, PacketMetadata)
        self.assertIsInstance(udp_meta, PacketMetadata)
        self.assertIsInstance(icmp_meta, PacketMetadata)
        self.assertIsNone(bad)
        self.assertEqual(engine._packets_seen, 4)
        self.assertEqual(engine._packets_printed, 3)

        assert tcp_meta is not None
        self.assertEqual(tcp_meta.protocol, "TCP")
        self.assertEqual(tcp_meta.timestamp.tzinfo, timezone.utc)

    def test_engine_display_dispatch_uses_parsed_packet(self) -> None:
        received: list[ParsedPacket] = []
        engine = PacketCaptureEngine.__new__(PacketCaptureEngine)
        engine._packets_seen = 0
        engine._packets_printed = 0
        engine._packet_handler = received.append

        engine._handle_raw_packet(make_tcp_packet(flags="S"))
        self.assertEqual(len(received), 1)
        self.assertIsInstance(received[0], ParsedPacket)
        self.assertEqual(received[0].tcp_flags, "S")

    def test_malformed_does_not_break_pipeline(self) -> None:
        engine = PacketCaptureEngine.__new__(PacketCaptureEngine)
        engine._packets_seen = 0
        engine._packets_printed = 0
        received: list[PacketMetadata] = []

        for raw in (
            make_malformed_standin(),
            make_tcp_packet(),
            None,
            make_udp_packet(),
        ):
            meta = engine._parse_raw_packet(raw)
            if meta is not None:
                received.append(meta)

        self.assertEqual(len(received), 2)
        self.assertEqual(received[0].protocol, "TCP")
        self.assertEqual(received[1].protocol, "UDP")


if __name__ == "__main__":
    unittest.main()
