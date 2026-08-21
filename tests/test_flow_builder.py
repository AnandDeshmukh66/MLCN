"""Unit and integration tests for Module 3 Flow Builder."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from flow_builder import Flow, FlowBuilder, FlowKey, canonicalize_flow_key
from packet_parsing import PacketMetadata, parse_packet
from tests.fixtures import (
    make_ethernet_only_packet,
    make_icmp_packet,
    make_malformed_standin,
    make_tcp_packet,
    make_udp_packet,
)


def _ts(seconds: float) -> datetime:
    return datetime.fromtimestamp(1_700_000_000.0 + seconds, tz=timezone.utc)


def _meta(
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int | None = 54321,
    dst_port: int | None = 80,
    protocol: str = "TCP",
    length: int = 100,
    at: float = 0.0,
    tcp_flags: str | None = "S",
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=_ts(at),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        tcp_flags=tcp_flags,
        ttl=64,
        tcp_window=8192 if protocol == "TCP" else None,
    )


class TestFlowKeyCanonicalization(unittest.TestCase):
    def test_reverse_direction_shares_key(self) -> None:
        forward = canonicalize_flow_key("10.0.0.1", "10.0.0.2", 54321, 80, "TCP")
        reverse = canonicalize_flow_key("10.0.0.2", "10.0.0.1", 80, 54321, "TCP")
        self.assertEqual(forward, reverse)

    def test_different_tuples_differ(self) -> None:
        a = canonicalize_flow_key("10.0.0.1", "10.0.0.2", 54321, 80, "TCP")
        b = canonicalize_flow_key("10.0.0.1", "10.0.0.2", 54321, 443, "TCP")
        c = canonicalize_flow_key("10.0.0.1", "10.0.0.2", 54321, 80, "UDP")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)


class TestPacketGrouping(unittest.TestCase):
    def test_packets_join_same_flow(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0, max_duration=300.0)
        builder.add_packet(_meta(at=0.0, length=60, tcp_flags="S"))
        builder.add_packet(_meta(at=1.0, length=80, tcp_flags="A"))
        flows = builder.flush()

        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.byte_count, 140)
        self.assertEqual(len(flow.packets), 2)
        self.assertEqual(flow.duration, 1.0)

    def test_reverse_direction_joins_same_flow(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(_meta(at=0.0, length=60, tcp_flags="S"))
        builder.add_packet(
            _meta(
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=80,
                dst_port=54321,
                at=0.5,
                length=40,
                tcp_flags="SA",
            )
        )
        flows = builder.flush()

        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.reverse_packet_count, 1)
        self.assertEqual(flow.forward_byte_count, 60)
        self.assertEqual(flow.reverse_byte_count, 40)
        self.assertEqual(flow.byte_count, 100)

    def test_different_five_tuples_create_separate_flows(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(_meta(dst_port=80, at=0.0))
        builder.add_packet(_meta(dst_port=443, at=0.1))
        builder.add_packet(
            _meta(
                src_ip="10.0.0.3",
                dst_ip="10.0.0.4",
                src_port=1000,
                dst_port=53,
                protocol="UDP",
                at=0.2,
                tcp_flags=None,
            )
        )
        flows = builder.flush()
        self.assertEqual(len(flows), 3)
        keys = {flow.key for flow in flows}
        self.assertEqual(len(keys), 3)


class TestTimeoutAndMemory(unittest.TestCase):
    def test_inactivity_timeout_completes_flow(self) -> None:
        builder = FlowBuilder(inactivity_timeout=10.0, max_duration=300.0)
        completed = builder.add_packet(_meta(at=0.0, length=50))
        self.assertEqual(completed, [])
        self.assertEqual(builder.active_count, 1)

        completed = builder.add_packet(
            _meta(
                src_ip="192.168.0.1",
                dst_ip="192.168.0.2",
                src_port=1111,
                dst_port=2222,
                at=10.0,
                length=20,
            )
        )
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].packet_count, 1)
        self.assertEqual(completed[0].byte_count, 50)
        self.assertEqual(builder.active_count, 1)

    def test_expire_cleans_idle_flows(self) -> None:
        builder = FlowBuilder(inactivity_timeout=5.0)
        builder.add_packet(_meta(at=0.0))
        self.assertEqual(builder.active_count, 1)

        expired = builder.expire(_ts(5.0))
        self.assertEqual(len(expired), 1)
        self.assertEqual(builder.active_count, 0)

    def test_max_duration_closes_active_flow(self) -> None:
        builder = FlowBuilder(inactivity_timeout=1000.0, max_duration=10.0)
        builder.add_packet(_meta(at=0.0, length=10))
        # Same conversation after active timeout → old flow closed, new started.
        completed = builder.add_packet(_meta(at=10.0, length=20, tcp_flags="A"))
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].packet_count, 1)
        self.assertEqual(completed[0].byte_count, 10)
        self.assertEqual(builder.active_count, 1)

        flushed = builder.flush()
        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0].packet_count, 1)
        self.assertEqual(flushed[0].byte_count, 20)

    def test_max_active_flows_evicts_oldest(self) -> None:
        builder = FlowBuilder(
            inactivity_timeout=1000.0,
            max_duration=1000.0,
            max_active_flows=2,
        )
        builder.add_packet(_meta(dst_port=80, at=0.0))
        builder.add_packet(_meta(dst_port=81, at=1.0))
        self.assertEqual(builder.active_count, 2)

        completed = builder.add_packet(_meta(dst_port=82, at=2.0))
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].key.dst_port, 80)
        self.assertEqual(builder.active_count, 2)


class TestAggregation(unittest.TestCase):
    def test_packet_and_byte_aggregation(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(_meta(at=0.0, length=100))
        builder.add_packet(_meta(at=1.0, length=250, tcp_flags="A"))
        builder.add_packet(_meta(at=2.0, length=50, tcp_flags="A"))
        flow = builder.flush()[0]

        self.assertEqual(flow.packet_count, 3)
        self.assertEqual(flow.byte_count, 400)
        self.assertEqual(flow.start_time, _ts(0.0))
        self.assertEqual(flow.end_time, _ts(2.0))
        self.assertAlmostEqual(flow.duration, 2.0)
        self.assertEqual(flow.forward_packet_count, 3)
        self.assertEqual(flow.reverse_packet_count, 0)


class TestProtocolAndMissingPorts(unittest.TestCase):
    def test_tcp_and_udp_flows(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(_meta(protocol="TCP", at=0.0))
        builder.add_packet(
            _meta(
                protocol="UDP",
                src_port=53000,
                dst_port=53,
                at=0.1,
                tcp_flags=None,
            )
        )
        flows = {flow.protocol: flow for flow in builder.flush()}
        self.assertIn("TCP", flows)
        self.assertIn("UDP", flows)

    def test_icmp_without_ports(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(
            _meta(
                src_ip="8.8.8.8",
                dst_ip="1.1.1.1",
                src_port=None,
                dst_port=None,
                protocol="ICMP",
                at=0.0,
                length=64,
                tcp_flags=None,
            )
        )
        builder.add_packet(
            _meta(
                src_ip="1.1.1.1",
                dst_ip="8.8.8.8",
                src_port=None,
                dst_port=None,
                protocol="ICMP",
                at=0.2,
                length=64,
                tcp_flags=None,
            )
        )
        flows = builder.flush()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].protocol, "ICMP")
        self.assertIsNone(flows[0].src_port)
        self.assertIsNone(flows[0].dst_port)
        self.assertEqual(flows[0].packet_count, 2)
        self.assertEqual(flows[0].forward_packet_count, 1)
        self.assertEqual(flows[0].reverse_packet_count, 1)

    def test_packets_without_ips_are_skipped(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        completed = builder.add_packet(
            PacketMetadata(
                timestamp=_ts(0.0),
                src_ip=None,
                dst_ip=None,
                protocol="Other",
                src_port=None,
                dst_port=None,
                length=40,
            )
        )
        self.assertEqual(completed, [])
        self.assertEqual(builder.active_count, 0)
        self.assertEqual(builder.flush(), [])


class TestMalformedInput(unittest.TestCase):
    def test_none_and_wrong_type_do_not_crash(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        self.assertEqual(builder.add_packet(None), [])
        self.assertEqual(builder.add_packet(make_malformed_standin()), [])  # type: ignore[arg-type]
        self.assertEqual(builder.add_packet("not-a-packet"), [])  # type: ignore[arg-type]
        self.assertEqual(builder.active_count, 0)

    def test_batch_skips_bad_entries(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        completed = builder.add_packets(
            [
                None,
                _meta(at=0.0),
                make_malformed_standin(),  # type: ignore[list-item]
                _meta(at=1.0, tcp_flags="A"),
            ]
        )
        self.assertEqual(completed, [])
        flows = builder.flush()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].packet_count, 2)


class TestModule2Integration(unittest.TestCase):
    def test_consumes_module2_packet_metadata(self) -> None:
        tcp = parse_packet(make_tcp_packet(flags="S", payload=b"abc"))
        tcp_ack = parse_packet(
            make_tcp_packet(
                src="10.0.0.2",
                dst="10.0.0.1",
                sport=80,
                dport=54321,
                flags="SA",
            )
        )
        udp = parse_packet(make_udp_packet())
        icmp = parse_packet(make_icmp_packet())
        eth = parse_packet(make_ethernet_only_packet())
        bad = parse_packet(make_malformed_standin())

        self.assertIsInstance(tcp, PacketMetadata)
        self.assertIsInstance(tcp_ack, PacketMetadata)
        assert tcp is not None and tcp_ack is not None

        # Align reverse packet onto the same conversation timeline.
        tcp_ack = PacketMetadata(
            timestamp=tcp.timestamp + timedelta(milliseconds=5),
            src_ip=tcp_ack.src_ip,
            dst_ip=tcp_ack.dst_ip,
            protocol=tcp_ack.protocol,
            src_port=tcp_ack.src_port,
            dst_port=tcp_ack.dst_port,
            length=tcp_ack.length,
            tcp_flags=tcp_ack.tcp_flags,
            ttl=tcp_ack.ttl,
            tcp_window=tcp_ack.tcp_window,
        )

        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packets([tcp, tcp_ack, udp, icmp, eth, bad])
        flows = builder.flush()

        by_proto: dict[str, list[Flow]] = {}
        for flow in flows:
            by_proto.setdefault(flow.protocol, []).append(flow)

        self.assertEqual(len(by_proto["TCP"]), 1)
        self.assertEqual(by_proto["TCP"][0].packet_count, 2)
        self.assertEqual(by_proto["TCP"][0].forward_packet_count, 1)
        self.assertEqual(by_proto["TCP"][0].reverse_packet_count, 1)
        self.assertEqual(len(by_proto["UDP"]), 1)
        self.assertEqual(len(by_proto["ICMP"]), 1)
        # Ethernet-only / malformed never become flows.
        self.assertNotIn("Other", by_proto)
        self.assertIsInstance(by_proto["TCP"][0].key, FlowKey)
        self.assertGreater(by_proto["TCP"][0].byte_count, 0)
        # Packet-level metadata preserved for Feature Engineering.
        self.assertEqual(by_proto["TCP"][0].packets[0].tcp_flags, "S")
        self.assertEqual(by_proto["TCP"][0].packets[1].tcp_flags, "SA")


class TestModule1Module2Module3Pipeline(unittest.TestCase):
    def test_end_to_end_capture_parse_flow(self) -> None:
        from packet_capture import PacketCaptureEngine

        engine = PacketCaptureEngine.__new__(PacketCaptureEngine)
        engine._packets_seen = 0
        engine._packets_printed = 0

        builder = FlowBuilder(inactivity_timeout=60.0)
        raw_packets = [
            make_tcp_packet(flags="S"),
            make_tcp_packet(
                src="10.0.0.2",
                dst="10.0.0.1",
                sport=80,
                dport=54321,
                flags="SA",
            ),
            make_udp_packet(),
            make_malformed_standin(),
            make_icmp_packet(),
        ]

        for raw in raw_packets:
            meta = engine._parse_raw_packet(raw)
            builder.add_packet(meta)

        flows = builder.flush()
        self.assertEqual(len(flows), 3)
        self.assertEqual(engine._packets_seen, 5)
        self.assertEqual(engine._packets_printed, 4)

        protocols = sorted(flow.protocol for flow in flows)
        self.assertEqual(protocols, ["ICMP", "TCP", "UDP"])
        tcp_flow = next(flow for flow in flows if flow.protocol == "TCP")
        self.assertEqual(tcp_flow.packet_count, 2)


if __name__ == "__main__":
    unittest.main()
