"""Unit and integration tests for Module 4 Feature Engineering Engine."""

from __future__ import annotations

import json
import math
import statistics
import unittest
from datetime import datetime, timezone
from pathlib import Path

from flow_builder import Flow, FlowBuilder, FlowKey
from feature_engineering import (
    ACTIVITY_TIMEOUT_SECONDS,
    FEATURE_COUNT,
    FEATURE_ORDER,
    FeatureEngineeringEngine,
    FeatureVector,
    compute_feature_map,
    extract_features,
)
from packet_parsing import PacketMetadata, parse_packet
from tests.fixtures import make_tcp_packet, make_udp_packet


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


def _reverse(
    *,
    length: int = 40,
    at: float = 1.0,
    tcp_flags: str | None = "SA",
) -> PacketMetadata:
    return _meta(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=80,
        dst_port=54321,
        length=length,
        at=at,
        tcp_flags=tcp_flags,
    )


def _flow_from_packets(packets: tuple[PacketMetadata, ...]) -> Flow:
    if not packets:
        key = FlowKey(
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            src_port=0,
            dst_port=0,
            protocol="TCP",
        )
        now = _ts(0.0)
        return Flow(
            key=key,
            start_time=now,
            end_time=now,
            packet_count=0,
            byte_count=0,
            forward_packet_count=0,
            reverse_packet_count=0,
            forward_byte_count=0,
            reverse_byte_count=0,
            packets=(),
        )

    anchor = packets[0]
    key = FlowKey(
        src_ip=anchor.src_ip or "",
        dst_ip=anchor.dst_ip or "",
        src_port=anchor.src_port,
        dst_port=anchor.dst_port,
        protocol=anchor.protocol,
    )
    fwd = rev = fwd_bytes = rev_bytes = 0
    for packet in packets:
        if (
            packet.src_ip == anchor.src_ip
            and packet.dst_ip == anchor.dst_ip
            and packet.src_port == anchor.src_port
            and packet.dst_port == anchor.dst_port
        ):
            fwd += 1
            fwd_bytes += max(0, packet.length)
        else:
            rev += 1
            rev_bytes += max(0, packet.length)
    return Flow(
        key=key,
        start_time=packets[0].timestamp,
        end_time=max(p.timestamp for p in packets),
        packet_count=len(packets),
        byte_count=sum(max(0, p.length) for p in packets),
        forward_packet_count=fwd,
        reverse_packet_count=rev,
        forward_byte_count=fwd_bytes,
        reverse_byte_count=rev_bytes,
        packets=packets,
    )


class TestSchemaCompliance(unittest.TestCase):
    def test_feature_count_is_24(self) -> None:
        self.assertEqual(FEATURE_COUNT, 24)
        self.assertEqual(len(FEATURE_ORDER), 24)

    def test_feature_order_matches_schema_json(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "data" / "common_feature_schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(list(FEATURE_ORDER), schema["feature_order"])
        self.assertEqual(ACTIVITY_TIMEOUT_SECONDS, schema["activity_timeout_seconds"])

    def test_vector_preserves_order(self) -> None:
        flow = _flow_from_packets((_meta(at=0.0, length=60, tcp_flags="S"),))
        vector = extract_features(flow)
        self.assertEqual(list(vector.names), list(FEATURE_ORDER))
        self.assertEqual(len(vector), 24)
        self.assertEqual(len(vector.as_list()), 24)
        self.assertEqual(set(vector.as_dict()), set(FEATURE_ORDER))


class TestNormalAndDirectionalFlows(unittest.TestCase):
    def test_normal_bidirectional_flow(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=60, tcp_flags="S"),
                _reverse(at=1.0, length=40, tcp_flags="SA"),
                _meta(at=2.0, length=80, tcp_flags="A"),
                _reverse(at=3.0, length=100, tcp_flags="PA"),
            )
        )
        vector = extract_features(flow)
        values = vector.as_dict()

        self.assertEqual(values["Flow Duration"], 3.0)
        self.assertEqual(values["Total Fwd Packets"], 2)
        self.assertEqual(values["Total Backward Packets"], 2)
        self.assertEqual(values["Fwd Packets Length Total"], 140)
        self.assertEqual(values["Bwd Packets Length Total"], 140)
        self.assertEqual(values["Fwd Packet Length Mean"], 70.0)
        self.assertEqual(values["Bwd Packet Length Mean"], 70.0)
        self.assertAlmostEqual(values["Flow Bytes/s"], 280.0 / 3.0)
        self.assertAlmostEqual(values["Flow Packets/s"], 4.0 / 3.0)
        self.assertAlmostEqual(values["Flow IAT Mean"], 1.0)
        self.assertAlmostEqual(values["Flow IAT Std"], 0.0)
        self.assertAlmostEqual(values["Fwd IAT Mean"], 2.0)
        self.assertAlmostEqual(values["Bwd IAT Mean"], 2.0)
        self.assertAlmostEqual(values["Packet Length Mean"], 70.0)
        self.assertAlmostEqual(
            values["Packet Length Std"],
            statistics.stdev([60.0, 40.0, 80.0, 100.0]),
        )
        self.assertEqual(values["Down/Up Ratio"], 1.0)
        self.assertAlmostEqual(values["Active Mean"], 3.0)
        self.assertEqual(values["Idle Mean"], 0.0)

    def test_forward_only_flow(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=50, tcp_flags="S"),
                _meta(at=1.0, length=70, tcp_flags="A"),
                _meta(at=2.0, length=90, tcp_flags="A"),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertEqual(values["Total Fwd Packets"], 3)
        self.assertEqual(values["Total Backward Packets"], 0)
        self.assertEqual(values["Bwd Packets Length Total"], 0)
        self.assertEqual(values["Bwd Packet Length Mean"], 0.0)
        self.assertEqual(values["Bwd IAT Mean"], 0.0)
        self.assertEqual(values["Down/Up Ratio"], 0.0)
        self.assertAlmostEqual(values["Fwd IAT Mean"], 1.0)
        self.assertAlmostEqual(values["Fwd Packet Length Mean"], 70.0)

    def test_reverse_only_counts_via_zero_forward_means(self) -> None:
        # First packet defines forward; subsequent reverse packets only.
        # A flow that is "reverse-only" after the first packet still has
        # at least one forward packet (the opener). Zero-forward is the
        # empty / synthetic case covered separately.
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=60, tcp_flags="S"),
                _reverse(at=0.5, length=40, tcp_flags="SA"),
                _reverse(at=1.5, length=80, tcp_flags="A"),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertEqual(values["Total Fwd Packets"], 1)
        self.assertEqual(values["Total Backward Packets"], 2)
        self.assertEqual(values["Fwd IAT Mean"], 0.0)
        self.assertAlmostEqual(values["Bwd IAT Mean"], 1.0)
        self.assertAlmostEqual(values["Down/Up Ratio"], 0.5)


class TestEdgeCases(unittest.TestCase):
    def test_single_packet_flow(self) -> None:
        flow = _flow_from_packets((_meta(at=0.0, length=60, tcp_flags="S"),))
        values = extract_features(flow).as_dict()
        self.assertEqual(values["Flow Duration"], 0.0)
        self.assertEqual(values["Total Fwd Packets"], 1)
        self.assertEqual(values["Total Backward Packets"], 0)
        self.assertEqual(values["Flow Bytes/s"], 0.0)
        self.assertEqual(values["Flow Packets/s"], 0.0)
        self.assertEqual(values["Flow IAT Mean"], 0.0)
        self.assertEqual(values["Flow IAT Std"], 0.0)
        self.assertEqual(values["Fwd IAT Mean"], 0.0)
        self.assertEqual(values["Bwd IAT Mean"], 0.0)
        self.assertEqual(values["Packet Length Mean"], 60.0)
        self.assertEqual(values["Packet Length Std"], 0.0)
        self.assertEqual(values["Active Mean"], 0.0)
        self.assertEqual(values["Idle Mean"], 0.0)
        self.assertEqual(values["Down/Up Ratio"], 0.0)

    def test_zero_duration_multi_packet(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=5.0, length=80, tcp_flags="PA"),
                _meta(at=5.0, length=120, tcp_flags="A"),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertEqual(values["Flow Duration"], 0.0)
        self.assertEqual(values["Flow Bytes/s"], 0.0)
        self.assertEqual(values["Flow Packets/s"], 0.0)
        self.assertEqual(values["Flow IAT Mean"], 0.0)
        self.assertEqual(values["Flow IAT Std"], 0.0)
        self.assertEqual(values["Active Mean"], 0.0)

    def test_empty_packet_collection(self) -> None:
        flow = _flow_from_packets(())
        values = extract_features(flow).as_dict()
        for name in FEATURE_ORDER:
            self.assertEqual(values[name], 0.0, msg=name)

    def test_zero_division_means_and_ratio(self) -> None:
        flow = Flow(
            key=FlowKey("10.0.0.1", "10.0.0.2", 1, 2, "TCP"),
            start_time=_ts(0.0),
            end_time=_ts(0.0),
            packet_count=0,
            byte_count=0,
            forward_packet_count=0,
            reverse_packet_count=0,
            forward_byte_count=0,
            reverse_byte_count=0,
            packets=(),
        )
        values = extract_features(flow).as_dict()
        self.assertEqual(values["Fwd Packet Length Mean"], 0.0)
        self.assertEqual(values["Bwd Packet Length Mean"], 0.0)
        self.assertEqual(values["Down/Up Ratio"], 0.0)
        self.assertEqual(values["Flow Bytes/s"], 0.0)
        self.assertEqual(values["Flow Packets/s"], 0.0)


class TestTcpFlagsAndIat(unittest.TestCase):
    def test_tcp_flag_counting(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=60, tcp_flags="S"),
                _reverse(at=0.1, length=40, tcp_flags="SA"),
                _meta(at=0.2, length=80, tcp_flags="PA"),
                _reverse(at=0.3, length=40, tcp_flags="FA"),
                _meta(at=0.4, length=40, tcp_flags="R"),
                _meta(at=0.5, length=40, tcp_flags="UAP"),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertEqual(values["FIN Flag Count"], 1)
        self.assertEqual(values["SYN Flag Count"], 2)
        self.assertEqual(values["RST Flag Count"], 1)
        self.assertEqual(values["PSH Flag Count"], 2)
        self.assertEqual(values["ACK Flag Count"], 4)
        self.assertEqual(values["URG Flag Count"], 1)

    def test_missing_tcp_flags_contribute_zero(self) -> None:
        flow = _flow_from_packets(
            (
                PacketMetadata(
                    timestamp=_ts(0.0),
                    src_ip="192.168.0.1",
                    dst_ip="192.168.0.2",
                    protocol="UDP",
                    src_port=1000,
                    dst_port=53,
                    length=200,
                    tcp_flags=None,
                    ttl=64,
                    tcp_window=None,
                ),
                PacketMetadata(
                    timestamp=_ts(1.0),
                    src_ip="192.168.0.1",
                    dst_ip="192.168.0.2",
                    protocol="UDP",
                    src_port=1000,
                    dst_port=53,
                    length=200,
                    tcp_flags=None,
                    ttl=64,
                    tcp_window=None,
                ),
            )
        )
        values = extract_features(flow).as_dict()
        for flag in (
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
        ):
            self.assertEqual(values[flag], 0)

    def test_iat_statistics(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=10),
                _meta(at=1.0, length=10),
                _meta(at=4.0, length=10),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertAlmostEqual(values["Flow IAT Mean"], 2.0)
        self.assertAlmostEqual(values["Flow IAT Std"], statistics.stdev([1.0, 3.0]))
        self.assertAlmostEqual(values["Fwd IAT Mean"], 2.0)


class TestActiveIdle(unittest.TestCase):
    def test_active_idle_with_gap_above_threshold(self) -> None:
        # Active [0→1]=1.0, idle gap 9.0, active [10→11]=1.0
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=50, tcp_flags="S"),
                _meta(at=1.0, length=50, tcp_flags="A"),
                _meta(at=10.0, length=50, tcp_flags="A"),
                _meta(at=11.0, length=50, tcp_flags="A"),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertAlmostEqual(values["Active Mean"], 1.0)
        self.assertAlmostEqual(values["Idle Mean"], 9.0)
        self.assertEqual(ACTIVITY_TIMEOUT_SECONDS, 5.0)

    def test_no_idle_when_gaps_within_threshold(self) -> None:
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=50),
                _meta(at=2.0, length=50),
                _meta(at=4.0, length=50),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertAlmostEqual(values["Active Mean"], 4.0)
        self.assertEqual(values["Idle Mean"], 0.0)

    def test_gap_exactly_at_threshold_is_active(self) -> None:
        # Schema: split when gap *exceeds* threshold (gap > 5.0).
        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=50),
                _meta(at=5.0, length=50),
            )
        )
        values = extract_features(flow).as_dict()
        self.assertAlmostEqual(values["Active Mean"], 5.0)
        self.assertEqual(values["Idle Mean"], 0.0)


class TestEngineApiAndIntegration(unittest.TestCase):
    def test_engine_extract_many(self) -> None:
        engine = FeatureEngineeringEngine()
        flows = [
            _flow_from_packets((_meta(at=0.0, length=60, tcp_flags="S"),)),
            _flow_from_packets(
                (
                    _meta(at=0.0, length=60, tcp_flags="S"),
                    _reverse(at=1.0, length=40, tcp_flags="SA"),
                )
            ),
        ]
        vectors = engine.extract_many(flows)
        self.assertEqual(len(vectors), 2)
        self.assertIsInstance(vectors[0], FeatureVector)
        self.assertEqual(vectors[0].as_dict()["Total Fwd Packets"], 1)
        self.assertEqual(vectors[1].as_dict()["Total Backward Packets"], 1)

    def test_non_flow_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            extract_features("not-a-flow")  # type: ignore[arg-type]

    def test_invalid_activity_timeout(self) -> None:
        with self.assertRaises(ValueError):
            FeatureEngineeringEngine(activity_timeout=0.0)

    def test_module3_to_module4_pipeline(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        builder.add_packet(_meta(at=0.0, length=60, tcp_flags="S"))
        builder.add_packet(_reverse(at=0.5, length=40, tcp_flags="SA"))
        builder.add_packet(_meta(at=1.0, length=80, tcp_flags="PA"))
        flows = builder.flush()
        self.assertEqual(len(flows), 1)

        vector = extract_features(flows[0])
        self.assertEqual(len(vector), 24)
        values = vector.as_dict()
        self.assertEqual(values["Total Fwd Packets"], 2)
        self.assertEqual(values["Total Backward Packets"], 1)
        self.assertEqual(values["SYN Flag Count"], 2)
        self.assertEqual(values["FIN Flag Count"], 0)
        self.assertEqual(values["PSH Flag Count"], 1)
        self.assertTrue(all(math.isfinite(v) for v in vector))

    def test_module2_parse_to_module4(self) -> None:
        builder = FlowBuilder(inactivity_timeout=60.0)
        raw_packets = [
            make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=80, flags="S"),
            make_tcp_packet(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=54321, flags="SA"),
            make_udp_packet(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=53),
        ]
        # Stamp increasing times so duration / IAT are well-defined.
        for index, packet in enumerate(raw_packets):
            packet.time = 1_700_000_000.0 + index

        for raw in raw_packets:
            meta = parse_packet(raw)
            self.assertIsNotNone(meta)
            builder.add_packet(meta)

        flows = builder.flush()
        engine = FeatureEngineeringEngine()
        vectors = engine.extract_many(flows)
        self.assertGreaterEqual(len(vectors), 1)
        for vector in vectors:
            self.assertEqual(len(vector), FEATURE_COUNT)
            self.assertTrue(all(math.isfinite(v) for v in vector))

    def test_matches_schema_reference_probe(self) -> None:
        from data.common_feature_schema import _reference_feature_values

        flow = _flow_from_packets(
            (
                _meta(at=0.0, length=60, tcp_flags="S"),
                _reverse(at=1.0, length=40, tcp_flags="SA"),
                _meta(at=2.0, length=80, tcp_flags="A"),
                _meta(at=10.0, length=50, tcp_flags="FA"),
            )
        )
        expected = _reference_feature_values(flow)
        actual = compute_feature_map(flow)
        for name in FEATURE_ORDER:
            self.assertAlmostEqual(
                float(actual[name]),
                float(expected[name]),
                places=9,
                msg=name,
            )

    def test_feature_vector_from_mapping_and_zeros(self) -> None:
        zeros = FeatureVector.zeros()
        self.assertEqual(zeros.as_list(), [0.0] * 24)
        rebuilt = FeatureVector.from_mapping({"Flow Duration": 1.5, "SYN Flag Count": 2})
        self.assertEqual(rebuilt.get("Flow Duration"), 1.5)
        self.assertEqual(rebuilt.get("SYN Flag Count"), 2.0)
        self.assertEqual(rebuilt.get("Idle Mean"), 0.0)
        with self.assertRaises(KeyError):
            rebuilt.get("Not A Feature")
        with self.assertRaises(ValueError):
            FeatureVector(values=(1.0, 2.0))


if __name__ == "__main__":
    unittest.main()
