"""End-to-end integration tests for the Modules 1–5 pipeline."""

from __future__ import annotations

import math
import unittest
from unittest.mock import patch

from feature_engineering import FEATURE_COUNT, FEATURE_ORDER, FeatureVector
from flow_builder import Flow
from ml_detection import CLASS_ORDER, DetectionResult
from packet_capture import PacketCaptureEngine
from packet_parsing import PacketMetadata, parse_packet
from pipeline import IntrusionDetectionPipeline, PipelineResult
from tests.fixtures import (
    make_ethernet_only_packet,
    make_malformed_standin,
    make_tcp_packet,
    make_udp_packet,
)


def _stamp(packet, seconds: float) -> None:
    packet.time = 1_700_000_000.0 + seconds


class TestModuleHandoffs(unittest.TestCase):
    def test_module1_to_module2_handoff(self) -> None:
        """Module 1 parse path yields Module 2 PacketMetadata."""
        engine = PacketCaptureEngine.__new__(PacketCaptureEngine)
        engine._packets_seen = 0
        engine._packets_printed = 0

        raw = make_tcp_packet(flags="S")
        _stamp(raw, 0.0)
        metadata = engine._parse_raw_packet(raw)

        self.assertIsInstance(metadata, PacketMetadata)
        self.assertEqual(metadata.protocol, "TCP")
        self.assertEqual(metadata.src_ip, "10.0.0.1")
        self.assertEqual(metadata.dst_ip, "10.0.0.2")
        self.assertIsNotNone(metadata.tcp_flags)

    def test_module2_to_module3_handoff(self) -> None:
        pipeline = IntrusionDetectionPipeline(inactivity_timeout=60.0)
        raw = make_tcp_packet(flags="S")
        _stamp(raw, 0.0)
        meta = parse_packet(raw)
        self.assertIsNotNone(meta)

        completed = pipeline.process_metadata(meta)
        self.assertEqual(completed, [])
        self.assertEqual(pipeline.active_flow_count, 1)

        flushed = pipeline.flush()
        self.assertEqual(len(flushed), 1)
        self.assertIsInstance(flushed[0].flow, Flow)
        self.assertEqual(flushed[0].flow.packet_count, 1)

    def test_module3_to_module4_handoff(self) -> None:
        pipeline = IntrusionDetectionPipeline()
        raw = make_tcp_packet(flags="SA", payload=b"abc")
        _stamp(raw, 0.0)
        results = pipeline.process_raw_packets([raw], flush=True)
        self.assertEqual(len(results), 1)

        features = results[0].features
        self.assertIsInstance(features, FeatureVector)
        self.assertEqual(len(features), FEATURE_COUNT)
        self.assertEqual(list(features.names), list(FEATURE_ORDER))
        self.assertTrue(all(math.isfinite(v) for v in features))

    def test_module4_to_module5_and_detection_result(self) -> None:
        pipeline = IntrusionDetectionPipeline()
        packets = []
        for index, flags in enumerate(("S", "A", "PA", "FA")):
            pkt = make_tcp_packet(flags=flags, payload=b"x" * (index + 1))
            _stamp(pkt, float(index) * 0.2)
            packets.append(pkt)

        results = pipeline.process_raw_packets(packets, flush=True)
        self.assertEqual(len(results), 1)

        detection = results[0].detection
        self.assertIsInstance(detection, DetectionResult)
        self.assertIn(detection.predicted_class, CLASS_ORDER)
        self.assertEqual(
            detection.predicted_class_id,
            CLASS_ORDER.index(detection.predicted_class),
        )
        self.assertGreater(detection.confidence, 0.0)
        self.assertLessEqual(detection.confidence, 1.0)
        self.assertEqual(set(detection.probabilities), set(CLASS_ORDER))
        self.assertAlmostEqual(sum(detection.probabilities.values()), 1.0, places=5)


class TestPipelineBehaviors(unittest.TestCase):
    def test_multiple_flows(self) -> None:
        pipeline = IntrusionDetectionPipeline(inactivity_timeout=60.0)
        packets = [
            make_tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=80, flags="S"),
            make_tcp_packet(src="10.0.0.3", dst="10.0.0.4", sport=2222, dport=443, flags="S"),
            make_udp_packet(src="10.0.0.5", dst="10.0.0.6", sport=3333, dport=53),
        ]
        for index, pkt in enumerate(packets):
            _stamp(pkt, float(index))

        results = pipeline.process_raw_packets(packets, flush=True)
        self.assertEqual(len(results), 3)
        self.assertEqual(pipeline.flows_detected, 3)
        self.assertEqual(pipeline.active_flow_count, 0)
        protocols = {result.flow.protocol for result in results}
        self.assertEqual(protocols, {"TCP", "UDP"})

    def test_flush_at_shutdown_closes_active_flows(self) -> None:
        pipeline = IntrusionDetectionPipeline(inactivity_timeout=600.0)
        pkt = make_tcp_packet(flags="S")
        _stamp(pkt, 0.0)

        mid = pipeline.process_raw_packets([pkt], flush=False)
        self.assertEqual(mid, [])
        self.assertEqual(pipeline.active_flow_count, 1)

        closed = pipeline.close()
        self.assertEqual(len(closed), 1)
        self.assertEqual(pipeline.active_flow_count, 0)
        self.assertIsInstance(closed[0], PipelineResult)

        with self.assertRaises(RuntimeError):
            pipeline.process_raw_packet(pkt)

    def test_benign_traffic_produces_valid_detection(self) -> None:
        """Representative short TCP exchange yields a valid class label."""
        pipeline = IntrusionDetectionPipeline()
        forward = make_tcp_packet(
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=54321,
            dport=80,
            flags="S",
            payload=b"",
        )
        reverse = make_tcp_packet(
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=80,
            dport=54321,
            flags="SA",
            payload=b"",
        )
        ack = make_tcp_packet(
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=54321,
            dport=80,
            flags="A",
            payload=b"GET / HTTP/1.1\r\n",
        )
        for index, pkt in enumerate((forward, reverse, ack)):
            _stamp(pkt, float(index) * 0.05)

        results = pipeline.process_raw_packets([forward, reverse, ack], flush=True)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.flow.forward_packet_count, 2)
        self.assertEqual(result.flow.reverse_packet_count, 1)
        self.assertIn(result.predicted_class, CLASS_ORDER)
        self.assertTrue(math.isfinite(result.confidence))
        # Short interactive web-like flows are typically BENIGN for this model,
        # but any valid class label from the live booster is acceptable here.
        self.assertEqual(len(result.features), 24)

    def test_invalid_input_handling(self) -> None:
        pipeline = IntrusionDetectionPipeline()
        bad_inputs = [
            None,
            make_malformed_standin(),
            make_ethernet_only_packet(),  # no IPs → skipped by Module 3
            "not-a-packet",
            12345,
        ]
        for index, raw in enumerate(bad_inputs):
            if hasattr(raw, "time"):
                _stamp(raw, float(index))
            produced = pipeline.process_raw_packet(raw)
            self.assertEqual(produced, [])

        self.assertEqual(pipeline.flows_detected, 0)
        self.assertGreaterEqual(pipeline.packets_skipped, 1)
        # Flush with nothing active is safe.
        self.assertEqual(pipeline.flush(), [])

    def test_callback_and_lifecycle_cleanup(self) -> None:
        seen: list[str] = []

        def on_detection(result: PipelineResult) -> None:
            seen.append(result.predicted_class)

        pipeline = IntrusionDetectionPipeline(on_detection=on_detection)
        pkt = make_udp_packet()
        _stamp(pkt, 0.0)
        results = pipeline.process_raw_packets([pkt], flush=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(seen, [results[0].predicted_class])
        self.assertEqual(pipeline.results, tuple(results))

        pipeline.close()
        self.assertEqual(pipeline.active_flow_count, 0)

    def test_live_path_wires_capture_metadata_and_flushes(self) -> None:
        """Exercise run_live wiring without opening a real sniffer."""
        pipeline = IntrusionDetectionPipeline(interface=None)
        raw = make_tcp_packet(flags="S")
        _stamp(raw, 0.0)
        meta = parse_packet(raw)
        self.assertIsNotNone(meta)

        class _FakeCapture:
            def __init__(self, interface=None) -> None:
                self.interface = interface

            def capture_metadata(self, callback) -> None:
                callback(meta)

        with patch("pipeline.engine.PacketCaptureEngine", _FakeCapture):
            results = pipeline.run_live()

        self.assertEqual(len(results), 1)
        self.assertEqual(pipeline.active_flow_count, 0)
        self.assertTrue(isinstance(results[0].detection, DetectionResult))


class TestPipelineResultShape(unittest.TestCase):
    def test_as_dict_contains_detection_fields(self) -> None:
        pipeline = IntrusionDetectionPipeline()
        pkt = make_tcp_packet(flags="S")
        _stamp(pkt, 0.0)
        result = pipeline.process_raw_packets([pkt], flush=True)[0]
        payload = result.as_dict()
        self.assertEqual(payload["predicted_class"], result.predicted_class)
        self.assertIn("probabilities", payload)
        self.assertEqual(len(payload["probabilities"]), 5)


if __name__ == "__main__":
    unittest.main()
