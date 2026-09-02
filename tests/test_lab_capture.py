"""Tests for capture interface resolution and lab-port pipeline filtering."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from flow_builder import Flow, FlowKey
from ml_detection import DetectionResult
from packet_capture.interfaces import resolve_interfaces
from pipeline.engine import IntrusionDetectionPipeline, _flow_involves_port
from pipeline.models import PipelineResult


def _flow(dst_port: int) -> Flow:
    now = datetime.fromtimestamp(1_700_000_000.0, tz=timezone.utc)
    return Flow(
        key=FlowKey(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=50000,
            dst_port=dst_port,
            protocol="TCP",
        ),
        start_time=now,
        end_time=now,
        packet_count=2,
        byte_count=200,
        forward_packet_count=1,
        reverse_packet_count=1,
        forward_byte_count=100,
        reverse_byte_count=100,
        packets=(),
    )


def _detection() -> DetectionResult:
    probs = {
        "BENIGN": 0.9,
        "Brute Force": 0.02,
        "DDoS": 0.02,
        "DoS": 0.02,
        "Port Scan": 0.04,
    }
    return DetectionResult.from_probability_mapping(probs)


class TestResolveInterfaces(unittest.TestCase):
    @patch("packet_capture.interfaces.list_interfaces")
    def test_comma_separated_interfaces(self, mock_list) -> None:
        from packet_capture.interfaces import NetworkInterface

        mock_list.return_value = [
            NetworkInterface(name="Wi-Fi", address="192.168.1.33"),
            NetworkInterface(name=r"\Device\NPF_Loopback", address="127.0.0.1"),
        ]
        resolved = resolve_interfaces(r"Wi-Fi,\Device\NPF_Loopback")
        self.assertEqual(resolved, ["Wi-Fi", r"\Device\NPF_Loopback"])


class TestLabPortFilter(unittest.TestCase):
    def test_flow_involves_port(self) -> None:
        self.assertTrue(_flow_involves_port(_flow(8080), 8080))
        self.assertFalse(_flow_involves_port(_flow(8080), 443))

    def test_emit_skips_non_lab_flows(self) -> None:
        emitted: list[PipelineResult] = []
        pipeline = IntrusionDetectionPipeline(lab_port=8080, on_detection=emitted.append)
        pipeline._emit(
            PipelineResult(flow=_flow(443), features={}, detection=_detection())
        )
        pipeline._emit(
            PipelineResult(flow=_flow(8080), features={}, detection=_detection())
        )
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0].flow.dst_port, 8080)


if __name__ == "__main__":
    unittest.main()
