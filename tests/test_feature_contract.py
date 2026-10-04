"""Live feature vectors must follow the model's 24-feature schema and CIC units."""

from __future__ import annotations

import json
import math
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from feature_engineering import FEATURE_ORDER, FeatureEngineeringEngine
from feature_engineering.contract import (
    FEATURE_SPECS,
    FEATURE_UNITS,
    INTEGER_FEATURES,
    MICROSECONDS_PER_SECOND,
    TIME_FEATURES,
)
from flow_builder import FlowBuilder
from ml_detection import MLDetectionEngine
from packet_parsing import parse_packet
from tests.test_ml_detection import _CLASS_SAMPLES

MODEL_FEATURES_PATH = Path(__file__).resolve().parents[1] / "models" / "xgboost_ids_features.json"
BASE = 1_700_000_000.0
_SYN_OPTIONS = [("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]


def _tcp(src: str, dst: str, sport: int, dport: int, flags: str, at: float, payload: bytes = b""):
    options = _SYN_OPTIONS if flags == "S" else []
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, options=options)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = BASE + at
    return pkt


def _flows(packets):
    builder = FlowBuilder(inactivity_timeout=60.0, max_duration=120.0, terminate_on_fin=True)
    completed = []
    for raw in packets:
        completed.extend(builder.add_packet(parse_packet(raw)))
    return completed + builder.flush()


class TestSchema(unittest.TestCase):
    def test_feature_order_matches_trained_model(self) -> None:
        trained = json.loads(MODEL_FEATURES_PATH.read_text(encoding="utf-8"))["features"]
        self.assertEqual(list(FEATURE_ORDER), trained)
        self.assertEqual([spec.name for spec in FEATURE_SPECS], trained)

    def test_time_features_are_microseconds_and_rates_per_second(self) -> None:
        expected_time = {
            "Flow Duration",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Fwd IAT Mean",
            "Bwd IAT Mean",
            "Active Mean",
            "Idle Mean",
        }
        self.assertEqual(set(TIME_FEATURES), expected_time)
        for name in expected_time:
            self.assertEqual(FEATURE_UNITS[name], "microseconds", msg=name)
        self.assertEqual(FEATURE_UNITS["Flow Bytes/s"], "payload bytes per second")
        self.assertEqual(FEATURE_UNITS["Flow Packets/s"], "packets per second")
        self.assertIn("Flow Duration", INTEGER_FEATURES)


class TestLiveVectorUnits(unittest.TestCase):
    def test_flow_duration_is_microseconds_not_seconds(self) -> None:
        packets = [
            _tcp("10.0.0.1", "10.0.0.2", 50000, 8080, "S", 0.0),
            _tcp("10.0.0.2", "10.0.0.1", 8080, 50000, "SA", 0.5),
            _tcp("10.0.0.1", "10.0.0.2", 50000, 8080, "A", 1.5),
        ]
        (flow,) = _flows(packets)
        values = FeatureEngineeringEngine().extract(flow).as_dict()
        self.assertEqual(values["Flow Duration"], 1.5 * MICROSECONDS_PER_SECOND)
        self.assertAlmostEqual(values["Flow IAT Mean"], 750_000.0)
        self.assertAlmostEqual(values["Flow Packets/s"], 3 / 1.5)
        for name in FEATURE_ORDER:
            self.assertTrue(math.isfinite(values[name]), msg=name)

    def test_reproduces_cic_port_scan_row(self) -> None:
        """SYN → RST/ACK 66 µs later equals a real CIC-IDS2017 PortScan training row."""
        packets = [
            _tcp("10.0.0.1", "10.0.0.2", 40000, 8081, "S", 0.0),
            _tcp("10.0.0.2", "10.0.0.1", 8081, 40000, "RA", 0.000066),
        ]
        (flow,) = _flows(packets)
        live = FeatureEngineeringEngine().extract(flow).as_list()
        reference = _CLASS_SAMPLES["Port Scan"]
        for name, got, want in zip(FEATURE_ORDER, live, reference):
            self.assertTrue(math.isclose(got, want, rel_tol=1e-6, abs_tol=1e-6), msg=f"{name}: {got} != {want}")
        self.assertEqual(MLDetectionEngine().predict(FeatureEngineeringEngine().extract(flow)).predicted_class, "Port Scan")


class TestPayloadLengths(unittest.TestCase):
    def test_parser_reports_cic_payload_bytes(self) -> None:
        rst_ack = parse_packet(_tcp("10.0.0.2", "10.0.0.1", 80, 40000, "RA", 0.0))
        syn = parse_packet(_tcp("10.0.0.1", "10.0.0.2", 40000, 80, "S", 0.0))
        data = parse_packet(_tcp("10.0.0.1", "10.0.0.2", 40000, 80, "PA", 0.0, b"x" * 100))
        # Bare 40-byte segments carry 6 bytes of Ethernet padding in CIC captures.
        self.assertEqual(rst_ack.payload_length, 6)
        self.assertEqual(syn.payload_length, 0)
        self.assertEqual(data.payload_length, 100)


if __name__ == "__main__":
    unittest.main()
