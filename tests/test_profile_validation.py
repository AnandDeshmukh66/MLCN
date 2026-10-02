"""
Profile chain check without Npcap: generator wire shape → flows → 24 features → real model.

Packets come from ``tests.lab_traffic_simulation`` (an approximation of Windows
loopback captures). The connection-opening flow of every profile must be
recognised by the genuine XGBoost model; the short close-handshake tail flows
are BENIGN and are what the demo fallback covers.
"""

from __future__ import annotations

import collections
import unittest

from pipeline import IntrusionDetectionPipeline
from tests.lab_traffic_simulation import simulate_profile
from traffic_generator.config import DDOS_REQUEST, DOS_REQUEST_BYTES, LAB_PAGE_RESPONSE_BYTES
from traffic_generator.lab_server import LAB_PAGE_RESPONSE
from traffic_generator.traffic_generator import _build_dos_request

MIN_MATCH_FRACTION = 0.9


def _opening_flow_predictions(profile: str, **kwargs) -> collections.Counter:
    pipeline = IntrusionDetectionPipeline(inactivity_timeout=5.0)
    results = pipeline.process_raw_packets(simulate_profile(profile, duration=30.0, **kwargs), flush=True)
    return collections.Counter(
        result.predicted_class
        for result in results
        if (result.flow.packets[0].tcp_flags or "") == "S"
    )


class TestGeneratedProfilesUseRealModel(unittest.TestCase):
    def _assert_recognised(self, profile: str, **kwargs) -> None:
        counts = _opening_flow_predictions(profile, **kwargs)
        total = sum(counts.values())
        self.assertGreater(total, 0, msg=profile)
        self.assertGreaterEqual(counts[profile] / total, MIN_MATCH_FRACTION, msg=f"{profile}: {dict(counts)}")

    def test_benign(self) -> None:
        self._assert_recognised("BENIGN")

    def test_port_scan(self) -> None:
        self._assert_recognised("Port Scan")

    def test_brute_force(self) -> None:
        self._assert_recognised("Brute Force")

    def test_ddos(self) -> None:
        self._assert_recognised("DDoS")
        self._assert_recognised("DDoS", response_segments=3)
        self._assert_recognised("DDoS", fin_with_data=True)

    def test_dos(self) -> None:
        self._assert_recognised("DoS")
        self._assert_recognised("DoS", response_segments=3)
        self._assert_recognised("DoS", fin_with_data=True)

    def test_port_scan_breaks_if_windows_retransmits_syn(self) -> None:
        # Why the probe timeout is shorter than the ~0.5 s Windows SYN retry.
        counts = _opening_flow_predictions("Port Scan", windows_syn_retries=1)
        self.assertLess(counts["Port Scan"] / sum(counts.values()), MIN_MATCH_FRACTION)


class TestLabWireShapes(unittest.TestCase):
    def test_lab_page_and_request_sizes(self) -> None:
        self.assertEqual(len(LAB_PAGE_RESPONSE), LAB_PAGE_RESPONSE_BYTES)
        self.assertTrue(LAB_PAGE_RESPONSE.startswith(b"HTTP/1.1 200 OK"))
        self.assertLessEqual(len(DDOS_REQUEST), 26)
        self.assertEqual(len(_build_dos_request("127.0.0.1", 8080, 3)), DOS_REQUEST_BYTES)


if __name__ == "__main__":
    unittest.main()
