"""Dashboard: receiver data adapter and the Streamlit app wired to the real controller."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from demo_fallback import DISCLAIMER, FABRICATED, REAL_ML, session_result
from demo_fallback.session import SESSION_FILE_ENV
from ml_detection import CLASS_ORDER, DetectionResult
from traffic_generator.dashboard_data import build_view, read_records, receiver_view

APP = str(Path(__file__).resolve().parents[1] / "traffic_generator" / "streamlit_app.py")


def _genuine(name: str) -> DetectionResult:
    probs = {c: 0.01 for c in CLASS_ORDER}
    probs[name] = 0.96
    return DetectionResult.from_probability_mapping(probs)


def _flow_record(at: float, name: str, demo: bool = False) -> dict:
    return {
        "recorded_at": at, "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
        "src_port": 50001, "dst_port": 8080, "packet_count": 7, "byte_count": 123, "duration": 0.5,
        "start_time": at, "first_packet_flags": "S", "predicted_class": name, "confidence": 0.9,
        "probabilities": {c: 0.1 for c in CLASS_ORDER}, "demo_fallback": demo,
        "result_source": FABRICATED if demo else REAL_ML,
    }


def _write(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


class TestReceiverData(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.log = self.dir / "detections.jsonl"

    def test_missing_log_is_empty_waiting_state(self) -> None:
        view = build_view(read_records(self.log))
        self.assertIsNone(view.primary)

    def test_since_filters_old_runs_and_partial_lines(self) -> None:
        _write(self.log, [_flow_record(10.0, "DoS"), _flow_record(100.0, "DDoS")])
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write("{partial")
        records = read_records(self.log, since=50.0)
        self.assertEqual([r["predicted_class"] for r in records], ["DDoS"])

    def test_verdict_takes_priority_and_flags_fabricated(self) -> None:
        verdict = session_result("Brute Force", [_genuine("BENIGN")] * 4).as_dict()
        verdict["recorded_at"] = 200.0
        view = build_view([_flow_record(100.0, "BENIGN", True), verdict])
        self.assertFalse(view.live)
        self.assertTrue(view.fabricated)
        self.assertEqual(view.primary["displayed_attack"], "Brute Force")
        self.assertEqual(view.primary["disclaimer"], DISCLAIMER)

    def test_real_verdict_not_fabricated_and_live_flow_before_verdict(self) -> None:
        verdict = session_result("DDoS", [_genuine("DDoS")] * 5).as_dict()
        verdict["recorded_at"] = 5.0
        self.assertFalse(build_view([verdict]).fabricated)
        live = build_view([_flow_record(1.0, "DoS"), _flow_record(2.0, "DDoS")])
        self.assertTrue(live.live)
        self.assertEqual(live.latest_flow["predicted_class"], "DDoS")

    def test_receiver_view_reads_log_beside_session_file(self) -> None:
        _write(self.log, [_flow_record(time.time(), "DoS")])
        with patch.dict(os.environ, {SESSION_FILE_ENV: str(self.dir / "demo_session.json")}):
            self.assertEqual(receiver_view(0.0).latest_flow["predicted_class"], "DoS")


class TestStreamlitApp(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.log = self.dir / "detections.jsonl"
        patcher = patch.dict(os.environ, {SESSION_FILE_ENV: str(self.dir / "demo_session.json")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _text(self, app: AppTest) -> str:
        return " ".join(m.value for m in app.markdown)

    def test_starts_in_waiting_state_with_all_profiles(self) -> None:
        app = AppTest.from_file(APP, default_timeout=30).run()
        self.assertFalse(app.exception)
        self.assertEqual(list(app.radio[0].options), ["BENIGN", "Brute Force", "DDoS", "DoS", "Port Scan"])
        self.assertIn("Awaiting attack", self._text(app))
        for name in app.radio[0].options:
            self.assertFalse(app.radio[0].set_value(name).run().exception)

    def test_launch_invokes_generator_and_shows_fabricated_result(self) -> None:
        with patch("traffic_generator.controller.TrafficGeneratorController.start") as start:
            app = AppTest.from_file(APP, default_timeout=30).run()
            app.radio[0].set_value("DDoS").run()
            app.button[0].click().run()
        self.assertEqual(start.call_args.kwargs["profile_name"], "DDoS")
        self.assertEqual(start.call_args.kwargs["target"], "127.0.0.1")
        run = app.session_state["run"]
        verdict = session_result("DDoS", []).as_dict()
        verdict["recorded_at"] = run["started"] + 1
        _write(self.log, [verdict])
        app.run()
        text = self._text(app)
        self.assertIn(FABRICATED, text)
        self.assertIn("Interpolated Values", text)
        for name in CLASS_ORDER:
            self.assertIn(name, text)

    def test_real_result_has_no_disclaimer_and_repeat_run_replaces_it(self) -> None:
        with patch("traffic_generator.controller.TrafficGeneratorController.start"):
            app = AppTest.from_file(APP, default_timeout=30).run()
            app.button[0].click().run()
        run = app.session_state["run"]
        real = session_result("BENIGN", [_genuine("BENIGN")] * 5).as_dict()
        real["recorded_at"] = run["started"]
        _write(self.log, [real])
        text = self._text(app.run())
        self.assertIn(REAL_ML, text)
        self.assertNotIn("Synthetic demo result", text)
        # Second run: older verdict is ignored until a new one is logged.
        time.sleep(1.2)  # beyond the clock-skew lookback window
        with patch("traffic_generator.controller.TrafficGeneratorController.start"):
            app.button[0].click().run()
            app.run()
        self.assertGreater(app.session_state["run"]["started"], run["started"])
        self.assertIn("waiting for the receiver", self._text(app))


if __name__ == "__main__":
    unittest.main()
