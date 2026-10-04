"""Real-vs-demo display decision, synthetic probabilities and the session handoff."""

from __future__ import annotations

import io
import os
import random
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from demo_fallback import (
    DISCLAIMER,
    FABRICATED,
    REAL_ML,
    Decision,
    DemoFallback,
    decide,
    finish_session,
    read_session,
    result_source,
    session_result,
    synthetic_detection,
    write_session,
)
from demo_fallback.fallback import (
    DEMO_FALLBACK_ENV,
    MAX_SYNTHETIC_CONFIDENCE,
    MIN_SYNTHETIC_CONFIDENCE,
    SESSION_SETTLE_SECONDS,
)
from pipeline import cli as pipeline_cli
from demo_fallback.session import SESSION_FILE_ENV
from feature_engineering import FeatureVector
from flow_builder import Flow, FlowKey
from ml_detection import CLASS_ORDER, DetectionResult
from pipeline import IntrusionDetectionPipeline, PipelineResult
from traffic_generator.controller import _demo_session_finish, _demo_session_start
from traffic_generator.parameter_mapper import map_profile_to_parameters


def _genuine(predicted: str) -> DetectionResult:
    probabilities = {name: 0.01 for name in CLASS_ORDER}
    probabilities[predicted] = 0.96
    return DetectionResult.from_probability_mapping(probabilities)


def _flow(*, port: int = 8080, at: float | None = None) -> Flow:
    start = datetime.fromtimestamp(time.time() if at is None else at, tz=timezone.utc)
    return Flow(
        key=FlowKey("127.0.0.1", "127.0.0.1", 50000, port, "TCP"),
        start_time=start,
        end_time=start,
        packet_count=2,
        byte_count=0,
        forward_packet_count=1,
        reverse_packet_count=1,
        forward_byte_count=0,
        reverse_byte_count=0,
        packets=(),
    )


def _result(predicted: str, **flow_kwargs) -> PipelineResult:
    return PipelineResult(flow=_flow(**flow_kwargs), features=FeatureVector.zeros(), detection=_genuine(predicted))


class TestDecision(unittest.TestCase):
    def test_real_when_no_selection_or_match(self) -> None:
        self.assertIs(decide(_genuine("DDoS"), None), Decision.REAL)
        self.assertIs(decide(_genuine("DDoS"), "DDoS"), Decision.REAL)

    def test_fallback_when_prediction_differs(self) -> None:
        self.assertIs(decide(_genuine("BENIGN"), "Brute Force"), Decision.DEMO_FALLBACK)


class TestSyntheticProbabilities(unittest.TestCase):
    def test_distribution_invariants(self) -> None:
        rng = random.Random(7)
        for _ in range(500):
            for selected in CLASS_ORDER:
                result = synthetic_detection(selected, rng)
                probs = result.probabilities
                self.assertEqual(set(probs), set(CLASS_ORDER))
                self.assertEqual(result.predicted_class, selected)
                self.assertEqual(sum(probs.values()), 1.0)
                self.assertTrue(all(0.0 <= p <= 1.0 for p in probs.values()))
                self.assertEqual(max(probs, key=probs.get), selected)
                self.assertGreaterEqual(result.confidence, MIN_SYNTHETIC_CONFIDENCE - 1e-6)
                self.assertLessEqual(result.confidence, MAX_SYNTHETIC_CONFIDENCE + 1e-6)

    def test_values_vary_between_runs(self) -> None:
        samples = {tuple(synthetic_detection("DoS").probability_vector()) for _ in range(20)}
        self.assertGreater(len(samples), 1)

    def test_unknown_profile_rejected(self) -> None:
        with self.assertRaises(ValueError):
            synthetic_detection("Not A Class")


class TestSessionFile(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "demo_session.json"

    def test_round_trip_and_finish(self) -> None:
        self.assertIsNone(read_session(self.path))
        write_session("Port Scan", 8080, 8099, path=self.path, now=100.0)
        session = read_session(self.path)
        self.assertEqual((session.profile, session.port_low, session.port_high), ("Port Scan", 8080, 8099))
        self.assertIsNone(session.ended_at)
        finish_session(path=self.path, now=130.0)
        self.assertEqual(read_session(self.path).ended_at, 130.0)

    def test_covers_time_window_and_ports(self) -> None:
        write_session("DoS", 8080, 8080, path=self.path, now=1000.0)
        finish_session(path=self.path, now=1030.0)
        session = read_session(self.path)
        self.assertTrue(session.covers(_flow(at=1010.0)))
        self.assertTrue(session.covers(_flow(at=1031.0)))  # within grace
        self.assertFalse(session.covers(_flow(at=1100.0)))
        self.assertFalse(session.covers(_flow(at=990.0)))
        self.assertFalse(session.covers(_flow(at=1010.0, port=443)))

    def test_corrupt_file_reads_as_none(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        self.assertIsNone(read_session(self.path))


class TestDemoFallbackTransform(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "demo_session.json"

    def test_no_session_shows_genuine(self) -> None:
        result = _result("BENIGN")
        self.assertIs(DemoFallback(self.path)(result), result)

    def test_matching_prediction_shows_genuine(self) -> None:
        write_session("DDoS", 8080, 8080, path=self.path)
        result = _result("DDoS")
        self.assertIs(DemoFallback(self.path)(result), result)

    def test_mismatch_shows_selected_and_keeps_genuine(self) -> None:
        write_session("Brute Force", 8080, 8080, path=self.path)
        result = _result("BENIGN")
        shown = DemoFallback(self.path)(result)
        self.assertTrue(shown.demo_fallback)
        self.assertEqual(shown.predicted_class, "Brute Force")
        self.assertIs(shown.genuine_detection, result.detection)
        self.assertEqual(shown.model_detection.predicted_class, "BENIGN")
        payload = shown.as_dict()
        self.assertTrue(payload["demo_fallback"])
        self.assertEqual(payload["genuine_predicted_class"], "BENIGN")

    def test_flows_outside_session_are_untouched(self) -> None:
        write_session("DoS", 8080, 8080, path=self.path)
        other_port = _result("BENIGN", port=443)
        self.assertIs(DemoFallback(self.path)(other_port), other_port)

    def test_pipeline_results_stay_genuine(self) -> None:
        write_session("Brute Force", 8080, 8080, path=self.path)
        shown: list[PipelineResult] = []
        pipeline = IntrusionDetectionPipeline(
            on_detection=shown.append,
            lab_port=8080,
            display_transform=DemoFallback(self.path),
        )
        genuine = _result("BENIGN")
        pipeline._results.append(genuine)
        pipeline._emit(genuine)
        self.assertEqual(shown[0].predicted_class, "Brute Force")
        self.assertEqual(pipeline.results[0].predicted_class, "BENIGN")

    def test_failing_transform_falls_back_to_genuine(self) -> None:
        shown: list[PipelineResult] = []

        def broken(_result: PipelineResult) -> PipelineResult:
            raise RuntimeError("boom")

        pipeline = IntrusionDetectionPipeline(on_detection=shown.append, display_transform=broken)
        genuine = _result("BENIGN")
        pipeline._emit(genuine)
        self.assertIs(shown[0], genuine)


class TestSessionResult(unittest.TestCase):
    """The receiver's final per-session display: REAL ML or the fabricated selected attack."""

    def test_reliable_genuine_prediction_is_real_ml(self) -> None:
        verdict = session_result("DDoS", [_genuine("DDoS")] * 10)
        self.assertEqual(verdict.source, REAL_ML)
        self.assertEqual(verdict.detection.predicted_class, "DDoS")
        self.assertAlmostEqual(verdict.detection.confidence, _genuine("DDoS").confidence)
        self.assertIsNone(verdict.disclaimer)
        self.assertNotIn("disclaimer", verdict.as_dict())

    def test_unreliable_or_wrong_prediction_is_fabricated_selected(self) -> None:
        for genuine in ([_genuine("BENIGN")] * 10, [_genuine("DDoS")] * 8 + [_genuine("BENIGN")] * 2):
            verdict = session_result("DDoS", genuine)
            self.assertEqual(verdict.source, FABRICATED)
            self.assertEqual(verdict.detection.predicted_class, "DDoS")
            self.assertIsNotNone(verdict.genuine_detection)  # kept for debugging

    def test_no_flows_is_fabricated_selected(self) -> None:
        verdict = session_result("Port Scan", [])
        self.assertEqual((verdict.source, verdict.detection.predicted_class), (FABRICATED, "Port Scan"))

    def test_failure_is_fabricated_selected(self) -> None:
        verdict = session_result("Brute Force", [None])  # type: ignore[list-item]
        self.assertEqual((verdict.source, verdict.detection.predicted_class), (FABRICATED, "Brute Force"))

    def test_fabricated_values_vary_and_always_carry_disclaimer(self) -> None:
        verdicts = [session_result(name, []) for name in CLASS_ORDER for _ in range(10)]
        for verdict in verdicts:
            probs = verdict.detection.probabilities
            self.assertEqual(sum(probs.values()), 1.0)
            self.assertEqual(max(probs, key=probs.get), verdict.selected)
            self.assertEqual(verdict.disclaimer, DISCLAIMER)
            self.assertEqual(verdict.as_dict()["disclaimer"], DISCLAIMER)
        self.assertGreater(len({v.detection.probability_vector() for v in verdicts if v.selected == "DoS"}), 1)

    def test_per_flow_fabricated_result_carries_disclaimer(self) -> None:
        path = Path(tempfile.mkdtemp()) / "demo_session.json"
        write_session("DoS", 8080, 8080, path=path)
        shown = DemoFallback(path)(_result("BENIGN"))
        self.assertEqual(result_source(shown), {"result_source": FABRICATED, "disclaimer": DISCLAIMER})
        self.assertEqual(result_source(_result("BENIGN")), {"result_source": REAL_ML})

    def test_printed_fabricated_result_shows_selected_and_disclaimer(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            pipeline_cli._print_session_result(session_result("DDoS", [_genuine("BENIGN")] * 5))
        text = out.getvalue()
        self.assertIn("RESULT: DDoS | FABRICATED DEMO RESULT", text)
        self.assertIn(DISCLAIMER, text)
        self.assertNotIn("BENIGN=0.9", text)  # wrong genuine attack is not shown to the user


class TestSessionPoll(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "demo_session.json"
        self.fallback = DemoFallback(self.path)
        self.start = time.time()

    def _finish(self) -> float:
        end = self.start + 30.0
        finish_session(path=self.path, now=end)
        return end

    def test_reliable_session_reports_real_ml_once(self) -> None:
        write_session("DDoS", 8080, 8080, path=self.path, now=self.start)
        for _ in range(10):
            self.fallback(_result("DDoS", at=self.start + 1))
        self.assertIsNone(self.fallback.poll(now=self.start + 5))  # attacker still running
        end = self._finish()
        verdict = self.fallback.poll(now=end + SESSION_SETTLE_SECONDS + 0.1)
        self.assertEqual((verdict.source, verdict.relevant_flows), (REAL_ML, 10))
        self.assertIsNone(self.fallback.poll(now=end + 60))

    def test_session_without_flows_reports_fabricated_selected(self) -> None:
        write_session("Port Scan", 8080, 8099, path=self.path, now=self.start)
        end = self._finish()
        verdict = self.fallback.poll(now=end + SESSION_SETTLE_SECONDS + 0.1)
        self.assertEqual((verdict.source, verdict.detection.predicted_class), (FABRICATED, "Port Scan"))

    def test_receiver_shutdown_reports_unfinished_session(self) -> None:
        write_session("DoS", 8080, 8080, path=self.path, now=self.start)
        verdict = self.fallback.poll(now=self.start + 1, final=True)
        self.assertEqual(verdict.detection.predicted_class, "DoS")


class TestControllerHooks(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp()) / "demo_session.json"
        self.params = map_profile_to_parameters("Port Scan", target_host="127.0.0.1", duration_seconds=5.0)

    def test_hooks_write_session_when_enabled(self) -> None:
        env = {DEMO_FALLBACK_ENV: "1", SESSION_FILE_ENV: str(self.path)}
        with patch.dict(os.environ, env):
            _demo_session_start(self.params)
            session = read_session(self.path)
            self.assertEqual(session.profile, "Port Scan")
            self.assertEqual(session.port_low, min(self.params.target_port, self.params.port_scan_start))
            self.assertEqual(session.port_high, max(self.params.target_port, self.params.port_scan_end))
            _demo_session_finish()
            self.assertIsNotNone(read_session(self.path).ended_at)

    def test_hooks_noop_when_disabled(self) -> None:
        env = {DEMO_FALLBACK_ENV: "0", SESSION_FILE_ENV: str(self.path)}
        with patch.dict(os.environ, env):
            _demo_session_start(self.params)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
