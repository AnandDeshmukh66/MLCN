"""``--validate`` report: attribution, verdicts and the genuine-model path (no Npcap)."""

from __future__ import annotations

import json
import socket
import tempfile
import unittest
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock, patch

from mlcn_launcher import launcher
from mlcn_launcher.processes import LaunchConfig
from mlcn_launcher.validation import (
    ProfileWindow,
    format_report,
    load_records,
    run_profiles,
    summarize,
)
from pipeline import IntrusionDetectionPipeline
from tests.lab_traffic_simulation import simulate_profile
from traffic_generator.config import PROFILE_NAMES
from traffic_generator.lab_server import LabEchoServer


def _record(start: float, flags: str | None, genuine: str) -> dict:
    return {"start_time": start, "first_packet_flags": flags, "genuine_predicted_class": genuine}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestSummarize(unittest.TestCase):
    def test_attributes_by_flow_start_and_counts_only_opening_flows(self) -> None:
        windows = [ProfileWindow("DDoS", 100.0, 110.0), ProfileWindow("DoS", 120.0, 130.0)]
        records = [
            _record(101.0, "S", "DDoS"),
            _record(102.0, "S", "DDoS"),
            _record(103.0, "FA", "BENIGN"),  # close-handshake tail: not an opening flow
            _record(121.0, "S", "DoS"),
            _record(122.0, "S", "BENIGN"),
            _record(115.0, "S", "BENIGN"),  # settle-time flush probe, outside both windows
        ]
        ddos, dos = summarize(windows, records)
        self.assertEqual((ddos.total_flows, ddos.opening_flows, ddos.real_matches), (3, 2, 2))
        self.assertEqual(ddos.verdict, "REAL ML")
        self.assertEqual((dos.opening_flows, dos.real_matches), (2, 1))
        self.assertEqual(dos.verdict, "FABRICATED DEMO RESULT")
        self.assertIn("genuine: BENIGN=1, DoS=1", format_report([ddos, dos]))

    def test_no_capture_is_fabricated_not_real(self) -> None:
        (summary,) = summarize([ProfileWindow("Port Scan", 0.0, 10.0)], [])
        self.assertEqual(summary.verdict, "FABRICATED DEMO RESULT")

    def test_load_records_skips_partial_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.jsonl"
            path.write_text(json.dumps(_record(1.0, "S", "DoS")) + "\n{broken\n", encoding="utf-8")
            self.assertEqual(len(load_records(path)), 1)
            self.assertEqual(load_records(Path(tmp) / "missing.jsonl"), [])


class TestGenuineModelThroughReport(unittest.TestCase):
    def test_every_simulated_profile_is_real_ml(self) -> None:
        for profile in PROFILE_NAMES:
            packets = simulate_profile(profile, duration=30.0)
            results = IntrusionDetectionPipeline(inactivity_timeout=5.0).process_raw_packets(packets, flush=True)
            # Round-trip through JSON exactly as the detections log stores records.
            records = [json.loads(json.dumps(r.as_dict(), default=str)) for r in results]
            window = ProfileWindow(profile, float(packets[0].time), float(packets[-1].time))
            summaries = summarize([window], records)
            self.assertEqual(summaries[0].verdict, "REAL ML", format_report(summaries))


class TestRunProfiles(unittest.TestCase):
    def test_generates_sequential_windows_against_lab_server(self) -> None:
        port = _free_port()
        server = LabEchoServer(host="127.0.0.1", port=port)
        server.start()
        try:
            windows = run_profiles(
                host="127.0.0.1",
                port=port,
                port_span=5,
                seconds=1.0,
                settle_seconds=0.0,
                profiles=("BENIGN", "Port Scan"),
                sink=lambda _line: None,
            )
        finally:
            server.stop()
        self.assertEqual([w.profile for w in windows], ["BENIGN", "Port Scan"])
        self.assertLessEqual(windows[0].ended_at, windows[1].started_at)
        self.assertTrue(all(w.ended_at - w.started_at >= 0.9 for w in windows))


class TestLauncherReport(unittest.TestCase):
    def test_exit_code_requires_every_profile_real(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = LaunchConfig(python="python", capture_interfaces=(), repo_root=Path(tmp))
            cfg.logs_dir.mkdir(parents=True)
            window = ProfileWindow("DoS", 0.0, 10.0)
            cfg.detections_log.write_text(json.dumps(_record(1.0, "S", "DoS")) + "\n", encoding="utf-8")
            self.assertEqual(launcher._report_validation(cfg, [window]), 0)
            cfg.detections_log.write_text(json.dumps(_record(1.0, "S", "BENIGN")) + "\n", encoding="utf-8")
            self.assertEqual(launcher._report_validation(cfg, [window]), 1)
            self.assertIn("FABRICATED DEMO RESULT", (cfg.logs_dir / "validation_report.txt").read_text(encoding="utf-8"))

    def test_validate_runs_genuine_receiver_without_streamlit(self) -> None:
        started: list[tuple[str, list[str]]] = []

        class FakeProcess:
            def __init__(self, name, command, **_kwargs) -> None:
                self.name, self.command, self.running = name, command, False

            def start(self) -> None:
                started.append((self.name, self.command))
                self.running = True

            def stop(self) -> None:
                self.running = False

        def fake_profiles(**kwargs) -> list[ProfileWindow]:
            self.assertEqual(kwargs["seconds"], 5.0)
            cfg_log.write_text(json.dumps(_record(1.0, "S", "BENIGN")) + "\n", encoding="utf-8")
            return [ProfileWindow("BENIGN", 0.0, 10.0)]

        with tempfile.TemporaryDirectory() as tmp:
            cfg_log = Path(tmp) / "logs" / "launcher" / "validation_detections.jsonl"
            args = launcher.build_parser().parse_args(["--validate", "--validate-seconds", "5"])
            with ExitStack() as stack:
                for name, value in (
                    ("_preflight", MagicMock(return_value=(r"\Device\NPF_Loopback",))),
                    ("LaunchConfig", partial(LaunchConfig, repo_root=Path(tmp))),
                    ("ManagedProcess", FakeProcess),
                    ("LabEchoServer", MagicMock()),
                    ("_wait_for_port", MagicMock(return_value=True)),
                    ("_install_break_handler", MagicMock()),
                    ("run_profiles", fake_profiles),
                ):
                    stack.enter_context(patch.object(launcher, name, value))
                stack.enter_context(patch.object(launcher.time, "sleep"))
                self.assertEqual(launcher.run(args), 0)
        self.assertEqual([name for name, _ in started], ["receiver"])
        receiver_command = started[0][1]
        self.assertNotIn("--demo-fallback", receiver_command)
        self.assertEqual(Path(receiver_command[receiver_command.index("--detections-log") + 1]), cfg_log)


if __name__ == "__main__":
    unittest.main()
