"""Tests for the MLCN controlled traffic generator."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from traffic_generator.config import (
    BRUTE_FORCE_ATTEMPT_PREFIX,
    BRUTE_FORCE_ATTEMPTS_PER_SESSION,
    DDOS_REQUEST,
    DEFAULT_PROFILES_PATH,
    DOS_REQUEST_BYTES,
    LAB_PAGE_RESPONSE_BYTES,
    MAX_TEST_DURATION_SECONDS,
    PORT_SCAN_PROBE_TIMEOUT_SECONDS,
    PROFILE_NAMES,
)
from traffic_generator.lab_server import LabEchoServer
from traffic_generator.parameter_mapper import map_profile_to_parameters
from traffic_generator.profile_loader import (
    extract_reference_features,
    list_profile_names,
    load_profiles,
)
from traffic_generator.safety import (
    SafetyError,
    is_loopback_target,
    require_lab_confirmation,
    resolve_target_host,
    validate_test_limits,
)
from traffic_generator.traffic_generator import _build_dos_request, _line_session, build_generator
from traffic_generator.traffic_profile import TrafficParameters
import threading


class TestProfileLoader(unittest.TestCase):
    def test_load_default_profiles(self) -> None:
        doc = load_profiles()
        self.assertIn("attack_profiles", doc)
        self.assertIn("benign_baseline", doc)
        self.assertEqual(doc["schema"]["feature_count"], 24)

    def test_list_profile_names(self) -> None:
        names = list_profile_names()
        self.assertEqual(names[0], "BENIGN")
        for name in PROFILE_NAMES:
            self.assertIn(name, names)

    def test_extract_reference_features_for_each_profile(self) -> None:
        doc = load_profiles()
        for name in PROFILE_NAMES:
            refs = extract_reference_features(doc, name)
            self.assertIsInstance(refs, dict)
            self.assertGreater(len(refs), 0, msg=name)


class TestSafety(unittest.TestCase):
    def test_rejects_public_ip(self) -> None:
        with self.assertRaises(SafetyError):
            resolve_target_host("8.8.8.8")

    def test_accepts_private_ips(self) -> None:
        self.assertEqual(resolve_target_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(resolve_target_host("192.168.1.50"), "192.168.1.50")
        self.assertEqual(resolve_target_host("10.0.0.5"), "10.0.0.5")

    def test_localhost_is_loopback(self) -> None:
        self.assertTrue(is_loopback_target("localhost"))
        self.assertTrue(is_loopback_target("127.0.0.1"))

    def test_confirmation_required(self) -> None:
        with self.assertRaises(SafetyError):
            require_lab_confirmation(False, "LAB")
        with self.assertRaises(SafetyError):
            require_lab_confirmation(True, "NOPE")
        require_lab_confirmation(True, "LAB")

    def test_duration_cap(self) -> None:
        with self.assertRaises(SafetyError):
            validate_test_limits(
                duration_seconds=MAX_TEST_DURATION_SECONDS + 1,
                connection_rate=1.0,
            )


class TestParameterMapper(unittest.TestCase):
    def test_maps_all_profiles(self) -> None:
        doc = load_profiles()
        for name in PROFILE_NAMES:
            params = map_profile_to_parameters(
                name,
                target_host="127.0.0.1",
                duration_seconds=10.0,
                intensity=0.5,
                profiles_document=doc,
            )
            self.assertEqual(params.profile_name, name)
            self.assertGreater(params.duration_seconds, 0)
            self.assertGreater(params.connection_rate_per_sec, 0)
            self.assertIsNotNone(params.reference.reference_features)

    def test_port_scan_syn_only(self) -> None:
        params = map_profile_to_parameters(
            "Port Scan",
            target_host="192.168.0.10",
            intensity=0.5,
        )
        self.assertTrue(params.send_syn_only)
        self.assertFalse(params.use_http)
        self.assertLessEqual(
            params.port_scan_end - params.port_scan_start + 1,
            50,
        )

    def test_dos_idle_gap_above_threshold(self) -> None:
        params = map_profile_to_parameters(
            "DoS",
            target_host="127.0.0.1",
            intensity=0.5,
        )
        self.assertGreaterEqual(params.idle_gap_seconds, 5.0)

    def test_dos_produces_about_one_connection_per_second(self) -> None:
        for intensity, minimum in ((0.1, 0.8), (0.5, 0.9), (1.0, 1.1)):
            params = map_profile_to_parameters("DoS", target_host="127.0.0.1", intensity=intensity)
            burst = params.request_response_cycles * params.inter_message_delay_seconds
            rate = params.request_response_cycles / (burst + params.idle_gap_seconds)
            self.assertGreaterEqual(rate, minimum, msg=intensity)
            self.assertAlmostEqual(params.connection_rate_per_sec, rate)

    def test_intensity_scales_rates(self) -> None:
        doc = load_profiles()
        low = map_profile_to_parameters(
            "BENIGN",
            target_host="127.0.0.1",
            intensity=0.2,
            profiles_document=doc,
        )
        high = map_profile_to_parameters(
            "BENIGN",
            target_host="127.0.0.1",
            intensity=1.0,
            profiles_document=doc,
        )
        self.assertLessEqual(
            low.connection_rate_per_sec,
            high.connection_rate_per_sec,
        )


class TestTrafficGenerators(unittest.TestCase):
    def test_build_generator_for_each_profile(self) -> None:
        stop = threading.Event()
        for name in PROFILE_NAMES:
            params = map_profile_to_parameters(name, target_host="127.0.0.1", duration_seconds=0.1)
            gen = build_generator(params, stop)
            self.assertEqual(gen.params.profile_name, name)

    @patch("traffic_generator.traffic_generator._tcp_exchange")
    def test_benign_generator_counts_stats(self, mock_exchange) -> None:
        mock_exchange.return_value = (100, 2)
        stop = threading.Event()
        params = map_profile_to_parameters(
            "BENIGN",
            target_host="127.0.0.1",
            duration_seconds=0.15,
            intensity=0.5,
        )
        # Speed up delays for test
        params = TrafficParameters(
            **{
                **params.as_dict(),
                "inter_message_delay_seconds": 0.01,
                "forward_inter_delay_seconds": 0.01,
                "reference": params.reference,
            }
        )
        gen = build_generator(params, stop)
        stats = gen.run()
        self.assertGreater(stats.connections_attempted, 0)
        self.assertGreater(stats.packets_sent, 0)


class TestProfileWireShapes(unittest.TestCase):
    def _fast(self, name: str) -> TrafficParameters:
        params = map_profile_to_parameters(name, target_host="127.0.0.1", duration_seconds=0.1)
        return TrafficParameters(
            **{
                **params.as_dict(),
                "inter_message_delay_seconds": 0.01,
                "forward_inter_delay_seconds": 0.01,
                "idle_gap_seconds": 0.0,
                "reference": params.reference,
            }
        )

    @patch("traffic_generator.traffic_generator._line_session")
    def test_brute_force_uses_one_session_of_short_attempt_lines(self, mock_session) -> None:
        mock_session.return_value = (78, 12)
        build_generator(self._fast("Brute Force"), threading.Event()).run()
        lines = mock_session.call_args.args[2]
        self.assertEqual(len(lines), BRUTE_FORCE_ATTEMPTS_PER_SESSION)
        self.assertTrue(all(line.startswith(BRUTE_FORCE_ATTEMPT_PREFIX) and len(line) <= 16 for line in lines))

    @patch("traffic_generator.traffic_generator._tcp_exchange")
    def test_ddos_sends_tiny_page_request(self, mock_exchange) -> None:
        mock_exchange.return_value = (len(DDOS_REQUEST), 2)
        build_generator(self._fast("DDoS"), threading.Event()).run()
        self.assertEqual(mock_exchange.call_args.args[2], DDOS_REQUEST)

    @patch("traffic_generator.traffic_generator._tcp_exchange")
    def test_dos_sends_full_header_page_request(self, mock_exchange) -> None:
        stop = threading.Event()

        def exchange(*_args, **_kwargs):
            stop.set()  # skip the >5 s idle gap
            return DOS_REQUEST_BYTES, 2

        mock_exchange.side_effect = exchange
        build_generator(self._fast("DoS"), stop).run()
        request = mock_exchange.call_args.args[2]
        self.assertEqual(len(request), DOS_REQUEST_BYTES)
        self.assertTrue(request.startswith(b"GET /lab/dos/"))

    @patch("traffic_generator.traffic_generator._tcp_probe")
    def test_port_scan_probe_timeout_below_windows_syn_retry(self, mock_probe) -> None:
        build_generator(self._fast("Port Scan"), threading.Event()).run()
        self.assertTrue(mock_probe.called)
        self.assertLess(PORT_SCAN_PROBE_TIMEOUT_SECONDS, 0.5)


class TestLabEchoServerShapes(unittest.TestCase):
    def setUp(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.server = LabEchoServer(port=self.port)
        self.server.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

    def tearDown(self) -> None:
        self.server.stop()

    def _fetch(self, request: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=3.0) as sock:
            sock.sendall(request)
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
        return b"".join(chunks)

    def test_page_paths_return_lab_page(self) -> None:
        self.assertEqual(len(self._fetch(DDOS_REQUEST)), LAB_PAGE_RESPONSE_BYTES)
        dos = _build_dos_request("127.0.0.1", self.port, 1)
        self.assertEqual(len(self._fetch(dos)), LAB_PAGE_RESPONSE_BYTES)

    def test_brute_force_line_session_gets_one_deny_per_attempt(self) -> None:
        lines = [BRUTE_FORCE_ATTEMPT_PREFIX + b"%02d\r\n" % i for i in range(1, 4)]
        sent, packets = _line_session("127.0.0.1", self.port, lines, lambda: 0.0, time.sleep)
        self.assertEqual(sent, sum(len(line) for line in lines))
        self.assertEqual(packets, 2 * len(lines))


class TestControllerIntegration(unittest.TestCase):
    def test_controller_rejects_without_confirmation(self) -> None:
        from traffic_generator.controller import TrafficGeneratorController

        ctrl = TrafficGeneratorController(log_dir=Path(tempfile.mkdtemp()))
        with self.assertRaises(SafetyError):
            ctrl.start(
                profile_name="BENIGN",
                target="127.0.0.1",
                target_port=8080,
                duration_seconds=1.0,
                intensity=0.5,
                port_scan_start=8080,
                port_scan_end=8081,
                confirmed=False,
                confirmation_phrase="LAB",
            )

    @patch("traffic_generator.controller.require_two_machine_receiver")
    @patch("traffic_generator.traffic_generator._tcp_exchange")
    def test_controller_runs_short_test(self, mock_exchange, _mock_receiver_check) -> None:
        from traffic_generator.controller import TrafficGeneratorController

        mock_exchange.return_value = (50, 1)
        ctrl = TrafficGeneratorController(log_dir=Path(tempfile.mkdtemp()))
        ctrl.start(
            profile_name="BENIGN",
            target="127.0.0.1",
            target_port=8080,
            duration_seconds=0.2,
            intensity=0.5,
            port_scan_start=8080,
            port_scan_end=8081,
            confirmed=True,
            confirmation_phrase="LAB",
            enable_validation=False,
        )
        finished = ctrl.wait(timeout=5.0)
        self.assertTrue(finished)
        self.assertFalse(ctrl.running)
        self.assertIsNotNone(ctrl.last_log)
        self.assertEqual(ctrl.last_log.profile_name, "BENIGN")


class TestConnectivity(unittest.TestCase):
    def test_same_machine_target_rejected_for_two_machine(self) -> None:
        from traffic_generator.connectivity import require_two_machine_receiver

        with self.assertRaises(SafetyError) as ctx:
            require_two_machine_receiver(
                resolved_target="127.0.0.1",
                target_port=8080,
                profile_name="DDoS",
                use_http=True,
                enable_validation=False,
            )
        self.assertIn("Validation mode", str(ctx.exception))

    def test_recommended_receiver_command_includes_lab_port(self) -> None:
        from traffic_generator.connectivity import recommended_receiver_pipeline_command

        cmd = recommended_receiver_pipeline_command(port=8080)
        self.assertIn("--lab-port 8080", cmd)
        self.assertIn("8080", cmd)

    def test_validation_mode_skips_receiver_probe(self) -> None:
        from traffic_generator.connectivity import require_two_machine_receiver

        require_two_machine_receiver(
            resolved_target="127.0.0.1",
            target_port=8080,
            profile_name="DDoS",
            use_http=True,
            enable_validation=True,
        )

    @patch("traffic_generator.connectivity.probe_tcp_endpoint", return_value=(True, ""))
    def test_single_pc_mode_allows_same_machine_but_still_probes(self, mock_probe) -> None:
        from traffic_generator.connectivity import SINGLE_PC_ENV, require_two_machine_receiver

        with patch.dict(os.environ, {SINGLE_PC_ENV: "1"}):
            require_two_machine_receiver(
                resolved_target="127.0.0.1",
                target_port=8080,
                profile_name="DDoS",
                use_http=True,
                enable_validation=False,
            )
        mock_probe.assert_called_once_with("127.0.0.1", 8080)

    @patch("traffic_generator.connectivity.probe_tcp_endpoint", return_value=(False, "connection refused"))
    def test_unreachable_receiver_rejected(self, _mock_probe) -> None:
        from traffic_generator.connectivity import require_two_machine_receiver

        with patch(
            "traffic_generator.connectivity.is_same_machine_target",
            return_value=False,
        ):
            with self.assertRaises(SafetyError) as ctx:
                require_two_machine_receiver(
                    resolved_target="192.168.1.99",
                    target_port=8080,
                    profile_name="BENIGN",
                    use_http=True,
                    enable_validation=False,
                )
        self.assertIn("receiver_server", str(ctx.exception))


class TestProfilesFilePresent(unittest.TestCase):
    def test_default_profiles_path_exists(self) -> None:
        self.assertTrue(DEFAULT_PROFILES_PATH.is_file())
        doc = json.loads(DEFAULT_PROFILES_PATH.read_text(encoding="utf-8"))
        self.assertIn("important_note", doc)


if __name__ == "__main__":
    unittest.main()
