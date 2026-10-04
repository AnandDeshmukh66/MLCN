"""Launcher: interface selection, process commands/config and preflight flow (no real Npcap)."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from demo_fallback.fallback import DEMO_FALLBACK_ENV
from demo_fallback.session import SESSION_FILE_ENV
from mlcn_launcher import launcher
from mlcn_launcher.preflight import (
    LOOPBACK_DEVICE,
    LauncherError,
    NpcapStatus,
    needs_elevation,
    npcap_status,
    select_capture_interfaces,
)
from mlcn_launcher.processes import (
    LaunchConfig,
    ManagedProcess,
    child_environment,
    pipeline_command,
    streamlit_command,
)
from packet_capture.interfaces import NetworkInterface
from traffic_generator.connectivity import SINGLE_PC_ENV

# Arbitrary GUIDs: selection must work from addresses, never from a known GUID.
WIFI = r"\Device\NPF_{0D1C2B3A-4F5E-6071-8293-A4B5C6D7E8F9}"
ETHERNET = r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"
VPN = r"\Device\NPF_{ABCDEF01-2345-6789-ABCD-EF0123456789}"


def _interfaces() -> list[NetworkInterface]:
    return [
        NetworkInterface(name=ETHERNET, address="10.20.30.40"),
        NetworkInterface(name=VPN, address="0.0.0.0"),
        NetworkInterface(name=WIFI, address="192.168.1.23"),
        NetworkInterface(name=LOOPBACK_DEVICE, address="127.0.0.1"),
    ]


class TestInterfaceSelection(unittest.TestCase):
    def test_maps_local_ip_to_npcap_device_plus_loopback(self) -> None:
        selection = select_capture_interfaces(_interfaces(), "192.168.1.23")
        self.assertEqual(selection.interfaces, (WIFI, LOOPBACK_DEVICE))
        self.assertEqual(selection.as_argument(), f"{WIFI},{LOOPBACK_DEVICE}")
        self.assertEqual(selection.warnings, ())

    def test_follows_address_not_guid(self) -> None:
        selection = select_capture_interfaces(_interfaces(), "10.20.30.40")
        self.assertEqual(selection.lan_interface, ETHERNET)

    def test_unmatched_ip_captures_loopback_with_warning(self) -> None:
        selection = select_capture_interfaces(_interfaces(), "172.16.0.9")
        self.assertEqual(selection.interfaces, (LOOPBACK_DEVICE,))
        self.assertTrue(selection.warnings)

    def test_no_local_ip_captures_loopback_with_warning(self) -> None:
        selection = select_capture_interfaces(_interfaces(), None)
        self.assertEqual(selection.interfaces, (LOOPBACK_DEVICE,))
        self.assertTrue(selection.warnings)

    def test_missing_loopback_is_an_error(self) -> None:
        without_loopback = [iface for iface in _interfaces() if iface.name != LOOPBACK_DEVICE]
        with self.assertRaises(LauncherError) as ctx:
            select_capture_interfaces(without_loopback, "192.168.1.23")
        self.assertIn("NPF_Loopback", str(ctx.exception))


class TestNpcapChecks(unittest.TestCase):
    def test_detects_wpcap_dll_under_system_root(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.assertFalse(npcap_status(root).installed)
        dll = root / "System32" / "Npcap" / "wpcap.dll"
        dll.parent.mkdir(parents=True)
        dll.write_bytes(b"")
        self.assertEqual(npcap_status(root).dll_path, dll)

    def test_elevation_policy(self) -> None:
        def status(admin_only: bool | None) -> NpcapStatus:
            return NpcapStatus(Path("wpcap.dll"), admin_only, True)

        self.assertFalse(needs_elevation(status(True), admin=True))
        self.assertTrue(needs_elevation(status(True), admin=False))
        self.assertTrue(needs_elevation(status(None), admin=False))
        self.assertFalse(needs_elevation(status(False), admin=False))


class TestProcessCommands(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = LaunchConfig(
            python=r"C:\Program Files\Python312\python.exe",
            capture_interfaces=(WIFI, LOOPBACK_DEVICE),
            repo_root=Path(r"C:\MLCN"),
        )

    def test_pipeline_command(self) -> None:
        command = pipeline_command(self.cfg)
        self.assertEqual(command[:4], [self.cfg.python, "-u", "-m", "pipeline"])
        self.assertEqual(command[command.index("-i") + 1], f"{WIFI},{LOOPBACK_DEVICE}")
        self.assertEqual(command[command.index("--lab-port") + 1], "8080")
        self.assertEqual(command[command.index("--lab-port-span") + 1], "50")
        self.assertIn("--demo-fallback", command)
        self.assertIn("--detections-log", command)

    def test_pipeline_command_without_demo_fallback(self) -> None:
        cfg = LaunchConfig(python="python", capture_interfaces=(LOOPBACK_DEVICE,), demo_fallback=False)
        self.assertNotIn("--demo-fallback", pipeline_command(cfg))

    def test_windows_command_line_quoting(self) -> None:
        line = subprocess.list2cmdline(pipeline_command(self.cfg))
        self.assertTrue(line.startswith(f'"{self.cfg.python}" -u -m pipeline'))
        self.assertIn(f" {WIFI},{LOOPBACK_DEVICE} ", line)

    def test_streamlit_command(self) -> None:
        command = streamlit_command(self.cfg)
        self.assertEqual(command[1:4], ["-m", "streamlit", "run"])
        self.assertEqual(Path(command[4]), Path("traffic_generator") / "streamlit_app.py")
        self.assertEqual(command[command.index("--server.port") + 1], "8501")
        self.assertEqual(command[command.index("--server.headless") + 1], "true")

    def test_child_environment(self) -> None:
        env = child_environment(self.cfg, base={"PATH": "x"})
        self.assertEqual(env["PATH"], "x")
        self.assertEqual(env[SINGLE_PC_ENV], "1")
        self.assertEqual(env[DEMO_FALLBACK_ENV], "1")
        self.assertEqual(env[SESSION_FILE_ENV], str(self.cfg.demo_session_file))
        self.assertEqual(env["PYTHONUTF8"], "1")


class TestManagedProcess(unittest.TestCase):
    def test_streams_prefixed_output_and_stops(self) -> None:
        lines: list[str] = []
        child = ManagedProcess(
            "demo",
            [sys.executable, "-u", "-c", "import time; print('ready', flush=True); time.sleep(60)"],
            cwd=Path.cwd(),
            env=child_environment(LaunchConfig(python=sys.executable, capture_interfaces=())),
            sink=lines.append,
        )
        child.start()
        deadline = time.monotonic() + 10.0
        while not lines and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(lines[:1], ["[demo] ready"])
        child.stop(timeout=5.0)
        self.assertFalse(child.running)


class TestLauncherFlow(unittest.TestCase):
    def _args(self, *extra: str) -> argparse.Namespace:
        return launcher.build_parser().parse_args(list(extra))

    def test_non_windows_is_rejected(self) -> None:
        with patch.object(launcher, "is_windows", return_value=False):
            self.assertEqual(launcher.run(self._args("--check")), 1)

    def test_check_passes_with_npcap_and_loopback(self) -> None:
        with (
            patch.object(launcher, "is_windows", return_value=True),
            patch.object(launcher, "windows_version", return_value="10.0.22631"),
            patch.object(launcher, "is_admin", return_value=True),
            patch.object(launcher, "npcap_status", return_value=NpcapStatus(Path("wpcap.dll"), True, True)),
            patch.object(launcher, "detect_local_ipv4", return_value="192.168.1.23"),
            patch.object(launcher, "list_interfaces", return_value=_interfaces()),
            patch.object(launcher, "port_available", return_value=True),
        ):
            self.assertEqual(launcher._preflight(self._args()), (WIFI, LOOPBACK_DEVICE))
            self.assertEqual(launcher.run(self._args("--check")), 0)

    def test_missing_npcap_fails(self) -> None:
        with (
            patch.object(launcher, "is_windows", return_value=True),
            patch.object(launcher, "windows_version", return_value="10"),
            patch.object(launcher, "is_admin", return_value=True),
            patch.object(launcher, "npcap_status", return_value=NpcapStatus(None, None, None)),
        ):
            self.assertEqual(launcher.run(self._args("--check")), 1)

    def test_requests_uac_when_npcap_is_admin_only(self) -> None:
        with (
            patch.object(launcher, "is_windows", return_value=True),
            patch.object(launcher, "windows_version", return_value="10"),
            patch.object(launcher, "is_admin", return_value=False),
            patch.object(launcher, "npcap_status", return_value=NpcapStatus(Path("wpcap.dll"), True, True)),
            patch.object(launcher, "relaunch_elevated", return_value=True) as relaunch,
        ):
            self.assertEqual(launcher.run(self._args()), 0)
        relaunch.assert_called_once()

    def test_elevated_arguments_are_cwd_independent(self) -> None:
        arguments = launcher.elevated_arguments(["--port", "8080"])
        self.assertEqual(arguments[0], "-c")
        compile(arguments[1], "<elevated>", "exec")
        self.assertIn(repr(str(launcher.REPO_ROOT)), arguments[1])
        self.assertIn("--pause-on-exit", arguments[1])


if __name__ == "__main__":
    unittest.main()
