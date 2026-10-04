"""Windows + Npcap preflight checks and capture-interface selection."""

from __future__ import annotations

import ctypes
import os
import platform
import socket
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from packet_capture.interfaces import NetworkInterface

try:
    import winreg
except ImportError:  # development hosts (macOS/Linux) have no registry
    winreg = None

NPCAP_PARAMETERS_KEY = r"SYSTEM\CurrentControlSet\Services\npcap\Parameters"
LOOPBACK_DEVICE = r"\Device\NPF_Loopback"
NPCAP_DEVICE_PREFIX = "\\Device\\NPF_"


class LauncherError(RuntimeError):
    """Preflight/startup failure with a short, user-facing message."""


@dataclass(frozen=True)
class NpcapStatus:
    dll_path: Path | None
    admin_only: bool | None
    loopback_support: bool | None

    @property
    def installed(self) -> bool:
        return self.dll_path is not None

    def describe(self) -> str:
        def flag(value: bool | None) -> str:
            return "unknown" if value is None else ("yes" if value else "no")

        return (
            f"{self.dll_path} (admin-only: {flag(self.admin_only)}, "
            f"loopback support: {flag(self.loopback_support)})"
        )


@dataclass(frozen=True)
class CaptureSelection:
    lan_interface: str | None
    loopback_interface: str
    warnings: tuple[str, ...] = ()

    @property
    def interfaces(self) -> tuple[str, ...]:
        if self.lan_interface:
            return (self.lan_interface, self.loopback_interface)
        return (self.loopback_interface,)

    def as_argument(self) -> str:
        """Value for ``python -m pipeline -i`` (comma-separated)."""
        return ",".join(self.interfaces)


def is_windows() -> bool:
    return sys.platform == "win32"


def windows_version() -> str:
    return platform.version() or platform.release()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _read_npcap_flag(name: str) -> bool | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NPCAP_PARAMETERS_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, name)
        return bool(int(value))
    except (OSError, ValueError, TypeError):
        return None


def npcap_status(system_root: str | Path | None = None) -> NpcapStatus:
    root = Path(system_root or os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = (root / "System32" / "Npcap" / "wpcap.dll", root / "SysWOW64" / "Npcap" / "wpcap.dll")
    dll = next((path for path in candidates if path.is_file()), None)
    return NpcapStatus(
        dll_path=dll,
        admin_only=_read_npcap_flag("AdminOnly"),
        loopback_support=_read_npcap_flag("LoopbackSupport"),
    )


def needs_elevation(status: NpcapStatus, admin: bool) -> bool:
    """Elevate unless Npcap is known to allow non-admin capture."""
    return not admin and status.admin_only is not False


def relaunch_elevated(arguments: Sequence[str], cwd: str | Path) -> bool:
    """Re-run ``python <arguments>`` through the UAC prompt; True if it was launched."""
    params = subprocess.list2cmdline(list(arguments))
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(cwd), 1)
    return int(result) > 32


def detect_local_ipv4() -> str | None:
    """Primary LAN IPv4 (the route to the Internet); no packets are sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1
            address = sock.getsockname()[0]
    except OSError:
        return None
    if not address or address.startswith(("127.", "0.")):
        return None
    return address


def _is_loopback_device(name: str) -> bool:
    return name.lower().endswith("npf_loopback")


def select_capture_interfaces(
    interfaces: Sequence[NetworkInterface],
    local_ip: str | None,
) -> CaptureSelection:
    """
    Pick the Npcap device that owns ``local_ip`` plus ``\\Device\\NPF_Loopback``.

    Same-PC lab traffic is carried by the loopback device (also when the target
    is the local LAN IP), so loopback is mandatory and the LAN device optional.
    """
    loopback = next((iface.name for iface in interfaces if _is_loopback_device(iface.name)), None)
    if loopback is None:
        raise LauncherError(
            f"Npcap loopback adapter {LOOPBACK_DEVICE} not found. Reinstall Npcap with "
            "'Support loopback traffic' enabled."
        )

    if local_ip is None:
        return CaptureSelection(None, loopback, ("No LAN IPv4 detected; capturing loopback only.",))

    matches = [
        iface.name
        for iface in interfaces
        if iface.address == local_ip and not _is_loopback_device(iface.name)
    ]
    matches.sort(key=lambda name: not name.startswith(NPCAP_DEVICE_PREFIX))
    if not matches:
        return CaptureSelection(
            None,
            loopback,
            (f"No Npcap interface owns {local_ip}; capturing loopback only.",),
        )
    return CaptureSelection(matches[0], loopback)


def port_available(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True
