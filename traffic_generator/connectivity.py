"""Pre-flight checks for two-machine laboratory traffic tests."""

from __future__ import annotations

import socket
import sys

from traffic_generator.safety import SafetyError


def local_ip_addresses() -> set[str]:
    """Best-effort set of this host's private/local IPv4 addresses."""
    addrs = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1; no packets leave the host
            addrs.add(sock.getsockname()[0])
    except OSError:
        pass
    return addrs


def is_same_machine_target(resolved_ip: str) -> bool:
    """True when the target IP belongs to this machine (not a remote Laptop B)."""
    if resolved_ip in {"127.0.0.1", "::1"}:
        return True
    return resolved_ip in local_ip_addresses()


def probe_tcp_endpoint(host: str, port: int, *, timeout: float = 3.0) -> tuple[bool, str]:
    """
    Attempt a TCP connect to ``host:port``.

    Returns ``(True, "")`` on success or ``(False, reason)`` on failure.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except ConnectionRefusedError:
        return False, f"connection refused on {host}:{port} (no listener / firewall)"
    except TimeoutError:
        return False, f"timed out connecting to {host}:{port} (firewall or wrong IP)"
    except OSError as exc:
        return False, f"cannot reach {host}:{port}: {exc}"


def require_two_machine_receiver(
    *,
    resolved_target: str,
    target_port: int,
    profile_name: str,
    use_http: bool,
    enable_validation: bool,
) -> None:
    """
    Validate that a remote two-machine test can actually deliver traffic.

    Validation mode has its own loopback echo server — this check is skipped there.
    """
    if enable_validation:
        return

    if is_same_machine_target(resolved_target):
        raise SafetyError(
            f"target {resolved_target} is this machine — for single-host tests enable "
            "Validation mode (loopback). For two-machine tests, run the Streamlit UI on "
            "Laptop A and enter Laptop B's private IP, with the receiver pipeline and lab "
            "echo server on Laptop B."
        )

    if not use_http:
        # Port Scan uses SYN probes; receiver still needs to sniff inbound probes on Laptop B.
        return

    ok, reason = probe_tcp_endpoint(resolved_target, target_port)
    if ok:
        return

    raise SafetyError(
        f"receiver endpoint not reachable ({reason}). On Laptop B start the lab echo "
        f"server before generating traffic:\n"
        f"  python -m traffic_generator.receiver_server --port {target_port}\n"
        f"Then confirm Windows Firewall allows inbound TCP {target_port} and that "
        f"`python -m pipeline -i <iface>` is capturing the interface that receives "
        f"traffic destined to Laptop B (not unrelated outbound Internet flows)."
    )


def default_loopback_capture_interface() -> str:
    """Npcap/loopback capture interface name for the local receiver pipeline."""
    if sys.platform == "win32":
        return r"\Device\NPF_Loopback"
    if sys.platform == "darwin":
        return "lo0"
    return "lo"


def recommended_receiver_pipeline_command(
    *,
    port: int = 8080,
    wifi_interface: str = "Wi-Fi",
) -> str:
    """
    Suggested ``python -m pipeline`` command for Laptop B.

    Captures both the LAN adapter and loopback because Windows often hairpins
    traffic destined to the local IP through the loopback driver, so Wi-Fi alone
    only shows unrelated outbound Internet flows (e.g. HTTPS :443).
    """
    loopback = default_loopback_capture_interface()
    if sys.platform == "win32":
        return (
            f'python -m pipeline -i "{wifi_interface},{loopback}" --lab-port {port}'
        )
    if sys.platform == "darwin":
        return f"sudo python -m pipeline -i {wifi_interface},{loopback} --lab-port {port}"
    return f"sudo python -m pipeline -i eth0,{loopback} --lab-port {port}"
