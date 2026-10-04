"""
One-command Windows start for the single-PC MLCN demo.

    receiver: Npcap (LAN + NPF_Loopback) -> packets -> flows -> 24 features -> XGBoost
    attacker: Streamlit traffic generator -> lab echo server on the lab port
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
import webbrowser

from packet_capture.interfaces import list_interfaces
from traffic_generator.connectivity import probe_tcp_endpoint
from traffic_generator.lab_server import LabEchoServer

from mlcn_launcher.preflight import (
    LauncherError,
    detect_local_ipv4,
    is_admin,
    is_windows,
    needs_elevation,
    npcap_status,
    port_available,
    relaunch_elevated,
    select_capture_interfaces,
    windows_version,
)
from mlcn_launcher.processes import (
    REPO_ROOT,
    LaunchConfig,
    ManagedProcess,
    child_environment,
    pipeline_command,
    streamlit_command,
)
from mlcn_launcher.validation import (
    DEFAULT_PROFILE_SECONDS,
    ProfileWindow,
    format_report,
    load_records,
    run_profiles,
    summarize,
)

RECEIVER_STARTUP_SECONDS = 4.0
STREAMLIT_STARTUP_SECONDS = 45.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mlcn_launcher",
        description="Start the MLCN receiver pipeline + Streamlit attacker UI on one Windows PC.",
    )
    parser.add_argument("--port", type=int, default=8080, help="Lab TCP port (default: 8080).")
    parser.add_argument(
        "--port-span",
        type=int,
        default=50,
        help="Ports from --port captured for Port Scan (default: 50).",
    )
    parser.add_argument("--streamlit-port", type=int, default=8501, help="Streamlit UI port (default: 8501).")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the UI in a browser.")
    parser.add_argument(
        "--no-demo-fallback",
        action="store_true",
        help="Show only genuine model predictions (disable the temporary demo fallback).",
    )
    parser.add_argument("--no-elevate", action="store_true", help="Never trigger a UAC prompt.")
    parser.add_argument("--check", action="store_true", help="Run preflight checks only, then exit.")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Generate every profile on loopback and report genuine model results per profile (no UI).",
    )
    parser.add_argument(
        "--validate-seconds",
        type=float,
        default=DEFAULT_PROFILE_SECONDS,
        help=f"Seconds of traffic per profile in --validate (default: {DEFAULT_PROFILE_SECONDS:g}).",
    )
    parser.add_argument("--pause-on-exit", action="store_true", help=argparse.SUPPRESS)
    return parser


def _say(label: str, value: str) -> None:
    print(f"  {label:<14} {value}", flush=True)


def _preflight(args: argparse.Namespace) -> tuple[str, ...]:
    """Run Windows/Npcap/interface checks; return capture interfaces or raise LauncherError."""
    if not is_windows():
        raise LauncherError(f"the MLCN launcher targets Windows + Npcap (this is {sys.platform}).")
    _say("Windows", windows_version())

    admin = is_admin()
    _say("Administrator", "yes" if admin else "no")

    status = npcap_status()
    if not status.installed:
        raise LauncherError(
            "Npcap is not installed (wpcap.dll missing). Install it from https://npcap.com "
            "with 'Support loopback traffic' enabled."
        )
    _say("Npcap", status.describe())
    if status.loopback_support is False:
        raise LauncherError("Npcap loopback support is disabled. Reinstall Npcap with 'Support loopback traffic'.")
    if needs_elevation(status, admin):
        raise _ElevationRequired()

    local_ip = detect_local_ipv4()
    _say("Local IPv4", local_ip or "not found")
    selection = select_capture_interfaces(list_interfaces(), local_ip)
    _say("Capture", selection.as_argument())
    for warning in selection.warnings:
        _say("Warning", warning)

    if not port_available(args.port):
        raise LauncherError(f"TCP port {args.port} is already in use. Close the program using it or pass --port.")
    if not port_available(args.streamlit_port, "127.0.0.1"):
        raise LauncherError(
            f"Streamlit port {args.streamlit_port} is already in use (another UI running?). "
            "Close it or pass --streamlit-port."
        )
    last = args.port + max(1, args.port_span) - 1
    _say("Lab ports", f"{args.port} (Port Scan range {args.port}-{last})")
    return selection.interfaces


class _ElevationRequired(LauncherError):
    def __init__(self) -> None:
        super().__init__("Npcap capture requires Administrator rights.")


def elevated_arguments(argv: list[str]) -> list[str]:
    """Python arguments for the UAC relaunch; independent of the elevated working directory."""
    root = str(REPO_ROOT)
    forwarded = [*argv, "--pause-on-exit"] if "--pause-on-exit" not in argv else list(argv)
    code = (
        "import os, runpy, sys; "
        f"os.chdir({root!r}); sys.path.insert(0, {root!r}); "
        f"sys.argv = ['mlcn_launcher', *{forwarded!r}]; "
        "runpy.run_module('mlcn_launcher', run_name='__main__')"
    )
    return ["-c", code]


def _wait_for_port(port: int, timeout: float, alive: ManagedProcess | None = None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if alive is not None and not alive.running:
            return False
        ok, _reason = probe_tcp_endpoint("127.0.0.1", port, timeout=0.5)
        if ok:
            return True
        time.sleep(0.5)
    return False


def _install_break_handler() -> None:
    def _interrupt(_signum, _frame) -> None:
        raise KeyboardInterrupt

    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _interrupt)


def run(args: argparse.Namespace) -> int:
    print("MLCN launcher — preflight", flush=True)
    try:
        interfaces = _preflight(args)
    except _ElevationRequired as exc:
        if args.no_elevate or args.check:
            print(f"Error: {exc} Run from an Administrator terminal.", file=sys.stderr)
            return 1
        print("Requesting Administrator rights (UAC)...", flush=True)
        if relaunch_elevated(elevated_arguments(sys.argv[1:]), REPO_ROOT):
            return 0
        print(f"Error: {exc} UAC elevation was cancelled.", file=sys.stderr)
        return 1
    except LauncherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.check:
        print("Preflight OK.")
        return 0

    cfg = LaunchConfig(
        python=sys.executable,
        capture_interfaces=interfaces,
        lab_port=args.port,
        lab_port_span=max(1, args.port_span),
        streamlit_port=args.streamlit_port,
        demo_fallback=not (args.no_demo_fallback or args.validate),
        detections_file="validation_detections.jsonl" if args.validate else "detections.jsonl",
    )
    cfg.logs_dir.mkdir(parents=True, exist_ok=True)
    cfg.demo_session_file.unlink(missing_ok=True)
    if args.validate:
        cfg.detections_log.unlink(missing_ok=True)
    env = child_environment(cfg)

    echo = LabEchoServer(host="0.0.0.0", port=cfg.lab_port)
    receiver = ManagedProcess("receiver", pipeline_command(cfg), cwd=cfg.repo_root, env=env)
    attacker = ManagedProcess(
        "attacker",
        streamlit_command(cfg),
        cwd=cfg.repo_root,
        env=env,
        log_file=cfg.streamlit_log,
    )
    _install_break_handler()
    exit_code = 0
    windows: list[ProfileWindow] | None = None
    try:
        echo.start()
        if not _wait_for_port(cfg.lab_port, 3.0):
            raise LauncherError(f"lab echo server could not listen on TCP {cfg.lab_port}.")

        receiver.start()
        time.sleep(RECEIVER_STARTUP_SECONDS)
        if not receiver.running:
            raise LauncherError(
                f"receiver pipeline exited (code {receiver.returncode}); see [receiver] lines above."
            )

        if args.validate:
            windows = run_profiles(
                host="127.0.0.1",
                port=cfg.lab_port,
                port_span=cfg.lab_port_span,
                seconds=args.validate_seconds,
                settle_seconds=cfg.inactivity_timeout + 1.0,
            )
        else:
            exit_code = _serve_ui(cfg, args, receiver, attacker)
    except KeyboardInterrupt:
        print("\nStopping MLCN...", flush=True)
    except LauncherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        attacker.stop()
        receiver.stop()
        echo.stop()
        print("All MLCN processes stopped.", flush=True)
        if windows is not None:
            exit_code = _report_validation(cfg, windows)
    return exit_code


def _serve_ui(
    cfg: LaunchConfig,
    args: argparse.Namespace,
    receiver: ManagedProcess,
    attacker: ManagedProcess,
) -> int:
    """Start Streamlit and block until a child exits (returns 1) or Ctrl+C."""
    attacker.start()
    if not _wait_for_port(cfg.streamlit_port, STREAMLIT_STARTUP_SECONDS, attacker):
        raise LauncherError(f"Streamlit did not start; see {cfg.streamlit_log}.")

    print(
        f"\nMLCN running. Attacker UI: {cfg.streamlit_url} "
        f"(target 127.0.0.1, port {cfg.lab_port}, leave Validation mode OFF).\n"
        f"Detections are printed below and saved to {cfg.detections_log}.\n"
        "Press Ctrl+C to stop everything.\n",
        flush=True,
    )
    if not args.no_browser:
        webbrowser.open(cfg.streamlit_url)

    while receiver.running and attacker.running:
        time.sleep(0.5)
    stopped = receiver if not receiver.running else attacker
    print(f"Error: {stopped.name} exited unexpectedly (code {stopped.returncode}).", file=sys.stderr)
    return 1


def _report_validation(cfg: LaunchConfig, windows: list[ProfileWindow]) -> int:
    """Print and save the per-profile verdict; non-zero unless every profile is REAL ML."""
    summaries = summarize(windows, load_records(cfg.detections_log))
    report = format_report(summaries)
    report_path = cfg.logs_dir / "validation_report.txt"
    report_path.write_text(report + "\n", encoding="utf-8")
    print(f"\nLive validation (genuine model, Npcap capture):\n{report}\nSaved to {report_path}", flush=True)
    return 0 if all(item.verdict == "REAL ML" for item in summaries) else 1


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    code = run(args)
    if args.pause_on_exit:
        # The UAC window closes on exit; keep it open so messages stay readable.
        try:
            input("Press Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass
    return code
