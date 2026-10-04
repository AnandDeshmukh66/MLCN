"""CLI for the integrated MLCN Modules 1–5 pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import demo_fallback
from demo_fallback import DEMO_FALLBACK_ENV
from feature_engineering.contract import FLOW_TIMEOUT_SECONDS
from packet_capture.interfaces import list_interfaces

from pipeline.engine import IntrusionDetectionPipeline
from pipeline.models import PipelineResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description="MLCN end-to-end intrusion detection pipeline (Modules 1–5)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture on (e.g. Ethernet, Wi-Fi, lo0). "
        "Defaults to Scapy's default interface.",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--inactivity-timeout",
        type=float,
        default=60.0,
        help="Module 3 idle timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--max-duration",
        type=float,
        default=FLOW_TIMEOUT_SECONDS,
        help=(
            "Module 3 max flow duration in seconds "
            f"(default: {FLOW_TIMEOUT_SECONDS:g}, the CICFlowMeter training flow timeout)."
        ),
    )
    parser.add_argument(
        "--lab-port",
        type=int,
        metavar="PORT",
        help=(
            "Laboratory mode: capture/print only flows involving this TCP port "
            "(e.g. 8080 for traffic-generator tests). Filters out background Internet traffic."
        ),
    )
    parser.add_argument(
        "--lab-port-span",
        type=int,
        default=1,
        metavar="N",
        help="With --lab-port, also include the next N-1 ports (Port Scan range). Default: 1.",
    )
    parser.add_argument(
        "--detections-log",
        metavar="PATH",
        help="Append every displayed detection as one JSON line to PATH.",
    )
    parser.add_argument(
        "--demo-fallback",
        action="store_true",
        help=(
            "TEMPORARY demo mode: display the attacker-selected profile when the real "
            "prediction disagrees (genuine result kept in the detections log). "
            f"Also enabled by {DEMO_FALLBACK_ENV}=1."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def _print_interfaces() -> None:
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces detected.")
        return
    print(f"{'INTERFACE':<20} {'ADDRESS':<20}")
    print("-" * 40)
    for iface in interfaces:
        address = iface.address or "-"
        print(f"{iface.name:<20} {address:<20}")


def _format_probabilities(result: PipelineResult) -> str:
    return " ".join(f"{name}={prob:.3f}" for name, prob in result.detection.items())


def _print_result(result: PipelineResult) -> None:
    flow = result.flow
    detection = result.detection
    source = demo_fallback.result_source(result)
    print(
        f"[{detection.predicted_class}] "
        f"conf={detection.confidence:.4f} "
        f"{flow.protocol} {flow.src_ip}:{flow.src_port} → "
        f"{flow.dst_ip}:{flow.dst_port} "
        f"pkts={flow.packet_count} bytes={flow.byte_count} "
        f"dur={flow.duration:.3f}s "
        f"probs[{_format_probabilities(result)}] "
        f"source={source['result_source']}",
        flush=True,
    )
    if "disclaimer" in source:
        print(f"    {source['disclaimer']}", flush=True)


def _print_session_result(verdict: demo_fallback.SessionResult) -> None:
    shown = verdict.detection
    probs = " ".join(f"{name}={prob:.3f}" for name, prob in shown.items())
    print(f"\n===== RESULT: {verdict.selected} | {verdict.source} =====", flush=True)
    if verdict.disclaimer:
        print(verdict.disclaimer)
        print(f"selected={verdict.selected} displayed={shown.predicted_class} conf={shown.confidence:.4f} probs[{probs}]")
    else:
        print(
            f"selected={verdict.selected} genuine_predicted={shown.predicted_class} "
            f"genuine_conf={shown.confidence:.4f} genuine_probs[{probs}] "
            f"flows={verdict.relevant_flows} matched={verdict.genuine_matches}"
        )
    print("", flush=True)


def _append_log(path: Path | None, record: dict[str, object]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle_file:
        handle_file.write(json.dumps({"recorded_at": time.time(), **record}) + "\n")


def _log_path(log_path: str | None) -> Path | None:
    if not log_path:
        return None
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _detection_handler(log_path: str | None) -> Callable[[PipelineResult], None]:
    path = _log_path(log_path)

    def handle(result: PipelineResult) -> None:
        _print_result(result)
        _append_log(path, {**result.as_dict(), **demo_fallback.result_source(result)})

    return handle


def _session_result_handler(log_path: str | None) -> Callable[[demo_fallback.SessionResult], None]:
    path = _log_path(log_path)

    def handle(verdict: demo_fallback.SessionResult) -> None:
        _print_session_result(verdict)
        _append_log(path, verdict.as_dict())

    return handle


def _watch_sessions(
    fallback: demo_fallback.DemoFallback,
    report: Callable[[demo_fallback.SessionResult], None],
    stop: threading.Event,
) -> None:
    while not stop.wait(0.5):
        try:
            verdict = fallback.poll()
            if verdict is not None:
                report(verdict)
        except Exception:
            logging.debug("session verdict failed", exc_info=True)


def _wait_for_interrupt() -> None:
    """Keep reporting attacker sessions after a capture failure until stopped."""
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if args.list_interfaces:
        _print_interfaces()
        return 0

    demo_mode = args.demo_fallback or demo_fallback.enabled_from_env()
    fallback = demo_fallback.DemoFallback() if demo_mode else None
    if fallback is not None:
        report_session = _session_result_handler(args.detections_log)
        stop_watch = threading.Event()
        threading.Thread(
            target=_watch_sessions,
            args=(fallback, report_session, stop_watch),
            name="demo-session-watch",
            daemon=True,
        ).start()
    try:
        return _run(args, fallback)
    finally:
        if fallback is not None:
            stop_watch.set()
            verdict = fallback.poll(final=True)
            if verdict is not None:
                report_session(verdict)


def _run(args: argparse.Namespace, fallback: demo_fallback.DemoFallback | None) -> int:
    try:
        pipeline = IntrusionDetectionPipeline(
            interface=args.interface,
            inactivity_timeout=args.inactivity_timeout,
            max_duration=args.max_duration,
            on_detection=_detection_handler(args.detections_log),
            lab_port=args.lab_port,
            lab_port_span=args.lab_port_span,
            display_transform=fallback,
        )
    except Exception as exc:
        return _fail(f"Error initializing pipeline: {exc}", fallback)

    iface_label = args.interface or "default"
    print(f"MLCN pipeline starting on interface: {iface_label}")
    if args.lab_port:
        span = max(1, args.lab_port_span)
        ports = f"{args.lab_port}" if span == 1 else f"{args.lab_port}-{args.lab_port + span - 1}"
        print(f"Lab filter active: TCP port {ports}")
    print("Modules: Capture → Parse → Flow → Features → XGBoost")
    print("Press Ctrl+C to stop and flush active flows.\n")

    try:
        results = pipeline.run_live()
    except ValueError as exc:
        return _fail(f"Error: {exc}", fallback)
    except PermissionError as exc:
        return _fail(f"Error: {exc}", fallback)
    except OSError as exc:
        return _fail(f"Capture failed: {exc}", fallback)

    print(
        f"\nPipeline stopped. "
        f"Accepted {pipeline.packets_accepted} packet(s), "
        f"skipped {pipeline.packets_skipped}, "
        f"unclassified flows {pipeline.flows_skipped}, "
        f"detections {len(results)}."
    )
    return 0


def _fail(message: str, fallback: demo_fallback.DemoFallback | None) -> int:
    print(message, file=sys.stderr)
    if fallback is None:
        return 1
    # Demo mode: the selected attack must still be displayed for every attacker session.
    print("Demo fallback active: results will still be shown. Press Ctrl+C to stop.", flush=True)
    _wait_for_interrupt()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
