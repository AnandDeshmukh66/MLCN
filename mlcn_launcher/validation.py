"""
Automated live check (``start_mlcn.bat --validate``): generate every profile on
loopback against the running receiver and report whether the genuine model
recognised it from the real Npcap capture.
"""

from __future__ import annotations

import collections
import json
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from demo_fallback.fallback import FABRICATED, MIN_REAL_MATCH_FRACTION, REAL_ML
from traffic_generator.config import MAX_PORT_SCAN_PORTS, PROFILE_NAMES
from traffic_generator.connectivity import probe_tcp_endpoint
from traffic_generator.parameter_mapper import map_profile_to_parameters
from traffic_generator.traffic_generator import build_generator

DEFAULT_PROFILE_SECONDS = 20.0
# Flows starting slightly before/after a profile's run still belong to it.
_WINDOW_LEAD_SECONDS = 0.5
_WINDOW_TAIL_SECONDS = 1.0


@dataclass(frozen=True)
class ProfileWindow:
    profile: str
    started_at: float
    ended_at: float

    def contains(self, start_time: float) -> bool:
        return self.started_at - _WINDOW_LEAD_SECONDS <= start_time <= self.ended_at + _WINDOW_TAIL_SECONDS


@dataclass(frozen=True)
class ProfileSummary:
    profile: str
    opening_flows: int
    real_matches: int
    genuine_classes: dict[str, int]
    total_flows: int

    @property
    def match_fraction(self) -> float:
        return self.real_matches / self.opening_flows if self.opening_flows else 0.0

    @property
    def verdict(self) -> str:
        if self.opening_flows and self.match_fraction >= MIN_REAL_MATCH_FRACTION:
            return REAL_ML
        return FABRICATED


def run_profiles(
    *,
    host: str,
    port: int,
    port_span: int,
    seconds: float,
    settle_seconds: float,
    profiles: Sequence[str] = PROFILE_NAMES,
    sink: Callable[[str], None] = print,
) -> list[ProfileWindow]:
    """Generate each profile in turn; returns the wall-clock window of each run."""
    scan_end = port + min(max(1, port_span), MAX_PORT_SCAN_PORTS) - 1
    windows: list[ProfileWindow] = []
    for profile in profiles:
        params = map_profile_to_parameters(
            profile,
            target_host=host,
            target_port=port,
            duration_seconds=seconds,
            port_scan_start=port,
            port_scan_end=scan_end,
        )
        sink(f"[validate] {profile}: generating for {seconds:g} s...")
        started = time.time()
        build_generator(params, threading.Event()).run()
        windows.append(ProfileWindow(profile, started, time.time()))
        # Let idle flows expire: new packets after the inactivity timeout close them.
        time.sleep(settle_seconds)
        probe_tcp_endpoint(host, port, timeout=1.0)
    return windows


def load_records(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


def summarize(windows: Iterable[ProfileWindow], records: Sequence[dict]) -> list[ProfileSummary]:
    """Per profile: share of connection-opening flows the genuine model labelled correctly."""
    summaries = []
    for window in windows:
        in_window = [r for r in records if window.contains(float(r.get("start_time", 0.0)))]
        opening = [r for r in in_window if r.get("first_packet_flags") == "S"]
        genuine = collections.Counter(r["genuine_predicted_class"] for r in opening)
        summaries.append(
            ProfileSummary(
                profile=window.profile,
                opening_flows=len(opening),
                real_matches=genuine[window.profile],
                genuine_classes=dict(genuine),
                total_flows=len(in_window),
            )
        )
    return summaries


def format_report(summaries: Sequence[ProfileSummary]) -> str:
    lines = [
        f"{'PROFILE':<12} {'FLOWS':>6} {'OPENING':>8} {'REAL MATCH':>11}  RESULT",
        "-" * 64,
    ]
    for item in summaries:
        detail = ""
        if item.verdict == FABRICATED and item.genuine_classes:
            detail = "  genuine: " + ", ".join(f"{k}={v}" for k, v in sorted(item.genuine_classes.items()))
        lines.append(
            f"{item.profile:<12} {item.total_flows:>6} {item.opening_flows:>8} "
            f"{item.match_fraction:>10.0%}  {item.verdict}{detail}"
        )
    return "\n".join(lines)
