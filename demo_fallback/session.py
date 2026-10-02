"""
File handoff of the attacker's selected profile to the receiver process.

The Streamlit/attacker process writes the active session; the receiver
pipeline (a separate process) reads it to know which profile was selected.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from flow_builder.models import Flow

SESSION_FILE_ENV = "MLCN_DEMO_SESSION_FILE"
DEFAULT_SESSION_FILE = Path(__file__).resolve().parents[1] / "logs" / "demo_session.json"
# Tolerance for flows that start just before/after the generator start/stop timestamps.
SESSION_GRACE_SECONDS = 2.0


@dataclass(frozen=True)
class DemoSession:
    profile: str
    port_low: int
    port_high: int
    started_at: float
    ended_at: float | None = None

    def covers(self, flow: Flow, *, grace: float = SESSION_GRACE_SECONDS) -> bool:
        """True when ``flow`` started during this session and touches its lab ports."""
        start = flow.start_time.timestamp()
        if start < self.started_at - grace:
            return False
        if self.ended_at is not None and start > self.ended_at + grace:
            return False
        ports = range(self.port_low, self.port_high + 1)
        return flow.src_port in ports or flow.dst_port in ports


def session_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    override = os.environ.get(SESSION_FILE_ENV)
    return Path(override) if override else DEFAULT_SESSION_FILE


def _write(session: DemoSession, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(session)), encoding="utf-8")
    # Windows refuses to replace a file another process has open; the reader only
    # holds it for a moment, so retry briefly.
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def write_session(
    profile: str,
    port_low: int,
    port_high: int,
    *,
    path: str | Path | None = None,
    now: float | None = None,
) -> DemoSession:
    session = DemoSession(
        profile=profile,
        port_low=int(port_low),
        port_high=int(max(port_low, port_high)),
        started_at=time.time() if now is None else now,
    )
    _write(session, session_path(path))
    return session


def finish_session(*, path: str | Path | None = None, now: float | None = None) -> None:
    target = session_path(path)
    session = read_session(target)
    if session is None or session.ended_at is not None:
        return
    ended = time.time() if now is None else now
    _write(DemoSession(**{**asdict(session), "ended_at": ended}), target)


def read_session(path: str | Path | None = None) -> DemoSession | None:
    try:
        raw = json.loads(session_path(path).read_text(encoding="utf-8"))
        return DemoSession(**raw)
    except (OSError, ValueError, TypeError):
        return None
