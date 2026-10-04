"""Read-only receiver data for the dashboard (no Streamlit imports, unit-testable)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from demo_fallback.session import SESSION_FILE_ENV, session_path

DETECTIONS_FILE = "detections.jsonl"
DEMO_NOTICE = ""
HISTORY_LIMIT = 12
_TAIL_BYTES = 512_000


def detections_log_path() -> Path:
    """The receiver's log sits next to the demo session file the launcher configures."""
    override = os.environ.get("MLCN_DETECTIONS_LOG")
    if override:
        return Path(override)
    return session_path().parent / DETECTIONS_FILE


def read_records(path: Path, since: float = 0.0) -> list[dict]:
    """Records logged at or after ``since`` (epoch seconds); tolerant of partial lines."""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - _TAIL_BYTES))
            raw = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    records = []
    for line in raw.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and float(record.get("recorded_at", 0.0)) >= since:
            records.append(record)
    return records


@dataclass(frozen=True)
class ReceiverView:
    """What the right-hand panel shows for the current attacker run."""

    verdict: dict | None = None  # final session_result record
    latest_flow: dict | None = None  # newest per-flow record
    flows: list[dict] = field(default_factory=list)  # per-flow records, newest first
    live: bool = False  # no final verdict yet, showing the newest flow

    @property
    def primary(self) -> dict | None:
        return self.verdict or self.latest_flow

    @property
    def fabricated(self) -> bool:
        primary = self.primary
        if primary is None:
            return False
        return primary.get("result_source") == "Interpolated Values" or bool(primary.get("demo_fallback"))


def build_view(records: list[dict]) -> ReceiverView:
    verdicts = [r for r in records if r.get("record_type") == "session_result"]
    flows = [r for r in records if r.get("record_type") != "session_result"]
    flows.reverse()
    return ReceiverView(
        verdict=verdicts[-1] if verdicts else None,
        latest_flow=flows[0] if flows else None,
        flows=flows,
        live=not verdicts and bool(flows),
    )


def receiver_view(since: float) -> ReceiverView:
    return build_view(read_records(detections_log_path(), since))


__all__ = ["DEMO_NOTICE", "HISTORY_LIMIT", "ReceiverView", "SESSION_FILE_ENV", "build_view", "receiver_view"]
