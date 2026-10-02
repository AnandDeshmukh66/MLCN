"""
Real-vs-demo display decision and synthetic probability generation.

Genuine XGBoost inference always runs first and is never altered; this module
only builds an alternative *display* result when the genuine prediction does
not match the attacker's selected profile.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import random
import threading
import time
from collections.abc import Sequence
from pathlib import Path

from ml_detection.models import DetectionResult
from ml_detection.schema import CLASS_ORDER

from demo_fallback.session import DemoSession, read_session, session_path
from pipeline.models import PipelineResult

DEMO_FALLBACK_ENV = "MLCN_DEMO_FALLBACK"

REAL_ML = "REAL ML"
FABRICATED = "FABRICATED DEMO RESULT"
DISCLAIMER = "Synthetic values used for demo purposes — not genuine model output."
# Existing reliability rule: share of connection-opening flows the genuine model must get right.
MIN_REAL_MATCH_FRACTION = 0.9
# After the attacker stops, wait for FIN-closed flows to be classified before the verdict.
SESSION_SETTLE_SECONDS = 3.0

# Synthetic confidence of the selected class (above the 0.9 acceptance rule).
MIN_SYNTHETIC_CONFIDENCE = 0.91
MAX_SYNTHETIC_CONFIDENCE = 0.975
# Probabilities are multiples of 2**-20, so any summation order gives exactly 1.0.
_PROBABILITY_UNITS = 1 << 20


class Decision(enum.Enum):
    REAL = "REAL"
    DEMO_FALLBACK = "DEMO_FALLBACK"


def enabled_from_env() -> bool:
    return os.environ.get(DEMO_FALLBACK_ENV, "").strip() == "1"


def decide(genuine: DetectionResult, selected_profile: str | None) -> Decision:
    """REAL when no profile is selected or the model already predicts it."""
    if selected_profile is None or genuine.predicted_class == selected_profile:
        return Decision.REAL
    return Decision.DEMO_FALLBACK


def synthetic_detection(selected_profile: str, rng: random.Random | None = None) -> DetectionResult:
    """Randomised 5-class distribution peaked on ``selected_profile``; sums exactly to 1.0."""
    if selected_profile not in CLASS_ORDER:
        raise ValueError(f"unknown profile: {selected_profile!r}")
    rng = rng or random.Random()
    top_units = round(
        rng.uniform(MIN_SYNTHETIC_CONFIDENCE, MAX_SYNTHETIC_CONFIDENCE) * _PROBABILITY_UNITS
    )
    others = [name for name in CLASS_ORDER if name != selected_profile]
    remaining = _PROBABILITY_UNITS - top_units
    weights = [rng.random() + 0.05 for _ in others]
    total_weight = sum(weights)
    units = [int(remaining * w / total_weight) for w in weights]
    units[units.index(max(units))] += remaining - sum(units)

    probabilities = {selected_profile: top_units / _PROBABILITY_UNITS}
    for name, share in zip(others, units):
        probabilities[name] = share / _PROBABILITY_UNITS
    return DetectionResult.from_probability_mapping(probabilities)


def result_source(result: PipelineResult) -> dict[str, str]:
    """Display/log fields naming where a per-flow result came from."""
    if result.demo_fallback:
        return {"result_source": FABRICATED, "disclaimer": DISCLAIMER}
    return {"result_source": REAL_ML}


@dataclasses.dataclass(frozen=True)
class SessionResult:
    """The receiver's final answer for one attacker session; always shows ``selected``."""

    selected: str
    source: str
    detection: DetectionResult
    relevant_flows: int
    genuine_matches: int
    genuine_detection: DetectionResult | None = None

    @property
    def disclaimer(self) -> str | None:
        return DISCLAIMER if self.source == FABRICATED else None

    def as_dict(self) -> dict[str, object]:
        genuine = self.genuine_detection
        record: dict[str, object] = {
            "record_type": "session_result",
            "selected_attack": self.selected,
            "displayed_attack": self.detection.predicted_class,
            "result_source": self.source,
            "confidence": self.detection.confidence,
            "probabilities": dict(self.detection.probabilities),
            "relevant_flows": self.relevant_flows,
            "genuine_matches": self.genuine_matches,
            "genuine_predicted_class": genuine.predicted_class if genuine else None,
            "genuine_confidence": genuine.confidence if genuine else None,
            "genuine_probabilities": dict(genuine.probabilities) if genuine else None,
        }
        if self.disclaimer:
            record["disclaimer"] = self.disclaimer
        return record


def _mean_detection(detections: Sequence[DetectionResult]) -> DetectionResult:
    sums = {name: 0.0 for name in CLASS_ORDER}
    for detection in detections:
        for name, probability in detection.items():
            sums[name] += probability
    total = sum(sums.values())
    return DetectionResult.from_probability_mapping({name: s / total for name, s in sums.items()})


def session_result(
    selected: str,
    genuine: Sequence[DetectionResult],
    rng: random.Random | None = None,
) -> SessionResult:
    """REAL ML when the genuine model meets the reliability rule; otherwise fabricated ``selected``."""
    matches = 0
    aggregate = None
    try:
        matches = sum(1 for d in genuine if d.predicted_class == selected)
        if genuine:
            aggregate = _mean_detection(genuine)
            if matches / len(genuine) >= MIN_REAL_MATCH_FRACTION and aggregate.predicted_class == selected:
                return SessionResult(selected, REAL_ML, aggregate, len(genuine), matches, aggregate)
    except Exception:
        aggregate = None
    return SessionResult(
        selected, FABRICATED, synthetic_detection(selected, rng), len(genuine), matches, aggregate
    )


def _is_opening_flow(result: PipelineResult) -> bool:
    """Connection-opening flows; close-handshake tail flows are not judged."""
    packets = result.flow.packets
    return not packets or packets[0].tcp_flags == "S"


class DemoFallback:
    """
    ``IntrusionDetectionPipeline`` display transform.

    Flows inside an active attacker session whose genuine prediction differs
    from the selected profile are displayed with a synthetic distribution;
    the genuine result is preserved on ``PipelineResult.genuine_detection``.
    """

    def __init__(self, session_file: str | Path | None = None, rng: random.Random | None = None) -> None:
        self._path = session_path(session_file)
        self._rng = rng or random.Random()
        self._cached: DemoSession | None = None
        self._cached_mtime: float | None = None
        self._created_at = time.time()
        self._lock = threading.Lock()
        self._genuine: dict[float, list[DetectionResult]] = {}
        self._reported: set[float] = set()

    def _session(self) -> DemoSession | None:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return None
        if mtime != self._cached_mtime:
            session = read_session(self._path)
            if session is None:
                return self._cached
            self._cached, self._cached_mtime = session, mtime
        return self._cached

    def __call__(self, result: PipelineResult) -> PipelineResult:
        with self._lock:
            session = self._session()
        if session is None or not session.covers(result.flow):
            return result
        try:
            if _is_opening_flow(result):
                with self._lock:
                    self._genuine.setdefault(session.started_at, []).append(result.detection)
            if decide(result.detection, session.profile) is Decision.REAL:
                return result
        except Exception:
            pass
        return dataclasses.replace(
            result,
            detection=synthetic_detection(session.profile, self._rng),
            demo_fallback=True,
            genuine_detection=result.detection,
        )

    def poll(self, now: float | None = None, *, final: bool = False) -> SessionResult | None:
        """
        The session verdict once the attacker has stopped (plus settle time), exactly once.

        ``final`` (receiver shutdown) reports an unfinished session immediately.
        """
        now = time.time() if now is None else now
        with self._lock:
            session = self._session()
            if session is None or session.started_at in self._reported:
                return None
            if session.ended_at is not None and session.ended_at < self._created_at:
                self._reported.add(session.started_at)  # stale session from before this receiver
                return None
            if not final and (session.ended_at is None or now < session.ended_at + SESSION_SETTLE_SECONDS):
                return None
            self._reported.add(session.started_at)
            genuine = self._genuine.pop(session.started_at, [])
        return session_result(session.profile, genuine, self._rng)
