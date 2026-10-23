"""
Structured, serializable analysis context for the XAI assistant.

Built only from results the application already has: the dashboard's current
run, the receiver detections it reads, the traffic generator's run log, the
saved offline evaluation artifacts in ``models/`` and the launcher's live
validation report. Nothing is re-inferred. IP addresses are reduced to their
address class so raw network identifiers are not sent to the LLM.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from demo_fallback.fallback import DISCLAIMER, MIN_REAL_MATCH_FRACTION, REAL_ML
from traffic_generator.dashboard_data import ReceiverView, detections_log_path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = REPO_ROOT / "models"
EVALUATION_FILE = "xgboost_evaluation_results.json"
CONFUSION_FILE = "xgboost_confusion_matrix.csv"
FEATURES_FILE = "xgboost_ids_features.json"
VALIDATION_REPORT_FILE = "validation_report.txt"

CONTEXT_SCHEMA = "mlcn-xai-context/1"
MAX_RECENT_FLOWS = 20
MAX_VALIDATION_REPORT_CHARS = 2000
PIPELINE_STAGES = (
    "Packet capture (Scapy/Npcap)",
    "Packet parsing and validation",
    "Bidirectional flow building",
    "24-feature CICFlowMeter-style feature engineering",
    "XGBoost five-class detection (softmax probabilities)",
)
# Generator parameters that identify hosts are dropped before reaching the LLM.
_REDACTED_PARAMETERS = {"target_host"}


def _iso(epoch: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _round(value: Any, digits: int = 4) -> float | None:
    try:
        return round(float(value), digits)
    except (TypeError, ValueError):
        return None


def _probabilities(raw: Any) -> dict[str, float] | None:
    if not isinstance(raw, dict):
        return None
    return {str(name): _round(value) for name, value in raw.items()}


def host_kind(ip: Any) -> str:
    """Address class instead of the address itself."""
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private-lan"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    return "public"


def _is_synthetic(record: dict) -> bool:
    return bool(record.get("demo_fallback")) or (
        record.get("result_source") not in (None, REAL_ML) or record.get("disclaimer") == DISCLAIMER
    )


def _model_prediction(record: dict) -> dict[str, Any] | None:
    """The genuine XGBoost output for a record, or ``None`` when the log does not contain it."""
    if record.get("genuine_predicted_class") is not None:
        return {
            "class": record["genuine_predicted_class"],
            "confidence": _round(record.get("genuine_confidence")),
            "probabilities": _probabilities(record.get("genuine_probabilities")),
        }
    if not _is_synthetic(record) and record.get("predicted_class") is not None:
        return {
            "class": record["predicted_class"],
            "confidence": _round(record.get("confidence")),
            "probabilities": _probabilities(record.get("probabilities")),
        }
    return None


def flow_summary(record: dict) -> dict[str, Any]:
    return {
        "recorded_at": _iso(record.get("recorded_at")),
        "protocol": record.get("protocol"),
        "source": f'{host_kind(record.get("src_ip"))}:{record.get("src_port")}',
        "destination": f'{host_kind(record.get("dst_ip"))}:{record.get("dst_port")}',
        "packet_count": record.get("packet_count"),
        "byte_count": record.get("byte_count"),
        "duration_seconds": _round(record.get("duration"), 6),
        "first_packet_tcp_flags": record.get("first_packet_flags"),
        "model_prediction": _model_prediction(record),
        "displayed_class": record.get("predicted_class"),
        "displayed_confidence": _round(record.get("confidence")),
        "displayed_result_is_synthetic": _is_synthetic(record),
    }


def verdict_summary(record: dict) -> dict[str, Any]:
    synthetic = _is_synthetic(record)
    aggregate = None
    if record.get("genuine_predicted_class") is not None:
        aggregate = {
            "class": record["genuine_predicted_class"],
            "confidence": _round(record.get("genuine_confidence")),
            "probabilities": _probabilities(record.get("genuine_probabilities")),
        }
    return {
        "recorded_at": _iso(record.get("recorded_at")),
        "selected_attack_profile": record.get("selected_attack"),
        "displayed_attack": record.get("displayed_attack"),
        "displayed_confidence": _round(record.get("confidence")),
        "displayed_probabilities": _probabilities(record.get("probabilities")),
        "displayed_result_is_synthetic": synthetic,
        "relevant_opening_flows": record.get("relevant_flows"),
        "opening_flows_where_model_matched_selected_profile": record.get("genuine_matches"),
        "model_mean_probability_prediction": aggregate,
        "reliability_rule": (
            f"Shown as REAL ML only when at least {MIN_REAL_MATCH_FRACTION:.0%} of connection-opening flows "
            "were classified by the model as the selected profile and the mean-probability class equals it; "
            "otherwise the dashboard shows a synthetic distribution peaked on the selected profile."
        ),
    }


def _detections_summary(flows: list[dict]) -> dict[str, Any]:
    model_classes: Counter[str] = Counter()
    displayed_classes: Counter[str] = Counter()
    confidences: list[float] = []
    synthetic = 0
    packets = 0
    for record in flows:
        displayed_classes[str(record.get("predicted_class"))] += 1
        if _is_synthetic(record):
            synthetic += 1
        prediction = _model_prediction(record)
        if prediction:
            model_classes[prediction["class"]] += 1
            if prediction["confidence"] is not None:
                confidences.append(prediction["confidence"])
        try:
            packets += int(record.get("packet_count") or 0)
        except (TypeError, ValueError):
            pass
    return {
        "flow_count": len(flows),
        "total_packets": packets,
        "model_predicted_class_counts": dict(model_classes),
        "displayed_class_counts": dict(displayed_classes),
        "flows_with_synthetic_display": synthetic,
        "model_confidence_mean": _round(sum(confidences) / len(confidences)) if confidences else None,
        "model_confidence_min": _round(min(confidences)) if confidences else None,
        "model_confidence_max": _round(max(confidences)) if confidences else None,
    }


@lru_cache(maxsize=4)
def _load_offline_evaluation(models_dir: str) -> dict[str, Any] | None:
    root = Path(models_dir)
    try:
        evaluation = json.loads((root / EVALUATION_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    report = evaluation.pop("classification_report", {})
    per_class = {
        name: {k: _round(v) for k, v in values.items()}
        for name, values in report.items()
        if isinstance(values, dict) and name not in ("macro avg", "weighted avg")
    }
    result: dict[str, Any] = {
        "source": f"models/{EVALUATION_FILE} (saved held-out test-set evaluation; not this session's traffic)",
        "metrics": {k: (_round(v, 6) if isinstance(v, float) else v) for k, v in evaluation.items()},
        "per_class": per_class,
    }
    try:
        with (root / CONFUSION_FILE).open(encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        labels = rows[0][1:]
        result["confusion_matrix"] = {
            "orientation": "rows = actual class, columns = predicted class",
            "labels": labels,
            "rows": {row[0]: dict(zip(labels, (int(float(v)) for v in row[1:]))) for row in rows[1:] if row},
        }
    except (OSError, ValueError, IndexError):
        result["confusion_matrix"] = None
    try:
        features = json.loads((root / FEATURES_FILE).read_text(encoding="utf-8"))
        result["input_features"] = features.get("features")
    except (OSError, ValueError):
        result["input_features"] = None
    return result


def offline_evaluation(models_dir: Path = MODELS_DIR) -> dict[str, Any] | None:
    cached = _load_offline_evaluation(str(models_dir))
    return json.loads(json.dumps(cached)) if cached else None


def live_validation_report(path: Path | None = None) -> dict[str, Any] | None:
    path = path or detections_log_path().parent / VALIDATION_REPORT_FILE
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    return {
        "source": "launcher --validate run (genuine model on generated loopback traffic, demo fallback disabled)",
        "text": text[:MAX_VALIDATION_REPORT_CHARS],
    }


def generator_snapshot(controller: Any) -> dict[str, Any] | None:
    """Duck-typed view of ``TrafficGeneratorController`` state, host identifiers removed."""
    if controller is None:
        return None
    try:
        snapshot: dict[str, Any] = {
            "running": bool(controller.running),
            "status": str(controller.status),
            "stats": controller.stats.as_dict(),
        }
        last = controller.last_log
    except Exception:
        return None
    if last is not None:
        log = last.as_dict()
        snapshot["last_run"] = {
            "profile": log.get("profile_name"),
            "started_at": log.get("started_at"),
            "ended_at": log.get("ended_at"),
            "stop_reason": log.get("stop_reason"),
            "stats": log.get("stats"),
            "error_count": len(log.get("error_messages") or []),
            "parameters": {k: v for k, v in (log.get("parameters") or {}).items() if k not in _REDACTED_PARAMETERS},
        }
    return snapshot


def _belongs_to_run(last_run: dict, run: dict | None, tolerance: float = 5.0) -> bool:
    """The controller's last run log is only the dashboard's current run if profile and start agree."""
    if not run or last_run.get("profile") != run.get("profile"):
        return False
    try:
        started = datetime.fromisoformat(str(last_run.get("started_at"))).timestamp()
        return abs(started - float(run.get("started"))) <= tolerance
    except (TypeError, ValueError):
        return False


def build_analysis_context(
    run: dict | None,
    view: ReceiverView | None,
    generator: dict[str, Any] | None = None,
    *,
    models_dir: Path = MODELS_DIR,
    validation_report_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Everything the assistant may rely on; missing pieces are ``None`` and listed in ``unavailable``."""
    view = view or ReceiverView()
    unavailable: list[str] = []

    current_run = None
    if run:
        current_run = {
            "selected_attack_profile": run.get("profile"),
            "started_at": _iso(run.get("started")),
            "ended_at": _iso(run.get("ended")),
            "state": "running" if run.get("ended") is None else "finished",
        }
    else:
        unavailable.append("No attack/traffic run has been launched in this dashboard session yet.")

    verdict = verdict_summary(view.verdict) if view.verdict else None
    if run and verdict is None:
        unavailable.append("No final session verdict has been logged by the receiver for this run yet.")

    displayed = None
    primary = view.primary
    if primary is not None:
        displayed = {
            "status": "FINAL" if view.verdict else "LIVE (analysing, no verdict yet)",
            "attack": primary.get("displayed_attack") or primary.get("predicted_class"),
            "confidence": _round(primary.get("confidence")),
            "probability_bars": _probabilities(primary.get("probabilities")),
            # Exactly the pill the dashboard renders (streamlit_app._result_card uses ReceiverView.fabricated).
            "source_label_shown": "Fetching Results" if view.fabricated else REAL_ML,
            "is_synthetic": _is_synthetic(primary),
        }
    elif run:
        unavailable.append("The receiver has not classified any flows for this run yet.")

    detections = None
    if view.flows:
        detections = {
            "summary": _detections_summary(view.flows),
            "recent_flows_newest_first": [flow_summary(r) for r in view.flows[:MAX_RECENT_FLOWS]],
        }

    evaluation = offline_evaluation(models_dir)
    if evaluation is None:
        unavailable.append("Offline model evaluation artifacts could not be read from models/.")

    validation = live_validation_report(validation_report_path)

    if generator and generator.get("last_run") and not _belongs_to_run(generator["last_run"], run):
        generator = {k: v for k, v in generator.items() if k != "last_run"}

    unavailable.append(
        "No per-prediction feature attribution (SHAP, LIME or similar) is produced by this application, "
        "and per-flow 24-feature values are not logged; only flow-level statistics are available."
    )

    return {
        "schema": CONTEXT_SCHEMA,
        "generated_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "live_analysis_available": bool(run and (verdict or detections)),
        "pipeline": {
            "stages": list(PIPELINE_STAGES),
            "model": "XGBoost multi-class IDS",
            "classes": evaluation["metrics"].get("classes") if evaluation else None,
            "lab_target": "loopback lab target (attacker and receiver on the same PC)",
        },
        "current_run": current_run,
        "traffic_generator": generator,
        "dashboard_detection_card": displayed,
        "session_verdict": verdict,
        "flow_detections": detections,
        "offline_model_evaluation": evaluation,
        "live_validation_report": validation,
        "explainability": {
            "feature_attribution_available": False,
            "available_evidence": [
                "class probability distribution per flow and per session",
                "flow statistics (packets, bytes, duration, first TCP flags, ports)",
                "offline per-class metrics and confusion matrix",
            ],
        },
        "unavailable": unavailable,
    }


def context_overview(context: dict[str, Any]) -> str:
    """One-line description of what the assistant can currently see (for the UI)."""
    run = context.get("current_run")
    metrics = "offline model metrics loaded" if context.get("offline_model_evaluation") else "offline metrics unavailable"
    if not run:
        return f"No run launched yet · {metrics}"
    flows = (context.get("flow_detections") or {}).get("summary", {}).get("flow_count", 0)
    state = "final verdict" if context.get("session_verdict") else "no verdict yet"
    return f'Run: {run["selected_attack_profile"]} ({run["state"]}) · {flows} flow(s) · {state} · {metrics}'
