"""
Markdown XAI analysis report saved beside the project's other generated reports.

Tables are copied from the analysis context; the narrative sections are written by
the LLM under the same grounding rules as the chatbot. If the LLM is unavailable the
report is still produced with those sections marked as unavailable.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from demo_fallback.fallback import REAL_ML
from xai_assistant.assistant import system_instruction
from xai_assistant.llm import GeminiClient, LLMError

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
REPORT_PREFIX = "xai_analysis_report"
MAX_NAME_ATTEMPTS = 100

NARRATIVE_FIELDS = {
    "analysis_overview": "Analysis Overview",
    "findings_interpretation": "Explanation and Interpretation",
    "visualization_observations": "Observations from Visualizations",
    "limitations_and_uncertainty": "Limitations and Uncertainties",
    "conclusions": "Summary and Conclusions",
}
NARRATIVE_SCHEMA = {
    "type": "OBJECT",
    "properties": {name: {"type": "STRING"} for name in NARRATIVE_FIELDS},
    "required": list(NARRATIVE_FIELDS),
}
REPORT_TASK = """\
Write the narrative sections of a formal explanatory report about the analysis in the ANALYSIS
CONTEXT. Return JSON with these string fields, each containing Markdown (paragraphs and bullet
lists only, no headings):
- analysis_overview: what was run and what the system concluded, in 1-2 short paragraphs.
- findings_interpretation: explain the predictions, probabilities, flow statistics and session
  verdict; separate observed evidence, model predictions, interpretation and unsupported conclusions.
- visualization_observations: what the dashboard detection card, probability bars, flow cards and
  recent-flow table show, and what the offline confusion matrix and per-class metrics indicate.
- limitations_and_uncertainty: data and model limitations, uncertainty, synthetic display results,
  missing feature attribution, and why a prediction does not prove an attack.
- conclusions: a balanced overall summary and the conclusions the evidence supports.
Use only numbers present in the context. If no live run is available, say so and focus on the
offline model evaluation.
"""


@dataclass(frozen=True)
class ReportResult:
    path: Path
    markdown: str
    narrative_error: str | None = None

    @property
    def filename(self) -> str:
        return self.path.name


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        value = f"{value:.4f}"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return "—"


def _unavailable(reason: str) -> str:
    return f"_Not available: {reason}_"


def request_narrative(context: Mapping[str, Any], client: GeminiClient) -> dict[str, str]:
    raw = client.generate(
        system_instruction(context),
        [{"role": "user", "content": REPORT_TASK}],
        temperature=0.2,
        max_output_tokens=8192,
        response_schema=NARRATIVE_SCHEMA,
    )
    try:
        data = json.loads(raw)
    except ValueError:
        return {"findings_interpretation": raw}
    if not isinstance(data, dict):
        return {"findings_interpretation": raw}
    return {k: str(data[k]).strip() for k in NARRATIVE_FIELDS if data.get(k)}


def _narrative(narrative: Mapping[str, str], key: str, missing: str) -> str:
    return narrative.get(key) or _unavailable(missing)


def _input_section(context: Mapping[str, Any]) -> str:
    run = context.get("current_run")
    if not run:
        return _unavailable("no attack/traffic run was launched in this dashboard session.")
    parts = [
        _table(
            ["Item", "Value"],
            [
                ["Selected attack profile", run.get("selected_attack_profile")],
                ["Run state", run.get("state")],
                ["Started (UTC)", run.get("started_at")],
                ["Ended (UTC)", run.get("ended_at")],
                ["Target", (context.get("pipeline") or {}).get("lab_target")],
            ],
        )
    ]
    generator = context.get("traffic_generator") or {}
    last = generator.get("last_run")
    if last:
        parts.append("**Traffic generator parameters (laboratory, rate-limited)**\n\n" + _table(
            ["Parameter", "Value"], [[k, v] for k, v in (last.get("parameters") or {}).items()]))
        parts.append("**Traffic generator statistics**\n\n" + _table(
            ["Counter", "Value"],
            [[k, v] for k, v in (last.get("stats") or {}).items()] + [["stop_reason", last.get("stop_reason")]],
        ))
    else:
        parts.append(_unavailable("the traffic generator run log for this run has not been written yet."))
    summary = (context.get("flow_detections") or {}).get("summary")
    if summary:
        parts.append("**Captured flows classified by the receiver**\n\n" + _table(
            ["Measure", "Value"],
            [
                ["Flows classified", summary.get("flow_count")],
                ["Total packets in those flows", summary.get("total_packets")],
                ["Flows whose dashboard display was synthetic", summary.get("flows_with_synthetic_display")],
            ],
        ))
    return "\n\n".join(parts)


def _config_section(context: Mapping[str, Any]) -> str:
    pipeline = context.get("pipeline") or {}
    evaluation = context.get("offline_model_evaluation") or {}
    metrics = evaluation.get("metrics") or {}
    lines = ["**Pipeline stages**", ""] + [f"{i}. {s}" for i, s in enumerate(pipeline.get("stages") or [], 1)]
    lines += [
        "",
        _table(
            ["Item", "Value"],
            [
                ["Model", metrics.get("model") or pipeline.get("model")],
                ["Classes", ", ".join(pipeline.get("classes") or []) or None],
                ["Number of input features", metrics.get("num_features")],
                ["Best boosting iteration", metrics.get("best_iteration")],
            ],
        ),
    ]
    features = evaluation.get("input_features")
    if features:
        lines += ["", "**Input features:** " + ", ".join(f"`{f}`" for f in features)]
    verdict = context.get("session_verdict")
    if verdict:
        lines += ["", f"**Session verdict rule:** {verdict.get('reliability_rule')}"]
    return "\n".join(lines)


def _probability_rows(*named: tuple[str, Mapping[str, float] | None]) -> tuple[list[str], list[list[Any]]]:
    present = [(name, probs) for name, probs in named if probs]
    classes: list[str] = []
    for _, probs in present:
        classes += [c for c in probs if c not in classes]
    headers = ["Class"] + [name for name, _ in present]
    return headers, [[c] + [_pct(probs.get(c)) for _, probs in present] for c in classes]


def _predictions_section(context: Mapping[str, Any]) -> str:
    parts: list[str] = []
    card = context.get("dashboard_detection_card")
    if card:
        parts.append("**Dashboard detection card**\n\n" + _table(
            ["Item", "Value"],
            [
                ["Status", card.get("status")],
                ["Displayed attack", card.get("attack")],
                ["Displayed confidence", _pct(card.get("confidence"))],
                ["Source label shown on dashboard", card.get("source_label_shown")],
                ["Displayed values are synthetic (not model output)", "Yes" if card.get("is_synthetic") else "No"],
            ],
        ))
    verdict = context.get("session_verdict")
    if verdict:
        model = verdict.get("model_mean_probability_prediction") or {}
        parts.append("**Session verdict**\n\n" + _table(
            ["Item", "Value"],
            [
                ["Selected profile", verdict.get("selected_attack_profile")],
                ["Displayed attack", verdict.get("displayed_attack")],
                ["Displayed result is synthetic", "Yes" if verdict.get("displayed_result_is_synthetic") else "No"],
                ["Model mean-probability class", model.get("class")],
                ["Model mean-probability confidence", _pct(model.get("confidence"))],
                ["Connection-opening flows judged", verdict.get("relevant_opening_flows")],
                ["Opening flows the model matched to the selected profile",
                 verdict.get("opening_flows_where_model_matched_selected_profile")],
            ],
        ))
        headers, rows = _probability_rows(
            ("Model (genuine) probability", model.get("probabilities")),
            ("Displayed probability", verdict.get("displayed_probabilities")),
        )
        if rows:
            parts.append("**Class probabilities**\n\n" + _table(headers, rows))
    flows = (context.get("flow_detections") or {}).get("recent_flows_newest_first") or []
    if flows:
        rows = []
        for f in flows:
            model = f.get("model_prediction") or {}
            rows.append([
                f.get("recorded_at"), f.get("protocol"), f.get("source"), f.get("destination"),
                f.get("packet_count"), f.get("byte_count"), f.get("duration_seconds"),
                f.get("first_packet_tcp_flags"), model.get("class"), _pct(model.get("confidence")),
                f.get("displayed_class"), "Yes" if f.get("displayed_result_is_synthetic") else "No",
            ])
        parts.append(f"**Most recent classified flows (newest first, up to {len(flows)})**\n\n" + _table(
            ["Time (UTC)", "Proto", "Source", "Destination", "Pkts", "Bytes", "Duration s", "First flags",
             "Model class", "Model conf.", "Displayed class", "Synthetic display"],
            rows,
        ))
    return "\n\n".join(parts) or _unavailable("no predictions have been produced in this session.")


def _findings_section(context: Mapping[str, Any]) -> str:
    lines: list[str] = []
    verdict = context.get("session_verdict")
    if verdict:
        judged = verdict.get("relevant_opening_flows") or 0
        matched = verdict.get("opening_flows_where_model_matched_selected_profile") or 0
        share = f" ({matched / judged:.0%})" if judged else ""
        model = verdict.get("model_mean_probability_prediction") or {}
        lines += [
            f"- Selected traffic profile: **{verdict.get('selected_attack_profile')}**.",
            f"- The model classified {matched} of {judged} connection-opening flows as the selected profile{share}.",
            f"- Model mean-probability prediction: **{model.get('class') or 'not available'}**"
            + (f" ({_pct(model.get('confidence'))})." if model.get("confidence") is not None else "."),
        ]
        if verdict.get("displayed_result_is_synthetic"):
            shown = (context.get("dashboard_detection_card") or {}).get("source_label_shown")
            mislabelled = f' even though the dashboard label reads "{shown}"' if shown == REAL_ML else ""
            lines.append(
                "- The dashboard result for this session is a **synthetic demo display**; its class and "
                f"probabilities were not produced by the model{mislabelled}."
            )
        else:
            lines.append("- The dashboard result for this session is the genuine model output (REAL ML).")
    summary = (context.get("flow_detections") or {}).get("summary")
    if summary and summary.get("model_predicted_class_counts"):
        counts = ", ".join(f"{k}: {v}" for k, v in summary["model_predicted_class_counts"].items())
        lines.append(f"- Genuine model predictions across classified flows — {counts}.")
        if summary.get("model_confidence_mean") is not None:
            lines.append(
                f"- Model confidence across these flows: mean {_pct(summary['model_confidence_mean'])}, "
                f"min {_pct(summary['model_confidence_min'])}, max {_pct(summary['model_confidence_max'])}."
            )
    if not lines:
        return _unavailable("no live detections were recorded in this session.")
    lines.append("- These are statistical classifications of laboratory traffic, not proof that an attack occurred.")
    return "\n".join(lines)


def _metrics_section(context: Mapping[str, Any]) -> str:
    evaluation = context.get("offline_model_evaluation")
    parts: list[str] = []
    if evaluation:
        m = evaluation.get("metrics") or {}
        parts.append(f"Source: {evaluation.get('source')}.")
        keys = ["test_samples", "accuracy", "balanced_accuracy", "macro_precision", "macro_recall", "macro_f1",
                "weighted_f1", "log_loss", "roc_auc_ovr_macro", "cohen_kappa", "matthews_correlation_coefficient",
                "mean_prediction_confidence"]
        parts.append("**Overall offline metrics**\n\n" + _table(["Metric", "Value"], [[k, m.get(k)] for k in keys if k in m]))
        per_class = evaluation.get("per_class") or {}
        if per_class:
            parts.append("**Per-class offline metrics**\n\n" + _table(
                ["Class", "Precision", "Recall", "F1", "Support"],
                [[c, v.get("precision"), v.get("recall"), v.get("f1-score"),
                  int(v["support"]) if v.get("support") is not None else None] for c, v in per_class.items()],
            ))
        cm = evaluation.get("confusion_matrix")
        if cm:
            labels = cm["labels"]
            parts.append(f"**Offline confusion matrix** ({cm['orientation']})\n\n" + _table(
                ["Actual \\ Predicted"] + labels,
                [[actual] + [row.get(label) for label in labels] for actual, row in cm["rows"].items()],
            ))
    else:
        parts.append(_unavailable("offline evaluation artifacts could not be read."))
    validation = context.get("live_validation_report")
    if validation:
        parts.append(f"**Live validation report** ({validation['source']})\n\n```text\n{validation['text']}\n```")
    return "\n\n".join(parts)


def _limitations_section(context: Mapping[str, Any], narrative: Mapping[str, str], missing: str) -> str:
    known = "\n".join(f"- {item}" for item in context.get("unavailable") or [])
    body = narrative.get("limitations_and_uncertainty") or _unavailable(missing)
    return (f"**Known gaps in the available data**\n\n{known}\n\n" if known else "") + body


def build_report_markdown(
    context: Mapping[str, Any],
    narrative: Mapping[str, str] | None,
    *,
    model_name: str | None,
    narrative_error: str | None = None,
    now: datetime | None = None,
) -> str:
    now = now or datetime.now().astimezone()
    narrative = narrative or {}
    missing = f"AI narrative could not be generated ({narrative_error})" if narrative_error else "AI narrative not generated"
    provenance = (
        f"Narrative sections were generated by Google Gemini (`{model_name}`) from this session's analysis "
        "context under strict grounding rules; tables are copied directly from application data."
        if narrative else f"{missing}. Tables below are copied directly from application data."
    )
    sections = [
        ("Analysis Overview", _narrative(narrative, "analysis_overview", missing)),
        ("Dataset and Input Summary", _input_section(context)),
        ("Model and Analysis Configuration", _config_section(context)),
        ("Predictions and Classification Results", _predictions_section(context)),
        ("Attack and Anomaly Detection Findings", _findings_section(context)),
        ("Key Numerical Results and Metrics", _metrics_section(context)),
        ("Explanation and Interpretation", _narrative(narrative, "findings_interpretation", missing)),
        ("Observations from Visualizations", _narrative(narrative, "visualization_observations", missing)),
        ("Limitations and Uncertainties", _limitations_section(context, narrative, missing)),
        ("Summary and Conclusions", _narrative(narrative, "conclusions", missing)),
    ]
    header = [
        "# MLCN Explainable AI Analysis Report",
        "",
        f"- **Generated:** {now.strftime('%Y-%m-%d %H:%M:%S %Z').strip()} "
        f"({now.astimezone(timezone.utc).isoformat(timespec='seconds')})",
        f"- **Context snapshot:** {context.get('generated_at')}",
        f"- **Live analysis available:** {'Yes' if context.get('live_analysis_available') else 'No'}",
        "",
        f"> {provenance} Predictions are statistical classifications, not proof of an attack.",
    ]
    body = [f"## {i}. {title}\n\n{content}" for i, (title, content) in enumerate(sections, 1)]
    return "\n".join(header) + "\n\n" + "\n\n".join(body) + "\n"


def save_report(markdown: str, reports_dir: Path | None = None, now: datetime | None = None) -> Path:
    """Write to a new ``xai_analysis_report_YYYYMMDD_HHMMSS[_N].md``; never overwrites an existing file."""
    reports_dir = reports_dir or REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    for attempt in range(MAX_NAME_ATTEMPTS):
        suffix = f"_{attempt}" if attempt else ""
        path = reports_dir / f"{REPORT_PREFIX}_{stamp}{suffix}.md"
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(markdown)
            return path
        except FileExistsError:
            continue
    raise OSError(f"could not find a free report filename in {reports_dir}")


def generate_report(
    context: Mapping[str, Any],
    client: GeminiClient | None,
    *,
    reports_dir: Path | None = None,
    now: datetime | None = None,
) -> ReportResult:
    narrative: dict[str, str] | None = None
    error: str | None = None
    if client is None:
        error = "LLM client not configured"
    else:
        try:
            narrative = request_narrative(context, client)
        except LLMError as exc:
            error = str(exc)
    now = now or datetime.now().astimezone()
    markdown = build_report_markdown(
        context, narrative, model_name=client.model if client else None, narrative_error=error, now=now
    )
    return ReportResult(save_report(markdown, reports_dir, now), markdown, error)

