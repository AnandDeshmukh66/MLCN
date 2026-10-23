"""
Context-aware Explainable AI assistant for the MLCN dashboard.

Explains the current session's detection results with Google Gemini, grounded in
data the application already produced, and writes Markdown analysis reports to
``reports/``. Purely additive: it never re-runs or alters inference.
"""

from xai_assistant.assistant import GROUNDING_RULES, answer, system_instruction
from xai_assistant.context import build_analysis_context, context_overview, generator_snapshot
from xai_assistant.llm import GeminiClient, LLMError, LLMSettings, LLMUnavailable, load_settings
from xai_assistant.report import REPORTS_DIR, ReportResult, build_report_markdown, generate_report, save_report

__all__ = [
    "GROUNDING_RULES",
    "REPORTS_DIR",
    "GeminiClient",
    "LLMError",
    "LLMSettings",
    "LLMUnavailable",
    "ReportResult",
    "answer",
    "build_analysis_context",
    "build_report_markdown",
    "context_overview",
    "generate_report",
    "generator_snapshot",
    "load_settings",
    "save_report",
    "system_instruction",
]
