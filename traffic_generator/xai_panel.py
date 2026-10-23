"""XAI assistant section of the MLCN console: grounded chat about the current run and Markdown reports."""

from __future__ import annotations

from typing import Any

import streamlit as st

from traffic_generator.dashboard_data import ReceiverView, receiver_view
from xai_assistant import (
    GeminiClient,
    LLMError,
    answer,
    build_analysis_context,
    context_overview,
    generate_report,
    generator_snapshot,
)
from xai_assistant.assistant import MAX_QUESTION_CHARS

CHAT_HEIGHT = 420
EXAMPLE_QUESTIONS = (
    "What happened in this analysis?",
    "Explain the current prediction.",
    "Why was this traffic classified as suspicious?",
    "What does the confusion matrix mean?",
    "Explain the model performance.",
)

CSS = """
<style>
div[data-testid="stChatMessage"] { background:var(--panel); border:1px solid var(--line); border-radius:10px;
        padding:.55rem .75rem; }
div[data-testid="stChatMessage"] p, div[data-testid="stChatMessage"] li,
div[data-testid="stChatMessage"] td, div[data-testid="stChatMessage"] th { color:var(--text); font-size:.84rem; }
div[data-testid="stChatInput"] > div { background:var(--panel); border:1px solid var(--line); }
div[data-testid="stChatInput"] textarea { color:var(--text); }
div[data-testid="stDownloadButton"] button { width:100%; border-radius:8px; border:1px solid var(--accent);
        background:var(--accent-dim); color:var(--accent); }
</style>
"""


def _html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def _init_state() -> None:
    st.session_state.setdefault("xai_messages", [])  # [{"role", "content", "error"?}]
    st.session_state.setdefault("xai_report", None)  # {"path", "filename", "markdown", "warning"}
    if "xai_client" not in st.session_state:
        st.session_state.xai_client = GeminiClient()


def _clear_chat() -> None:
    st.session_state.xai_messages = []


def _current_context(ctrl: Any) -> dict:
    run = st.session_state.get("run")
    try:
        view = receiver_view(run["since"]) if run else ReceiverView()
    except Exception:
        view = ReceiverView()
    return build_analysis_context(run, view, generator_snapshot(ctrl))


def _render(message: dict) -> None:
    with st.chat_message(message["role"]):
        if message.get("error"):
            st.error(message["content"])
        else:
            st.markdown(message["content"])


def _ask(prompt: str, context: dict, client: GeminiClient, box: Any) -> None:
    history = list(st.session_state.xai_messages)
    question = {"role": "user", "content": prompt.strip()[:MAX_QUESTION_CHARS]}
    with box:
        _render(question)
        with st.chat_message("assistant"):
            # Spinner and reply share one slot so the bubble's layout matches _render on later reruns.
            slot = st.empty()
            with slot, st.spinner("Analysing the current results…"):
                try:
                    reply = {"role": "assistant", "content": answer(question["content"], history, context, client)}
                except LLMError as exc:
                    reply = {"role": "assistant", "content": str(exc), "error": True}
                except Exception as exc:
                    reply = {"role": "assistant", "content": f"Unexpected assistant error ({type(exc).__name__}).",
                             "error": True}
                if reply.get("error"):
                    question["error"] = True
                # Stored before the next Streamlit call so an interrupting rerun cannot drop the reply.
                st.session_state.xai_messages = history + [question, reply]
            if reply.get("error"):
                slot.error(reply["content"])
            else:
                slot.markdown(reply["content"])


def _make_report(context: dict, client: GeminiClient) -> None:
    try:
        with st.spinner("Generating the XAI analysis report…"):
            result = generate_report(context, client if client.settings.configured else None)
    except OSError as exc:
        st.session_state.xai_report = {"error": f"Could not save the report: {exc.strerror or type(exc).__name__}"}
        return
    st.session_state.xai_report = {
        "path": str(result.path),
        "filename": result.filename,
        "markdown": result.markdown,
        "warning": result.narrative_error,
    }


@st.fragment
def xai_panel(ctrl: Any) -> None:
    _init_state()
    _html(CSS)
    _html('<div class="panel-title">XAI ASSISTANT · EXPLAINABLE ANALYSIS</div>')
    client: GeminiClient = st.session_state.xai_client
    context = _current_context(ctrl)
    llm = f"Gemini · {client.model}" if client.settings.configured else "LLM not configured (set GEMINI_API_KEY in .env)"
    st.caption(f"{context_overview(context)} · {llm}")

    messages = st.session_state.xai_messages
    box = st.container(height=CHAT_HEIGHT, border=True)
    with box:
        intro = st.empty()
        if not messages:
            examples = "".join(f"<li>{q}</li>" for q in EXAMPLE_QUESTIONS)
            intro.markdown(
                '<div class="sub" style="letter-spacing:.04em">Ask about the current run, its predictions and '
                "the model's evaluation. Answers are grounded in this session's results.<ul>"
                f"{examples}</ul></div>",
                unsafe_allow_html=True,
            )
        for message in messages:
            _render(message)

    prompt = st.chat_input("Ask about the current analysis…", key="xai_prompt", max_chars=MAX_QUESTION_CHARS)
    c1, c2, c3 = st.columns([1, 1, 2])
    c1.button("Clear chat", key="xai_clear", on_click=_clear_chat)
    make_report = c2.button("Generate report", key="xai_generate_report")

    if prompt:
        intro.empty()
        _ask(prompt, context, client, box)
    if make_report:
        _make_report(context, client)

    report = st.session_state.xai_report
    if report and report.get("error"):
        st.error(report["error"])
    elif report:
        c3.download_button(
            "Download Markdown report",
            data=report["markdown"],
            file_name=report["filename"],
            mime="text/markdown",
            key="xai_download",
        )
        st.success(f"Report saved: {report['path']}")
        if report.get("warning"):
            st.warning(f"Report saved without the AI narrative: {report['warning']}")
