"""XAI assistant: context building, grounding prompt, Gemini wrapper, Markdown reports and dashboard panel."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from google.genai import errors as genai_errors
from streamlit.testing.v1 import AppTest

from demo_fallback import FABRICATED, REAL_ML, session_result
from demo_fallback.session import SESSION_FILE_ENV
from ml_detection import CLASS_ORDER, DetectionResult
from traffic_generator.dashboard_data import build_view
from traffic_generator.traffic_profile import GeneratorRunLog, GeneratorStats
from xai_assistant import (
    GROUNDING_RULES,
    GeminiClient,
    LLMError,
    LLMSettings,
    LLMUnavailable,
    answer,
    build_analysis_context,
    build_report_markdown,
    generate_report,
    generator_snapshot,
    load_settings,
    save_report,
    system_instruction,
)
from xai_assistant import report as report_module
from xai_assistant.assistant import conversation_messages

APP = str(Path(__file__).resolve().parents[1] / "traffic_generator" / "streamlit_app.py")
FAKE_KEY = "test-key-not-real-123"


def _detection(name: str, top: float = 0.96) -> DetectionResult:
    probs = {c: (1.0 - top) / 4 for c in CLASS_ORDER}
    probs[name] = top
    return DetectionResult.from_probability_mapping(probs)


def _flow(at: float, displayed: str, genuine: str, *, synthetic: bool, ip: str = "192.168.1.20") -> dict:
    shown, real = _detection(displayed), _detection(genuine, 0.88)
    return {
        "recorded_at": at, "protocol": "TCP", "src_ip": ip, "dst_ip": "127.0.0.1", "src_port": 50001,
        "dst_port": 8080, "packet_count": 7, "byte_count": 640, "duration": 0.42, "start_time": at,
        "first_packet_flags": "S", "predicted_class": displayed, "confidence": shown.confidence,
        "probabilities": dict(shown.probabilities), "demo_fallback": synthetic,
        "genuine_predicted_class": genuine, "genuine_confidence": real.confidence,
        "genuine_probabilities": dict(real.probabilities),
        "result_source": FABRICATED if synthetic else REAL_ML,
    }


def _context_with_run(synthetic: bool = True) -> dict:
    started = 1_000.0
    genuine = [_detection("BENIGN")] * 3 + [_detection("DDoS")]
    verdict = session_result("DDoS", genuine).as_dict()
    verdict["recorded_at"] = started + 30
    if not synthetic:
        verdict = session_result("DDoS", [_detection("DDoS")] * 5).as_dict()
        verdict["recorded_at"] = started + 30
    flows = [_flow(started + 1, "DDoS", "BENIGN", synthetic=synthetic), _flow(started + 2, "DDoS", "DDoS", synthetic=False)]
    view = build_view(flows + [verdict])
    run = {"profile": "DDoS", "started": started, "since": started - 1, "ended": started + 25}
    return build_analysis_context(run, view, None, validation_report_path=Path("/nonexistent/report.txt"))


class FakeClient:
    """Stands in for GeminiClient; records calls, never touches the network."""

    def __init__(self, reply: str = "Grounded answer.", error: Exception | None = None) -> None:
        self.reply, self.error, self.calls = reply, error, []
        self.settings = LLMSettings(api_key=FAKE_KEY)
        self.model = "fake-model"

    def generate(self, system: str, messages, **kwargs) -> str:
        self.calls.append({"system": system, "messages": [dict(m) for m in messages], **kwargs})
        if self.error:
            raise self.error
        return self.reply


class TestContext(unittest.TestCase):
    def test_no_run_reports_unavailable_but_keeps_offline_metrics(self) -> None:
        ctx = build_analysis_context(None, None)
        self.assertFalse(ctx["live_analysis_available"])
        self.assertIsNone(ctx["current_run"])
        self.assertIsNone(ctx["session_verdict"])
        self.assertTrue(any("No attack" in u for u in ctx["unavailable"]))
        evaluation = ctx["offline_model_evaluation"]
        self.assertAlmostEqual(evaluation["metrics"]["accuracy"], 0.994238, places=5)
        self.assertEqual(evaluation["confusion_matrix"]["rows"]["BENIGN"]["Brute Force"], 799)
        self.assertEqual(len(evaluation["input_features"]), 24)
        self.assertFalse(ctx["explainability"]["feature_attribution_available"])
        json.dumps(ctx)  # serializable

    def test_synthetic_display_is_flagged_and_genuine_prediction_kept(self) -> None:
        ctx = _context_with_run(synthetic=True)
        self.assertTrue(ctx["live_analysis_available"])
        verdict = ctx["session_verdict"]
        self.assertTrue(verdict["displayed_result_is_synthetic"])
        self.assertEqual(verdict["selected_attack_profile"], "DDoS")
        self.assertEqual(verdict["opening_flows_where_model_matched_selected_profile"], 1)
        self.assertEqual(verdict["model_mean_probability_prediction"]["class"], "BENIGN")
        self.assertTrue(ctx["dashboard_detection_card"]["is_synthetic"])
        summary = ctx["flow_detections"]["summary"]
        self.assertEqual(summary["model_predicted_class_counts"], {"DDoS": 1, "BENIGN": 1})
        self.assertEqual(summary["flows_with_synthetic_display"], 1)

    def test_real_result_not_flagged(self) -> None:
        ctx = _context_with_run(synthetic=False)
        self.assertFalse(ctx["session_verdict"]["displayed_result_is_synthetic"])
        self.assertFalse(ctx["dashboard_detection_card"]["is_synthetic"])
        self.assertEqual(ctx["dashboard_detection_card"]["source_label_shown"], REAL_ML)

    def test_source_label_mirrors_dashboard_even_when_values_are_synthetic(self) -> None:
        verdict = session_result("DoS", []).as_dict()
        verdict["recorded_at"] = 5.0
        view = build_view([verdict])
        card = build_analysis_context({"profile": "DoS", "started": 1.0, "since": 0, "ended": 4.0}, view)[
            "dashboard_detection_card"]
        self.assertTrue(card["is_synthetic"])
        self.assertEqual(card["source_label_shown"], "Fetching Results" if view.fabricated else REAL_ML)

    def test_ip_addresses_are_reduced_to_address_class(self) -> None:
        text = json.dumps(_context_with_run())
        self.assertNotIn("192.168.1.20", text)
        self.assertNotIn("127.0.0.1", text)
        self.assertIn("private-lan:50001", text)
        self.assertIn("loopback:8080", text)

    def test_generator_snapshot_redacts_host_and_drops_stale_run(self) -> None:
        started = datetime(2026, 10, 1, tzinfo=timezone.utc)
        log = GeneratorRunLog("DoS", "127.0.0.1:8080", started, parameters={"target_host": "127.0.0.1", "intensity": 0.5})
        ctrl = SimpleNamespace(running=False, status="Finished", stats=GeneratorStats(packets_sent=9), last_log=log)
        snap = generator_snapshot(ctrl)
        self.assertEqual(snap["last_run"]["parameters"], {"intensity": 0.5})
        self.assertEqual(snap["stats"]["packets_sent"], 9)
        current = {"profile": "DoS", "started": started.timestamp() + 0.2, "since": 0, "ended": None}
        self.assertIn("last_run", build_analysis_context(current, None, snap)["traffic_generator"])
        stale = {**current, "started": started.timestamp() + 600}
        self.assertNotIn("last_run", build_analysis_context(stale, None, snap)["traffic_generator"])


class TestAssistant(unittest.TestCase):
    def test_system_instruction_contains_rules_and_context(self) -> None:
        ctx = _context_with_run()
        text = system_instruction(ctx)
        self.assertIn(GROUNDING_RULES, text)
        self.assertIn("<analysis_context>", text)
        self.assertIn('"displayed_result_is_synthetic": true', text)
        for phrase in ("Never invent metrics", "untrusted data", "not proof", "SHAP"):
            self.assertIn(phrase, GROUNDING_RULES)

    def test_follow_up_sends_previous_successful_turns(self) -> None:
        client = FakeClient("Follow-up answer.")
        history = [
            {"role": "user", "content": "What happened?"},
            {"role": "assistant", "content": "A DDoS run."},
            {"role": "user", "content": "broken", "error": True},
            {"role": "assistant", "content": "API failed", "error": True},
        ]
        self.assertEqual(answer("Why?", history, {"x": 1}, client), "Follow-up answer.")
        sent = client.calls[0]["messages"]
        self.assertEqual([m["content"] for m in sent], ["What happened?", "A DDoS run.", "Why?"])
        self.assertIn('"x": 1', client.calls[0]["system"])

    def test_history_is_bounded_and_starts_with_user(self) -> None:
        history = [{"role": "user" if i % 2 == 0 else "assistant", "content": f"m{i}" * 3000} for i in range(40)]
        turns = conversation_messages(history)
        self.assertLessEqual(len(turns), 12)
        self.assertEqual(turns[0]["role"], "user")
        self.assertTrue(all(len(t["content"]) <= 4000 for t in turns))

    def test_empty_question_rejected(self) -> None:
        with self.assertRaises(ValueError):
            answer("   ", [], {}, FakeClient())


class TestGeminiClient(unittest.TestCase):
    def test_settings_from_env_and_key_hidden_from_repr(self) -> None:
        settings = load_settings({"GEMINI_API_KEY": FAKE_KEY, "MLCN_LLM_MODEL": "m", "MLCN_LLM_TIMEOUT_SECONDS": "999",
                                  "MLCN_LLM_MAX_RETRIES": "50"})
        self.assertEqual(settings.model, "m")
        self.assertEqual(settings.timeout_seconds, 300.0)
        self.assertEqual(settings.max_retries, 3)
        self.assertNotIn(FAKE_KEY, repr(settings))
        self.assertFalse(load_settings({}).configured)

    def test_missing_key_is_unavailable(self) -> None:
        with self.assertRaises(LLMUnavailable):
            GeminiClient(load_settings({})).generate("sys", [{"role": "user", "content": "hi"}])

    def _client_raising(self, exc: Exception) -> GeminiClient:
        client = GeminiClient(LLMSettings(api_key=FAKE_KEY, model="m"))
        sdk = MagicMock()
        sdk.models.generate_content.side_effect = exc
        client._client = sdk
        return client

    def test_api_errors_map_to_safe_messages(self) -> None:
        cases = {
            429: "rate limit",
            403: "rejected the credentials",
            404: "model was not found",
            503: "temporarily unavailable",
        }
        for code, phrase in cases.items():
            cls = genai_errors.ServerError if code >= 500 else genai_errors.ClientError
            error = cls(code, {"error": {"code": code, "message": f"bad key {FAKE_KEY}", "status": "X"}})
            with self.assertRaises(LLMError) as caught:
                self._client_raising(error).generate("sys", [{"role": "user", "content": "hi"}])
            self.assertIn(phrase, str(caught.exception))
            self.assertNotIn(FAKE_KEY, str(caught.exception))

    def test_timeout_and_network_errors(self) -> None:
        class ReadTimeout(Exception):
            pass

        with self.assertRaisesRegex(LLMError, "did not respond"):
            self._client_raising(ReadTimeout()).generate("s", [{"role": "user", "content": "q"}])
        with self.assertRaisesRegex(LLMError, "Could not reach"):
            self._client_raising(ConnectionError("dns")).generate("s", [{"role": "user", "content": "q"}])

    def test_roles_mapped_and_empty_reply_rejected(self) -> None:
        client = self._client_raising(None)
        client._client.models.generate_content.side_effect = None
        client._client.models.generate_content.return_value = SimpleNamespace(text="  ok ")
        reply = client.generate("sys", [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}])
        self.assertEqual(reply, "ok")
        kwargs = client._client.models.generate_content.call_args.kwargs
        self.assertEqual([c.role for c in kwargs["contents"]], ["user", "model"])
        self.assertEqual(kwargs["config"].system_instruction, "sys")
        client._client.models.generate_content.return_value = SimpleNamespace(text=None)
        with self.assertRaisesRegex(LLMError, "empty response"):
            client.generate("sys", [{"role": "user", "content": "a"}])


class TestReport(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())

    def test_report_saved_with_real_values_and_narrative(self) -> None:
        narrative = {k: f"Narrative for {k}." for k in report_module.NARRATIVE_FIELDS}
        client = FakeClient(json.dumps(narrative))
        result = generate_report(_context_with_run(), client, reports_dir=self.dir)
        self.assertEqual(result.path.parent, self.dir)
        self.assertRegex(result.filename, r"^xai_analysis_report_\d{8}_\d{6}\.md$")
        text = result.path.read_text(encoding="utf-8")
        self.assertEqual(text, result.markdown)
        self.assertIsNone(result.narrative_error)
        self.assertIn("# MLCN Explainable AI Analysis Report", text)
        for i, title in enumerate(["Analysis Overview", "Dataset and Input Summary", "Summary and Conclusions"]):
            self.assertRegex(text, rf"## \d+\. {title}")
        self.assertIn("Narrative for conclusions.", text)
        self.assertIn("0.9942", text)  # offline accuracy from models/
        self.assertIn("| BENIGN | 208300 | 799 |", text)  # confusion matrix row
        self.assertIn("synthetic demo display", text)
        self.assertIn("The model classified 1 of 4 connection-opening flows", text)
        self.assertNotIn("192.168.1.20", text)
        self.assertEqual(client.calls[0]["response_schema"], report_module.NARRATIVE_SCHEMA)

    def test_llm_failure_still_saves_report_with_marked_sections(self) -> None:
        result = generate_report(_context_with_run(), FakeClient(error=LLMError("service down")), reports_dir=self.dir)
        self.assertEqual(result.narrative_error, "service down")
        text = result.path.read_text(encoding="utf-8")
        self.assertIn("_Not available: AI narrative could not be generated (service down)_", text)
        self.assertIn("| BENIGN | 208300 | 799 |", text)

    def test_no_run_report_marks_live_sections_unavailable(self) -> None:
        text = build_report_markdown(build_analysis_context(None, None), None, model_name=None)
        self.assertIn("no attack/traffic run was launched", text)
        self.assertIn("**Live analysis available:** No", text)

    def test_never_overwrites_existing_reports(self) -> None:
        now = datetime(2026, 10, 24, 1, 2, 3)
        existing = self.dir / "xai_analysis_report_20261024_010203.md"
        existing.write_text("keep me", encoding="utf-8")
        first = save_report("one", self.dir, now)
        second = save_report("two", self.dir, now)
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me")
        self.assertEqual(first.name, "xai_analysis_report_20261024_010203_1.md")
        self.assertEqual(second.name, "xai_analysis_report_20261024_010203_2.md")
        self.assertEqual(first.read_text(encoding="utf-8"), "one")

    def test_default_directory_is_existing_reports_folder(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(report_module.REPORTS_DIR, root / "reports")
        self.assertTrue((root / "reports" / "MLCN_Final_Mini_Project_Report.pdf").exists())


class TestXaiPanel(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        env = patch.dict(os.environ, {SESSION_FILE_ENV: str(self.dir / "demo_session.json"), "GEMINI_API_KEY": FAKE_KEY})
        env.start()
        self.addCleanup(env.stop)

    def _app(self) -> AppTest:
        return AppTest.from_file(APP, default_timeout=30).run()

    def _text(self, app: AppTest) -> str:
        return " ".join(str(m.value) for m in app.markdown)

    def test_panel_renders_without_touching_existing_controls(self) -> None:
        app = self._app()
        self.assertFalse(app.exception)
        self.assertIn("XAI ASSISTANT", self._text(app))
        self.assertEqual(app.button[0].label, "▶  LAUNCH ATTACK")
        self.assertEqual(len(app.chat_input), 1)
        self.assertIn("No run launched yet", " ".join(c.value for c in app.caption))

    def test_chat_answers_persist_and_follow_ups_include_history(self) -> None:
        replies = iter(["First grounded answer.", "Second answer."])
        with patch("xai_assistant.llm.GeminiClient.generate", side_effect=lambda *a, **k: next(replies)) as gen:
            app = self._app()
            app.chat_input[0].set_value("What happened in this analysis?").run()
            self.assertFalse(app.exception)
            self.assertIn("First grounded answer.", self._text(app))
            app.run()  # ordinary rerun keeps the conversation
            self.assertIn("First grounded answer.", self._text(app))
            self.assertEqual(gen.call_count, 1)
            app.chat_input[0].set_value("And why?").run()
        self.assertEqual(gen.call_count, 2)
        messages = gen.call_args.args[1]
        self.assertEqual([m["content"] for m in messages],
                         ["What happened in this analysis?", "First grounded answer.", "And why?"])
        self.assertIn("No attack/traffic run has been launched", gen.call_args.args[0])
        self.assertEqual(len(app.session_state["xai_messages"]), 4)

    def test_api_failure_shown_without_crash_and_clear_chat(self) -> None:
        with patch("xai_assistant.llm.GeminiClient.generate", side_effect=LLMError("Gemini is down.")):
            app = self._app()
            app.chat_input[0].set_value("Explain").run()
        self.assertFalse(app.exception)
        self.assertIn("Gemini is down.", " ".join(e.value for e in app.error))
        clear = next(b for b in app.button if b.label == "Clear chat")
        clear.click().run()
        self.assertEqual(app.session_state["xai_messages"], [])

    def test_missing_key_reports_not_configured(self) -> None:
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}), patch("xai_assistant.llm.load_env_file"):
            app = self._app()
            self.assertIn("LLM not configured", " ".join(c.value for c in app.caption))
            app.chat_input[0].set_value("Explain").run()
        self.assertFalse(app.exception)
        self.assertIn("No Gemini API key configured", " ".join(e.value for e in app.error))

    def test_generate_report_saves_to_reports_dir_and_offers_download(self) -> None:
        narrative = json.dumps({k: "Grounded narrative." for k in report_module.NARRATIVE_FIELDS})
        with patch.object(report_module, "REPORTS_DIR", self.dir), \
                patch("xai_assistant.llm.GeminiClient.generate", return_value=narrative):
            app = self._app()
            next(b for b in app.button if b.label == "Generate report").click().run()
        self.assertFalse(app.exception)
        files = list(self.dir.glob("xai_analysis_report_*.md"))
        self.assertEqual(len(files), 1)
        self.assertIn("Grounded narrative.", files[0].read_text(encoding="utf-8"))
        self.assertIn(files[0].name, " ".join(s.value for s in app.success))
        self.assertEqual(app.session_state["xai_report"]["filename"], files[0].name)

    def test_context_follows_launched_run(self) -> None:
        log = self.dir / "detections.jsonl"
        with patch("traffic_generator.controller.TrafficGeneratorController.start"), \
                patch("xai_assistant.llm.GeminiClient.generate", return_value="ok") as gen:
            app = self._app()
            app.radio[0].set_value("DDoS").run()
            app.button[0].click().run()
            run = app.session_state["run"]
            verdict = session_result("DDoS", [_detection("DDoS")] * 5).as_dict()
            verdict["recorded_at"] = run["started"] + 1
            log.write_text(json.dumps(verdict) + "\n", encoding="utf-8")
            app.chat_input[0].set_value("Explain the current prediction.").run()
        system = gen.call_args.args[0]
        self.assertIn('"selected_attack_profile": "DDoS"', system)
        self.assertIn('"displayed_result_is_synthetic": false', system)
        self.assertNotIn(FAKE_KEY, system)


if __name__ == "__main__":
    unittest.main()
