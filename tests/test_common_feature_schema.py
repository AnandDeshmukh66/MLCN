"""Unit tests for Step 8 common feature schema validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from data.common_feature_schema import (
    DEFAULT_REPORT_PATH,
    DEFAULT_SCHEMA_PATH,
    build_candidate_feature_definitions,
    build_rejected_features,
    finalize_feature_list,
    validate_schema,
    write_schema_artifacts,
)


class TestCommonFeatureSchema(unittest.TestCase):
    def test_twenty_five_candidates_defined(self) -> None:
        candidates = build_candidate_feature_definitions()
        self.assertEqual(len(candidates), 25)
        indices = [feature.candidate_index for feature in candidates]
        self.assertEqual(indices, list(range(1, 26)))

    def test_finalize_removes_duplicate_average_packet_size(self) -> None:
        candidates = build_candidate_feature_definitions()
        rejected = build_rejected_features()
        retained = finalize_feature_list(candidates, rejected)
        names = [feature.canonical_name for feature in retained]
        self.assertNotIn("Average Packet Size", names)
        self.assertIn("Packet Length Mean", names)
        self.assertEqual(len(retained), 24)

    def test_validation_passes_for_final_schema(self) -> None:
        candidates = build_candidate_feature_definitions()
        rejected = build_rejected_features()
        retained = finalize_feature_list(candidates, rejected)
        result = validate_schema(candidates, retained, rejected)
        self.assertTrue(result.passed, msg="\n".join(result.errors))
        self.assertTrue(result.derivation_probe_passed)

    def test_validation_fails_without_formula(self) -> None:
        candidates = build_candidate_feature_definitions()
        rejected = build_rejected_features()
        retained = finalize_feature_list(candidates, rejected)
        broken = replace(retained[0], formula="")
        broken_list = [broken, *retained[1:]]
        result = validate_schema(candidates, broken_list, rejected)
        self.assertFalse(result.passed)
        self.assertTrue(any("missing formula" in err for err in result.errors))

    def test_validation_fails_on_duplicate_names(self) -> None:
        candidates = build_candidate_feature_definitions()
        rejected = build_rejected_features()
        retained = finalize_feature_list(candidates, rejected)
        dup = replace(retained[1], canonical_name=retained[0].canonical_name)
        broken_list = [retained[0], dup, *retained[2:]]
        result = validate_schema(candidates, broken_list, rejected)
        self.assertFalse(result.passed)
        self.assertTrue(any("duplicate" in err for err in result.errors))

    def test_validation_fails_without_edge_cases(self) -> None:
        candidates = build_candidate_feature_definitions()
        rejected = build_rejected_features()
        retained = finalize_feature_list(candidates, rejected)
        broken = replace(retained[0], edge_case_rules={})
        broken_list = [broken, *retained[1:]]
        result = validate_schema(candidates, broken_list, rejected)
        self.assertFalse(result.passed)
        self.assertTrue(any("edge-case" in err for err in result.errors))

    def test_schema_artifacts_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema_a = root / "schema_a.json"
            report_a = root / "report_a.md"
            schema_b = root / "schema_b.json"
            report_b = root / "report_b.md"

            write_schema_artifacts(schema_a, report_a)
            write_schema_artifacts(schema_b, report_b)

            self.assertEqual(schema_a.read_text(), schema_b.read_text())
            self.assertEqual(report_a.read_text(), report_b.read_text())

    def test_write_schema_artifacts_default_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "common_feature_schema.json"
            report_path = Path(tmp) / "common_feature_schema_report.md"
            schema, validation = write_schema_artifacts(schema_path, report_path)
            self.assertTrue(validation.passed)
            self.assertTrue(schema_path.is_file())
            self.assertTrue(report_path.is_file())
            loaded = json.loads(schema_path.read_text())
            self.assertEqual(loaded["schema_version"], schema["schema_version"])
            self.assertEqual(len(loaded["feature_order"]), 24)


class TestStep8Script(unittest.TestCase):
    def test_script_main_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / DEFAULT_SCHEMA_PATH.name
            report_path = Path(tmp) / DEFAULT_REPORT_PATH.name
            from data.common_feature_schema import main

            code = main(
                [
                    f"--schema={schema_path}",
                    f"--report={report_path}",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(schema_path.exists())
            self.assertTrue(report_path.exists())


if __name__ == "__main__":
    unittest.main()
