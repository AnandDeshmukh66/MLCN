"""Unit and real-model inference tests for Module 5 ML Detection Engine."""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from feature_engineering import FEATURE_ORDER, FeatureVector
from ml_detection import (
    CLASS_ORDER,
    DEFAULT_FEATURES_META_PATH,
    DEFAULT_MODEL_PATH,
    DetectionResult,
    FeatureValidationError,
    MLDetectionEngine,
    ModelLoadError,
)

# High-confidence, correctly labeled rows taken from
# models/xgboost_test_predictions.csv for live booster validation.
_CLASS_SAMPLES: dict[str, tuple[float, ...]] = {
    "BENIGN": (
        183.0,
        2.0,
        2.0,
        76.0,
        132.0,
        38.0,
        66.0,
        1136612.022,
        21857.9235,
        61.0,
        66.12110102,
        47.0,
        3.0,
        49.2,
        15.33623161,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ),
    "Brute Force": (
        233.0,
        2.0,
        1.0,
        14.0,
        0.0,
        7.0,
        0.0,
        60085.83691,
        12875.53648,
        116.5,
        51.61879503,
        233.0,
        0.0,
        7.0,
        8.082903769,
        0.0,
        1.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    "DDoS": (
        179133.0,
        3.0,
        5.0,
        26.0,
        11607.0,
        8.666666667,
        2321.4,
        64940.57488,
        44.65955463,
        25590.42857,
        67332.67383,
        318.0,
        44771.75,
        1292.555556,
        2650.585648,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ),
    "DoS": (
        97363516.0,
        6.0,
        6.0,
        369.0,
        11595.0,
        61.5,
        1932.5,
        122.8797037,
        0.123249452,
        8851228.727,
        29400000.0,
        19500000.0,
        1040.8,
        920.7692308,
        1906.483725,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        1.0,
        12998.0,
        97300000.0,
    ),
    "Port Scan": (
        66.0,
        1.0,
        1.0,
        0.0,
        6.0,
        0.0,
        6.0,
        90909.09091,
        30303.0303,
        66.0,
        0.0,
        0.0,
        0.0,
        2.0,
        3.464101615,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
        1.0,
        0.0,
        0.0,
    ),
}


def _vector_for(class_name: str) -> FeatureVector:
    values = _CLASS_SAMPLES[class_name]
    assert len(values) == 24
    assert list(FEATURE_ORDER)  # schema present
    return FeatureVector(values=values)


class TestInferenceBenign(unittest.TestCase):
    def test_predicts_benign(self) -> None:
        engine = MLDetectionEngine()
        result = engine.predict(_vector_for("BENIGN"))
        self.assertIsInstance(result, DetectionResult)
        self.assertEqual(result.predicted_class, "BENIGN")
        self.assertEqual(result.predicted_class_id, 0)
        self.assertGreater(result.confidence, 0.9)
        self.assertAlmostEqual(
            result.confidence,
            result.probabilities["BENIGN"],
            places=9,
        )
        self.assertEqual(set(result.probabilities), set(CLASS_ORDER))
        self.assertTrue(all(math.isfinite(p) for p in result.probabilities.values()))
        self.assertAlmostEqual(sum(result.probabilities.values()), 1.0, places=5)


class TestInferenceBruteForce(unittest.TestCase):
    def test_predicts_brute_force(self) -> None:
        engine = MLDetectionEngine()
        result = engine.predict(_vector_for("Brute Force"))
        self.assertEqual(result.predicted_class, "Brute Force")
        self.assertEqual(result.predicted_class_id, 1)
        self.assertGreater(result.confidence, 0.9)
        self.assertAlmostEqual(
            result.confidence,
            result.probabilities["Brute Force"],
            places=9,
        )
        self.assertEqual(len(result.probability_vector()), 5)


class TestInferenceDDoS(unittest.TestCase):
    def test_predicts_ddos(self) -> None:
        engine = MLDetectionEngine()
        result = engine.predict(_vector_for("DDoS"))
        self.assertEqual(result.predicted_class, "DDoS")
        self.assertEqual(result.predicted_class_id, 2)
        self.assertGreater(result.confidence, 0.9)
        self.assertAlmostEqual(
            result.confidence,
            result.probabilities["DDoS"],
            places=9,
        )


class TestInferenceDoS(unittest.TestCase):
    def test_predicts_dos(self) -> None:
        engine = MLDetectionEngine()
        result = engine.predict(_vector_for("DoS"))
        self.assertEqual(result.predicted_class, "DoS")
        self.assertEqual(result.predicted_class_id, 3)
        self.assertGreater(result.confidence, 0.9)
        self.assertAlmostEqual(
            result.confidence,
            result.probabilities["DoS"],
            places=9,
        )


class TestInferencePortScan(unittest.TestCase):
    def test_predicts_port_scan(self) -> None:
        engine = MLDetectionEngine()
        result = engine.predict(_vector_for("Port Scan"))
        self.assertEqual(result.predicted_class, "Port Scan")
        self.assertEqual(result.predicted_class_id, 4)
        self.assertGreater(result.confidence, 0.9)
        self.assertAlmostEqual(
            result.confidence,
            result.probabilities["Port Scan"],
            places=9,
        )


class TestFeatureValidation(unittest.TestCase):
    def test_wrong_feature_count_raises(self) -> None:
        engine = MLDetectionEngine()
        with self.assertRaises(FeatureValidationError):
            engine.predict([0.0] * 23)
        with self.assertRaises(FeatureValidationError):
            engine.predict([0.0] * 25)

    def test_non_finite_values_raise(self) -> None:
        engine = MLDetectionEngine()
        bad = list(_CLASS_SAMPLES["BENIGN"])
        bad[0] = float("nan")
        with self.assertRaises(FeatureValidationError):
            engine.predict(bad)
        bad[0] = float("inf")
        with self.assertRaises(FeatureValidationError):
            engine.predict(bad)

    def test_malformed_input_raises(self) -> None:
        engine = MLDetectionEngine()
        with self.assertRaises(FeatureValidationError):
            engine.predict("not-a-vector")  # type: ignore[arg-type]
        with self.assertRaises(FeatureValidationError):
            engine.predict({"Flow Duration": 1.0})  # type: ignore[arg-type]


class TestModelLoading(unittest.TestCase):
    def test_default_artifacts_exist_and_match_schema(self) -> None:
        self.assertTrue(DEFAULT_MODEL_PATH.is_file())
        self.assertTrue(DEFAULT_FEATURES_META_PATH.is_file())
        meta = json.loads(DEFAULT_FEATURES_META_PATH.read_text(encoding="utf-8"))
        self.assertEqual(meta["features"], list(FEATURE_ORDER))
        self.assertEqual(meta["classes"], list(CLASS_ORDER))

    def test_missing_model_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with self.assertRaises(ModelLoadError):
                MLDetectionEngine(
                    model_path=missing,
                    features_meta_path=DEFAULT_FEATURES_META_PATH,
                )

    def test_corrupt_metadata_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_meta = Path(tmp) / "bad_features.json"
            bad_meta.write_text('{"features": ["only-one"], "classes": []}', encoding="utf-8")
            with self.assertRaises(ModelLoadError):
                MLDetectionEngine(
                    model_path=DEFAULT_MODEL_PATH,
                    features_meta_path=bad_meta,
                )


if __name__ == "__main__":
    unittest.main()
