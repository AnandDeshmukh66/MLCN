# MLCN — Module 5: Machine Learning Detection Engine

Inference-only XGBoost multi-class IDS detector for the MLCN pipeline.

```text
Network → Module 1 → Module 2 → Module 3 → Module 4: Feature Engineering → Module 5: ML Detection
```

## Responsibility

Module 5 consumes a Module 4 `FeatureVector` (24 schema-ordered floats) and
runs the trained XGBoost model to produce a `DetectionResult`.

| Concern | Behavior |
|---------|----------|
| Model | Loads `models/xgboost_ids_multiclass.json` (no retraining) |
| Features | Exact 24-feature order from `data/common_feature_schema.json` |
| Classes | `BENIGN`, `Brute Force`, `DDoS`, `DoS`, `Port Scan` |
| Output | Predicted class, class ID, confidence, full probability map |
| Validation | Feature count/order/finiteness and model metadata compatibility |
| Bad input | `FeatureValidationError` / `ModelLoadError` (clear, typed) |

## Usage

```python
from feature_engineering import FeatureEngineeringEngine
from ml_detection import MLDetectionEngine

fe = FeatureEngineeringEngine()
detector = MLDetectionEngine()

vector = fe.extract(flow)
result = detector.predict(vector)
print(result.predicted_class, result.confidence, result.probabilities)
```

## Artifacts

| File | Role |
|------|------|
| `models/xgboost_ids_multiclass.json` | Trained booster |
| `models/xgboost_ids_features.json` | Feature/class metadata |

> The artifact directory is named `models/` (not `xgboost/`) so it does not
> shadow the pip `xgboost` package when running from the repository root.

## Dependencies

```bash
pip install -r requirements.txt
# macOS also needs OpenMP for the XGBoost native library:
#   brew install libomp
```

## Test / run

```bash
source macvenv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
