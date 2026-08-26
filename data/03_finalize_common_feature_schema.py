#!/usr/bin/env python3
"""
Step 8 — Finalize and validate the MLCN common feature schema.

Third data-preparation script. Produces deterministic JSON schema and markdown
report artifacts without implementing Module 4 feature engineering.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as `python data/03_finalize_common_feature_schema.py` from repo root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from data.common_feature_schema import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
