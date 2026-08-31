"""Import the pip ``xgboost`` package even if a local ``xgboost/`` artifact folder exists."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType


def import_xgboost() -> ModuleType:
    """
    Import the real XGBoost library from site-packages.

    A project folder named ``xgboost/`` (common on Windows) would otherwise be
    imported as a namespace package when the repository root is on ``sys.path``.
    Temporarily prefer site-packages so Module 5 can load the trained booster.
    """
    repo_root = Path(__file__).resolve().parents[1]
    artifact_dir = (repo_root / "xgboost").resolve()

    existing = sys.modules.get("xgboost")
    if existing is not None:
        module_paths = getattr(existing, "__path__", None)
        module_file = getattr(existing, "__file__", None)
        is_local_shadow = module_file is None and module_paths is not None and any(
            Path(path).resolve() == artifact_dir for path in module_paths
        )
        if is_local_shadow:
            del sys.modules["xgboost"]
            for name in list(sys.modules):
                if name.startswith("xgboost."):
                    del sys.modules[name]

    removed: list[str] = []
    repo_resolved = repo_root.resolve()
    for entry in list(sys.path):
        if entry == "":
            removed.append(entry)
            sys.path.remove(entry)
            continue
        try:
            if Path(entry).resolve() == repo_resolved:
                removed.append(entry)
                sys.path.remove(entry)
        except OSError:
            continue

    try:
        import xgboost as xgb  # noqa: WPS433 - intentional deferred import
    finally:
        for entry in reversed(removed):
            if entry not in sys.path:
                sys.path.insert(0, entry)

    return xgb
