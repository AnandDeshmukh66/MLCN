"""
TEMPORARY demo fallback (removable).

Makes the receiver display the attacker-selected profile when the genuine
XGBoost prediction disagrees. Real inference always runs first and is kept on
``PipelineResult.genuine_detection``; display results built here carry
``demo_fallback=True``.

To remove: delete this package and its three call sites —
``pipeline/cli.py`` (``--demo-fallback``), ``traffic_generator/controller.py``
(session start/finish hooks) and ``mlcn_launcher`` (``--demo-fallback`` flag).
"""

from demo_fallback.fallback import (
    DEMO_FALLBACK_ENV,
    DISCLAIMER,
    FABRICATED,
    REAL_ML,
    Decision,
    DemoFallback,
    SessionResult,
    decide,
    enabled_from_env,
    result_source,
    session_result,
    synthetic_detection,
)
from demo_fallback.session import (
    DemoSession,
    finish_session,
    read_session,
    write_session,
)

__all__ = [
    "DEMO_FALLBACK_ENV",
    "DISCLAIMER",
    "FABRICATED",
    "REAL_ML",
    "Decision",
    "DemoFallback",
    "DemoSession",
    "SessionResult",
    "decide",
    "enabled_from_env",
    "finish_session",
    "read_session",
    "result_source",
    "session_result",
    "synthetic_detection",
    "write_session",
]
