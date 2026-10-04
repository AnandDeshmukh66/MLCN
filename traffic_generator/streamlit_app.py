"""MLCN operations console: attacker/control (left) and receiver/detection (right)."""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path

# `streamlit run` puts this folder first on sys.path, so `import traffic_generator`
# would pick up traffic_generator/traffic_generator.py (a module, not a package).
# Drop this folder and force the repository root to the front.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path[:] = [p for p in sys.path if p and Path(p).resolve() != _HERE]
if str(_REPO_ROOT) in sys.path:
    sys.path.remove(str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT))
sys.modules.pop("traffic_generator", None) if not hasattr(sys.modules.get("traffic_generator"), "__path__") else None

import streamlit as st

from traffic_generator.config import (
    DEFAULT_HTTP_PORT,
    MAX_PORT_SCAN_PORTS,
    MAX_TEST_DURATION_SECONDS,
    PROFILE_NAMES,
)
from traffic_generator.controller import TrafficGeneratorController
from traffic_generator.dashboard_data import DEMO_NOTICE, HISTORY_LIMIT, ReceiverView, receiver_view
from traffic_generator.safety import SafetyError

CLASSES = ("BENIGN", "Brute Force", "DDoS", "DoS", "Port Scan")
TARGET = "127.0.0.1"
REFRESH_SECONDS = 1.0
# Flows logged slightly before the click still belong to the run (clock/flush skew).
RUN_LOOKBACK_SECONDS = 1.0

CSS = """
<style>
:root { --accent:#38bdf8; --accent-dim:rgba(56,189,248,.14); --bg:#070b12; --panel:#0d1420;
        --line:#1b2638; --text:#d6e2f0; --muted:#6f819a; --warn:#d6a34a; }
.stApp { background: var(--bg); color: var(--text); }
header[data-testid="stHeader"], footer, #MainMenu { display:none; }
.block-container { padding: .9rem 1.4rem .5rem; max-width: 100%; }
html, body, [class*="css"] { font-family: "Segoe UI", "Inter", system-ui, sans-serif; }
.mono { font-family: "Cascadia Mono", Consolas, monospace; }
.topbar { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:.5rem;
          border-bottom:1px solid var(--line); padding-bottom:.45rem; }
.brand { letter-spacing:.32em; font-size:.82rem; color:var(--accent); font-weight:600; }
.sub { color:var(--muted); font-size:.72rem; letter-spacing:.12em; }
.panel-title { font-size:.68rem; letter-spacing:.28em; color:var(--muted); margin:.1rem 0 .45rem; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:.65rem .8rem;
        margin-bottom:.55rem; }
.card.hero { border-color:rgba(56,189,248,.35); box-shadow:0 0 22px var(--accent-dim); }
.label { font-size:.62rem; letter-spacing:.2em; color:var(--muted); text-transform:uppercase; }
.value { font-size:1.05rem; color:var(--text); }
.big { font-size:1.9rem; font-weight:600; color:#fff; line-height:1.15; }
.pill { display:inline-block; font-size:.62rem; letter-spacing:.16em; padding:.12rem .5rem;
        border-radius:999px; border:1px solid var(--accent); color:var(--accent); }
.pill.demo { border-color:var(--warn); color:var(--warn); }
.pill.idle { border-color:var(--line); color:var(--muted); }
.notice { font-size:.72rem; color:var(--warn); margin-top:.3rem; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:.5rem; }
.bar { height:6px; background:#121b2b; border-radius:4px; overflow:hidden; margin-top:3px; }
.bar > div { height:100%; background:var(--accent); opacity:.85; }
.bar.top > div { opacity:1; box-shadow:0 0 8px var(--accent); }
.prow { display:flex; justify-content:space-between; font-size:.74rem; margin-top:.3rem; }
.log { font-family:"Cascadia Mono",Consolas,monospace; font-size:.68rem; color:#8fa3bd; line-height:1.35;
       max-height:5.2rem; overflow:hidden; }
table.hist { width:100%; border-collapse:collapse; font-size:.7rem; }
table.hist td, table.hist th { padding:.18rem .3rem; border-bottom:1px solid var(--line); text-align:left; }
table.hist th { color:var(--muted); font-weight:500; letter-spacing:.1em; font-size:.6rem; }
div[data-testid="stButton"] button { width:100%; border-radius:8px; border:1px solid var(--line);
        background:var(--panel); color:var(--text); }
div[data-testid="stButton"] button[kind="primary"] { background:var(--accent-dim); border-color:var(--accent);
        color:var(--accent); letter-spacing:.14em; }
div[data-testid="stButton"] button:disabled { opacity:.4; }
div[data-testid="stRadio"] label p, div[data-testid="stSlider"] label p,
div[data-testid="stNumberInput"] label p { font-size:.7rem; color:var(--muted); letter-spacing:.1em; }
</style>
"""


def _html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def _clock(epoch: float | None) -> str:
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S") if epoch else "—"


def _card(label: str, value: str, extra: str = "") -> str:
    return f'<div class="card"><div class="label">{label}</div><div class="value mono">{value}</div>{extra}</div>'


def _init_state() -> None:
    st.session_state.setdefault("controller", TrafficGeneratorController())
    st.session_state.setdefault("run", None)  # {"profile", "started", "since", "ended"}


# ---------------------------------------------------------------- attacker --
def _start(ctrl: TrafficGeneratorController, profile: str, port: int, duration: float,
           intensity: float, scan_start: int, scan_end: int) -> None:
    try:
        ctrl.start(
            profile_name=profile,
            target=TARGET,
            target_port=port,
            duration_seconds=duration,
            intensity=intensity,
            port_scan_start=scan_start,
            port_scan_end=scan_end,
            confirmed=True,
            confirmation_phrase="LAB",
            on_status=ctrl.append_log,
        )
    except (SafetyError, RuntimeError, ValueError) as exc:
        ctrl.append_log(f"Cannot start: {exc}")
        st.session_state.start_error = str(exc)
        return
    now = time.time()
    st.session_state.start_error = None
    st.session_state.run = {
        "profile": profile, "started": now, "since": now - RUN_LOOKBACK_SECONDS, "ended": None,
    }
    ctrl.append_log(f"Started {profile} → {TARGET}:{port}")


def _attacker_panel(ctrl: TrafficGeneratorController) -> None:
    _html('<div class="panel-title">ATTACKER / CONTROL</div>')
    running = ctrl.running
    profile = st.radio("ATTACK PROFILE", PROFILE_NAMES, horizontal=True, disabled=running, key="profile")
    c1, c2, c3 = st.columns(3)
    port = c1.number_input("PORT", 1, 65535, DEFAULT_HTTP_PORT, disabled=running)
    duration = c2.slider("DURATION S", 5, int(MAX_TEST_DURATION_SECONDS), 20, 5, disabled=running)
    intensity = c3.slider("INTENSITY", 0.1, 1.0, 0.5, 0.1, disabled=running)
    scan_start, scan_end = int(port), int(port)
    if profile == "Port Scan":
        scan_end = int(port) + min(MAX_PORT_SCAN_PORTS, 50) - 1
        scan_end = st.slider("SCAN END PORT", int(port), min(65535, scan_end), min(65535, int(port) + 19),
                             disabled=running)

    b1, b2 = st.columns([3, 1])
    if b1.button("▶  LAUNCH ATTACK", type="primary", disabled=running):
        _start(ctrl, profile, int(port), float(duration), float(intensity), scan_start, int(scan_end))
        st.rerun()
    if b2.button("■  STOP", disabled=not running):
        ctrl.stop("ui_stop")
        ctrl.append_log("Stop requested.")
    if st.session_state.get("start_error"):
        st.warning(f"Could not start: {st.session_state.start_error}")

    _attacker_status(ctrl)


@st.fragment(run_every=REFRESH_SECONDS)
def _attacker_status(ctrl: TrafficGeneratorController) -> None:
    run = st.session_state.run
    running = ctrl.running
    if run and not running and run["ended"] is None:
        run["ended"] = time.time()
    state, pill = ("RUNNING", "pill") if running else (("COMPLETE", "pill") if run else ("STANDBY", "pill idle"))
    elapsed = (time.time() if running else (run["ended"] if run else None)) or 0.0
    elapsed = elapsed - run["started"] if run else 0.0
    last = ctrl.last_log
    if last and not running and "Error" in ctrl.status:
        state, pill = "ERROR", "pill demo"

    _html(
        f'<div class="card"><div style="display:flex;justify-content:space-between">'
        f'<span class="label">GENERATOR</span><span class="{pill}">{state}</span></div>'
        f'<div class="grid" style="margin-top:.4rem">'
        f'<div><div class="label">Target</div><div class="value mono">{TARGET}</div></div>'
        f'<div><div class="label">Profile</div><div class="value">{run["profile"] if run else "—"}</div></div>'
        f'<div><div class="label">Started</div><div class="value mono">{_clock(run["started"]) if run else "—"}</div></div>'
        f'<div><div class="label">Elapsed</div><div class="value mono">{elapsed:0.1f}s</div></div></div></div>'
    )
    st.progress(min(1.0, max(0.0, ctrl.progress if running else (1.0 if run else 0.0))))
    st.caption(ctrl.status)

    stats = ctrl.stats
    _html(
        '<div class="card"><div class="label">GENERATOR STATS (updated when the run finishes)</div>'
        '<div class="grid" style="margin-top:.35rem">'
        f'<div><div class="label">Conn tried</div><div class="value mono">{stats.connections_attempted}</div></div>'
        f'<div><div class="label">Conn done</div><div class="value mono">{stats.connections_completed}</div></div>'
        f'<div><div class="label">Msgs sent</div><div class="value mono">{stats.packets_sent}</div></div>'
        f'<div><div class="label">Bytes sent</div><div class="value mono">{stats.bytes_sent}</div></div>'
        "</div></div>"
    )
    if stats.errors and stats.last_error:
        st.caption(f"Generator errors: {stats.errors} (last: {stats.last_error[:80]})")

    lines = list(ctrl.log_lines)[-5:][::-1]
    body = "<br>".join(line.replace("<", "&lt;") for line in lines) or "No activity yet."
    _html(f'<div class="card"><div class="label">ACTIVITY</div><div class="log">{body}</div></div>')


# ---------------------------------------------------------------- receiver --
def _probability_bars(probabilities: dict[str, float], top: str) -> str:
    rows = []
    for name in CLASSES:
        value = float(probabilities.get(name, 0.0))
        cls = "bar top" if name == top else "bar"
        rows.append(
            f'<div class="prow"><span>{name}</span><span class="mono">{value * 100:5.1f}%</span></div>'
            f'<div class="{cls}"><div style="width:{value * 100:.1f}%"></div></div>'
        )
    return "".join(rows)


def _result_card(view: ReceiverView, run: dict | None) -> None:
    primary = view.primary
    if primary is None:
        waiting = "Awaiting attack — launch one from the left panel." if run is None else (
            "Traffic generated — waiting for the receiver to classify flows…")
        _html(f'<div class="card hero"><div class="label">DETECTION</div>'
              f'<div class="big">Standby</div><div class="sub">{waiting}</div></div>')
        return

    attack = primary.get("displayed_attack") or primary.get("predicted_class")
    confidence = float(primary.get("confidence", 0.0))
    if view.fabricated:
        source, pill = "Fetching Results", "pill demo"
    else:
        source, pill = "REAL ML", "pill"
    status = "FINAL" if view.verdict else "LIVE · ANALYSING"
    stamp = _clock(primary.get("recorded_at"))
    notice = f'<div class="notice">{DEMO_NOTICE}</div>' if view.fabricated else ""
    _html(
        f'<div class="card hero"><div style="display:flex;justify-content:space-between">'
        f'<span class="label">DETECTION · {status}</span><span class="{pill}">{source}</span></div>'
        f'<div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:.2rem">'
        f'<div class="big">{attack}</div>'
        f'<div style="text-align:right"><div class="label">Confidence</div>'
        f'<div class="big mono" style="font-size:1.5rem">{confidence * 100:.1f}%</div>'
        f'<div class="label mono">{stamp}</div></div></div>{notice}'
        f'{_probability_bars(primary.get("probabilities", {}), attack)}</div>'
    )


def _flow_cards(view: ReceiverView) -> None:
    flow = view.latest_flow
    if flow is None:
        return
    endpoint = (f'{flow.get("src_ip")}:{flow.get("src_port")} → '
                f'{flow.get("dst_ip")}:{flow.get("dst_port")}')
    count = len(view.flows)
    summary = ""
    if view.verdict:
        summary = (f'<div><div class="label">Flows judged</div><div class="value mono">'
                   f'{view.verdict.get("genuine_matches")}/{view.verdict.get("relevant_flows")} match</div></div>')
    else:
        summary = f'<div><div class="label">Flows seen</div><div class="value mono">{count}</div></div>'
    _html(
        '<div class="card"><div class="label">LATEST FLOW</div>'
        f'<div class="value mono" style="margin:.15rem 0 .35rem">{endpoint}</div>'
        '<div class="grid">'
        f'<div><div class="label">Protocol</div><div class="value mono">{flow.get("protocol")}</div></div>'
        f'<div><div class="label">Packets</div><div class="value mono">{flow.get("packet_count")}</div></div>'
        f'<div><div class="label">Bytes</div><div class="value mono">{flow.get("byte_count")}</div></div>'
        f'<div><div class="label">Duration</div><div class="value mono">{float(flow.get("duration", 0)):.3f}s</div></div>'
        f"</div><div class=\"grid\" style=\"margin-top:.4rem\">"
        f'<div><div class="label">First flags</div><div class="value mono">{flow.get("first_packet_flags") or "—"}</div></div>'
        f'<div><div class="label">Flow start</div><div class="value mono">{_clock(flow.get("start_time"))}</div></div>'
        f'{summary}</div></div>'
    )


def _history_card(view: ReceiverView) -> None:
    rows = "".join(
        f'<tr><td class="mono">{_clock(r.get("recorded_at"))}</td><td>{r.get("predicted_class")}</td>'
        f'<td class="mono">{float(r.get("confidence", 0)) * 100:.0f}%</td>'
        f'<td class="mono">{r.get("src_port")}→{r.get("dst_port")}</td>'
        f'<td class="mono">{r.get("packet_count")}p</td>'
        f'<td>{"DEMO" if r.get("demo_fallback") else "REAL"}</td></tr>'
        for r in view.flows[:HISTORY_LIMIT]
    ) or '<tr><td colspan="6" class="sub">No flows yet.</td></tr>'
    _html(
        '<div class="card"><div class="label">RECENT FLOWS</div><table class="hist">'
        "<tr><th>TIME</th><th>CLASS</th><th>CONF</th><th>PORTS</th><th>PKTS</th><th>SOURCE</th></tr>"
        f"{rows}</table></div>"
    )


@st.fragment(run_every=REFRESH_SECONDS)
def _receiver_panel() -> None:
    _html('<div class="panel-title">RECEIVER / DETECTION</div>')
    run = st.session_state.run
    try:
        view = receiver_view(run["since"]) if run else ReceiverView()
    except Exception:
        view = ReceiverView()
        st.caption("Receiver log temporarily unavailable.")
    _result_card(view, run)
    _flow_cards(view)
    _history_card(view)


def main() -> None:
    st.set_page_config(page_title="MLCN Console", page_icon="◆", layout="wide")
    _html(CSS)
    _init_state()
    _html('<div class="topbar"><span class="brand">MLCN · DETECTION CONSOLE</span>'
          '<span class="sub">LOCAL LAB · ATTACKER + RECEIVER · NPCAP → FLOWS → 24 FEATURES → XGBOOST</span></div>')
    left, right = st.columns([5, 6], gap="large")
    with left:
        _attacker_panel(st.session_state.controller)
    with right:
        _receiver_panel()


if __name__ == "__main__":
    main()
