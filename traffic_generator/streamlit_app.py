"""Streamlit UI for the MLCN controlled IDS traffic generator."""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure repository root is importable when launched via `streamlit run`.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from traffic_generator.config import (
    DEFAULT_HTTP_PORT,
    MAX_PORT_SCAN_PORTS,
    MAX_TEST_DURATION_SECONDS,
    PROFILE_NAMES,
)
from traffic_generator.controller import TrafficGeneratorController
from traffic_generator.profile_loader import extract_reference_features, list_profile_names, load_profiles
from traffic_generator.safety import SafetyError, allowed_targets_hint
from traffic_generator.validation import default_loopback_interface, format_validation_table, summarize_validation


def _init_session_state() -> None:
    defaults = {
        "controller": TrafficGeneratorController(),
        "validation_rows": [],
        "last_summary": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def main() -> None:
    st.set_page_config(
        page_title="MLCN Lab Traffic Generator",
        page_icon="🧪",
        layout="wide",
    )
    _init_session_state()

    st.title("MLCN Controlled IDS Traffic Generator")
    st.caption(
        "Laboratory-only test traffic for authorized private/local receivers. "
        "Generates ordinary socket/HTTP traffic — M1→M4 on the receiver derive features naturally."
    )

    with st.sidebar:
        st.header("Safety")
        st.warning(
            "Authorized laboratory use only. Public Internet targets are rejected. "
            "No credential attacks, flooding, stealth, or evasion."
        )
        st.info(f"Allowed targets: {allowed_targets_hint()}")

    document = load_profiles()
    profiles = list_profile_names(document)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Test configuration")
        profile = st.selectbox("IDS test profile", profiles, index=0)
        target = st.text_input("Receiver IP / hostname", value="127.0.0.1")
        target_port = st.number_input(
            "Receiver port",
            min_value=1,
            max_value=65535,
            value=DEFAULT_HTTP_PORT,
        )
        duration = st.slider(
            "Duration (seconds)",
            min_value=5.0,
            max_value=float(MAX_TEST_DURATION_SECONDS),
            value=30.0,
            step=5.0,
        )
        intensity = st.slider(
            "Intensity (profile scale)",
            min_value=0.1,
            max_value=1.0,
            value=0.5,
            step=0.1,
        )

        if profile == "Port Scan":
            scan_start = st.number_input("Port scan start", value=8080, min_value=1, max_value=65535)
            scan_end = st.number_input(
                "Port scan end",
                value=min(8080 + MAX_PORT_SCAN_PORTS - 1, 8099),
                min_value=int(scan_start),
                max_value=min(65535, int(scan_start) + MAX_PORT_SCAN_PORTS - 1),
            )
        else:
            scan_start = 8080
            scan_end = 8099

    with col2:
        st.subheader("Profile reference (empirical medians)")
        refs = extract_reference_features(document, profile)
        if refs:
            preview = {k: refs[k] for k in list(refs)[:8]}
            st.json(preview)
            st.caption("Reference values from MLCN_compact_attack_traffic_profiles.json (not injected features).")
        else:
            st.write("No reference features loaded.")

        enable_validation = st.checkbox(
            "Validation mode (single-machine loopback only)",
            value=False,
            help=(
                "Starts receiver M1→M5 capture on loopback plus a tiny lab echo server. "
                "For Laptop B remote tests, run `python -m pipeline` separately."
            ),
        )
        if not enable_validation:
            st.info(
                "**Two-machine setup (Laptop B):**\n"
                "1. `python -m traffic_generator.receiver_server --port <port>`\n"
                "2. `python -m pipeline -i \"<Npcap interface>\"`\n"
                "3. Enter **Laptop B's IP** here (not this PC's IP unless it is Laptop B)."
            )
        validation_iface = st.text_input(
            "Validation capture interface",
            value=default_loopback_interface(),
            disabled=not enable_validation,
        )

    st.subheader("Mandatory confirmation")
    confirmed = st.checkbox("I confirm this is an authorized isolated laboratory test")
    confirmation_phrase = st.text_input("Type LAB to confirm", value="")

    ctrl: TrafficGeneratorController = st.session_state.controller
    btn_start, btn_stop = st.columns(2)

    with btn_start:
        start_clicked = st.button("Start test", type="primary", disabled=ctrl.running)
    with btn_stop:
        stop_clicked = st.button("Stop", disabled=not ctrl.running)

    if stop_clicked and ctrl.running:
        ctrl.stop("ui_stop")
        ctrl.append_log("Stop requested by user.")

    if start_clicked:
        try:
            ctrl.start(
                profile_name=profile,
                target=target,
                target_port=int(target_port),
                duration_seconds=float(duration),
                intensity=float(intensity),
                port_scan_start=int(scan_start),
                port_scan_end=int(scan_end),
                confirmed=confirmed,
                confirmation_phrase=confirmation_phrase,
                enable_validation=enable_validation,
                validation_interface=validation_iface if enable_validation else None,
                on_status=ctrl.append_log,
            )
            ctrl.append_log(f"Started profile={profile} target={target}:{target_port}")
        except (SafetyError, RuntimeError, ValueError) as exc:
            st.error(str(exc))
            ctrl.append_log(f"Start failed: {exc}")

    # Live status
    st.subheader("Live status")
    progress = ctrl.progress if ctrl.running else (1.0 if ctrl.last_log else 0.0)
    st.progress(min(1.0, max(0.0, progress)))
    st.write(ctrl.status)

    if ctrl.running:
        time.sleep(0.3)
        st.rerun()

    # Logs
    st.subheader("Log output")
    for line in reversed(list(ctrl.log_lines)[-30:]):
        st.text(line)

    # Summary
    st.subheader("Generated test summary")
    if ctrl.last_log:
        st.json(ctrl.last_log.as_dict())
    else:
        st.write("No completed runs yet.")

    stats = ctrl.stats
    if stats.connections_attempted or stats.packets_sent or stats.errors:
        st.metric("Connections attempted", stats.connections_attempted)
        st.metric("Connections completed", stats.connections_completed)
        st.metric("Packets/messages sent", stats.packets_sent)
        st.metric("Bytes sent", stats.bytes_sent)
        st.metric("Errors", stats.errors)
        if stats.last_error:
            st.error(f"Last connection error: {stats.last_error}")
        if (
            stats.connections_attempted > 0
            and stats.bytes_sent == 0
            and stats.errors >= stats.connections_attempted
        ):
            st.error(
                "No traffic was delivered to the receiver. The pipeline may still show "
                "unrelated background BENIGN flows (e.g. HTTPS to the Internet). "
                "On Laptop B run `python -m traffic_generator.receiver_server --port "
                f"{DEFAULT_HTTP_PORT}` and allow inbound TCP through the firewall."
            )

    # Validation results
    st.subheader("Validation results (receiver M1→M5)")
    records = list(ctrl.validation_records)
    if records:
        st.dataframe(format_validation_table(records), use_container_width=True)
        summary = summarize_validation(records)
        st.json(summary)
        st.caption(
            "Compare target profile → generated traffic → observed 24 features → XGBoost prediction."
        )
    elif enable_validation:
        st.info(
            "Validation enabled — classifications appear here after flows are captured on loopback."
        )
    else:
        st.info(
            "Two-machine lab: run `python -m pipeline -i <iface>` on Laptop B, then start a test "
            "toward Laptop B's private IP from this UI."
        )

    st.divider()
    st.markdown(
        "**Architecture:** UI → Profile Selector → Parameter Translator → Safe Traffic Generator "
        "→ Receiver (M1→M5) → XGBoost → Classification"
    )


if __name__ == "__main__":
    main()
