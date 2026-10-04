"""
Packet-level approximation of what the lab traffic generator puts on loopback.

Used to check, without Npcap, which generated profiles the real model
recognises after the feature-contract fix. Timings mimic Windows loopback
(sub-millisecond RTT, 200 ms delayed ACK). This is an approximation, not a
substitute for a real Windows capture.
"""

from __future__ import annotations

import random

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from traffic_generator.config import (
    BRUTE_FORCE_ATTEMPTS_PER_SESSION,
    BRUTE_FORCE_DENY_LINE,
    BRUTE_FORCE_REPLY_DELAY_SECONDS,
    BRUTE_FORCE_THINK_SECONDS,
    DDOS_REQUEST,
    DOS_REQUEST_BYTES,
    LAB_PAGE_RESPONSE_BYTES,
)
from traffic_generator.parameter_mapper import map_profile_to_parameters
from traffic_generator.traffic_profile import TrafficParameters

CLIENT_IP = "127.0.0.1"
SERVER_IP = "127.0.0.1"
LAB_PORT = 8080
BASE_TIME = 1_700_000_000.0
RTT = 0.00008
DELAYED_ACK_SECONDS = 0.2

# Windows SYN / SYN-ACK carry MSS, window-scale and SACK options.
_SYN_OPTIONS = [("MSS", 65495), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]

HTTP_200_LEN = 98


def _pkt(src_port: int, dst_port: int, flags: str, at: float, payload: int = 0) -> Packet:
    options = _SYN_OPTIONS if "S" in flags else []
    pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=src_port, dport=dst_port, flags=flags, window=65535, options=options
    )
    if payload:
        pkt = pkt / Raw(load=b"x" * payload)
    pkt.time = BASE_TIME + at
    return pkt


def _request_len(params: TrafficParameters, path: str) -> int:
    head = (
        f"GET {path} HTTP/1.1\r\nHost: {params.target_host}\r\n"
        "Connection: close\r\nUser-Agent: MLCN-Lab-Generator/1.0\r\n"
    )
    return len(head) + 2


def http_close_exchange(
    t0: float,
    client_port: int,
    request_len: int,
    response_len: int,
    *,
    response_segments: int = 1,
    fin_with_data: bool = False,
) -> list[Packet]:
    """One request per TCP connection; the server sends its reply then closes (LabEchoServer)."""
    c, s = client_port, LAB_PORT
    t = t0
    seq = [
        _pkt(c, s, "S", t),
        _pkt(s, c, "SA", t + RTT),
        _pkt(c, s, "A", t + 2 * RTT),
        _pkt(c, s, "PA", t + 2.2 * RTT, request_len),
    ]
    t += 4 * RTT
    per = response_len // response_segments
    for i in range(response_segments):
        last = i == response_segments - 1
        size = response_len - per * (response_segments - 1) if last else per
        flags = ("FPA" if fin_with_data else "PA") if last else "A"
        seq.append(_pkt(s, c, flags, t, size))
        t += RTT / 4
    if not fin_with_data:
        seq.append(_pkt(s, c, "FA", t))
    seq += [
        _pkt(c, s, "A", t + RTT),
        _pkt(c, s, "FA", t + 2 * RTT),
        _pkt(s, c, "A", t + 3 * RTT),
    ]
    return seq


def line_session(
    t0: float,
    client_port: int,
    exchanges: list[tuple[float, int, float, int]],
) -> list[Packet]:
    """
    Short request/reply lines on one connection, client closes.

    ``exchanges`` = (think_before_request, request_len, reply_delay, reply_len).
    A pure ACK follows any segment not answered within the delayed-ACK timer.
    """
    c, s = client_port, LAB_PORT
    t = t0
    seq = [_pkt(c, s, "S", t), _pkt(s, c, "SA", t + RTT), _pkt(c, s, "A", t + 2 * RTT)]
    t += 2 * RTT
    for think, req, reply_delay, reply in exchanges:
        t += think
        seq.append(_pkt(c, s, "PA", t, req))
        if reply_delay > DELAYED_ACK_SECONDS:
            seq.append(_pkt(s, c, "A", t + DELAYED_ACK_SECONDS))
        t += reply_delay
        seq.append(_pkt(s, c, "PA", t, reply))
        seq.append(_pkt(c, s, "A", t + DELAYED_ACK_SECONDS))
    t += DELAYED_ACK_SECONDS + 0.001
    seq += [
        _pkt(c, s, "FA", t),
        _pkt(s, c, "A", t + RTT),
        _pkt(s, c, "FA", t + 2 * RTT),
        _pkt(c, s, "A", t + 3 * RTT),
    ]
    return seq


def closed_port_probe(t0: float, client_port: int, dst_port: int, retries: int = 0) -> list[Packet]:
    seq: list[Packet] = []
    for attempt in range(retries + 1):
        at = t0 + attempt * 0.5
        seq.append(_pkt(client_port, dst_port, "S", at))
        seq.append(_pkt(dst_port, client_port, "RA", at + RTT))
    return seq


def simulate_profile(
    profile: str,
    *,
    duration: float = 30.0,
    seed: int = 0,
    windows_syn_retries: int = 0,
    response_segments: int = 1,
    fin_with_data: bool = False,
) -> list[Packet]:
    """Approximate the packets ``traffic_generator`` emits for ``profile``."""
    rng = random.Random(seed)
    params = map_profile_to_parameters(profile, target_host=CLIENT_IP, duration_seconds=duration)
    packets: list[Packet] = []
    port = 50000
    page = {"response_segments": response_segments, "fin_with_data": fin_with_data}

    def next_port() -> int:
        nonlocal port
        port += 1
        return port

    t = 0.0
    if profile == "BENIGN":
        while t < duration:
            req = _request_len(params, "/lab/benign/1")
            packets += http_close_exchange(t, next_port(), req, HTTP_200_LEN)
            t += max(0.0, params.inter_message_delay_seconds + rng.uniform(-0.003, 0.003)) + 0.002
    elif profile == "Port Scan":
        ports = list(range(params.port_scan_start, params.port_scan_end + 1))
        idx = 0
        while t < duration:
            dst = ports[idx % len(ports)]
            idx += 1
            if dst == LAB_PORT:
                c = next_port()
                packets += [
                    _pkt(c, dst, "S", t),
                    _pkt(dst, c, "SA", t + RTT),
                    _pkt(c, dst, "A", t + 2 * RTT),
                    _pkt(c, dst, "FA", t + 3 * RTT),
                    _pkt(dst, c, "A", t + 4 * RTT),
                    _pkt(dst, c, "R", t + 5 * RTT),
                ]
            else:
                packets += closed_port_probe(t, next_port(), dst, windows_syn_retries)
            t += max(0.01, params.inter_message_delay_seconds) + 0.001 + 0.5 * windows_syn_retries
    elif profile == "Brute Force":
        req_len = len(b"LAB-AUTH 01\r\n")
        while t < duration:
            exchanges = [
                (
                    rng.uniform(*BRUTE_FORCE_THINK_SECONDS) if i else 0.0,
                    req_len,
                    rng.uniform(*BRUTE_FORCE_REPLY_DELAY_SECONDS),
                    len(BRUTE_FORCE_DENY_LINE),
                )
                for i in range(BRUTE_FORCE_ATTEMPTS_PER_SESSION)
            ]
            session = line_session(t, next_port(), exchanges)
            packets += session
            t = float(session[-1].time) - BASE_TIME + params.inter_message_delay_seconds
    elif profile == "DDoS":
        for _worker in range(params.max_concurrent_connections):
            tw = rng.uniform(0, 0.05)
            while tw < duration:
                packets += http_close_exchange(
                    tw, next_port(), len(DDOS_REQUEST), LAB_PAGE_RESPONSE_BYTES, **page
                )
                tw += max(0.0, params.forward_inter_delay_seconds + rng.uniform(-0.9, 0.9)) + 0.001
    elif profile == "DoS":
        while t < duration:
            for _cycle in range(params.request_response_cycles):
                packets += http_close_exchange(
                    t, next_port(), DOS_REQUEST_BYTES, LAB_PAGE_RESPONSE_BYTES, **page
                )
                t += params.inter_message_delay_seconds
            t += max(5.5, params.idle_gap_seconds)
    else:
        raise ValueError(profile)
    packets.sort(key=lambda p: float(p.time))
    return packets
