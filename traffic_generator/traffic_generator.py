"""Safe, rate-limited laboratory traffic generators (socket-based)."""

from __future__ import annotations

import logging
import random
import socket
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Callable

from traffic_generator.config import (
    BRUTE_FORCE_ATTEMPT_PREFIX,
    BRUTE_FORCE_ATTEMPTS_PER_SESSION,
    BRUTE_FORCE_THINK_SECONDS,
    DDOS_REQUEST,
    DOS_REQUEST_BYTES,
    PORT_SCAN_PROBE_TIMEOUT_SECONDS,
)
from traffic_generator.traffic_profile import GeneratorStats, TrafficParameters

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 65536

ProgressCallback = Callable[[float, str], None]


class BaseTrafficGenerator(ABC):
    """Common stop/progress handling for profile generators."""

    def __init__(
        self,
        params: TrafficParameters,
        stop_event: threading.Event,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.params = params
        self.stop_event = stop_event
        self.progress_callback = progress_callback
        self.stats = GeneratorStats()

    def _record_error(self, exc: OSError, *, context: str) -> None:
        message = f"{context}: {exc}"
        self.stats.errors += 1
        self.stats.last_error = message
        if self.stats.errors == 1:
            self._report(0.0, message)
        logger.debug(message)

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.stop_event.is_set():
                return
            time.sleep(min(0.05, end - time.monotonic()))

    def _jittered_delay(self, base: float) -> float:
        jitter = self.params.timing_jitter_seconds
        if jitter <= 0:
            return base
        return max(0.0, base + random.uniform(-jitter, jitter))

    def _report(self, fraction: float, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(_clamp_fraction(fraction), message)

    @abstractmethod
    def run(self) -> GeneratorStats:
        """Execute until duration elapsed or stop requested."""


def _clamp_fraction(value: float) -> float:
    return max(0.0, min(1.0, value))


def _build_http_request(
    host: str,
    port: int,
    path: str,
    *,
    method: str = "GET",
    body: bytes = b"",
) -> bytes:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "User-Agent: MLCN-Lab-Generator/1.0",
    ]
    if body:
        headers.append(f"Content-Length: {len(body)}")
        headers.append("Content-Type: application/x-www-form-urlencoded")
    headers.extend(["", ""])
    head = "\r\n".join(headers).encode("ascii")
    return head + body


def _tcp_exchange(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout: float = 2.0,
) -> tuple[int, int]:
    """Send payload over TCP; return (bytes_sent, packets_estimate)."""
    sent = 0
    packets = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
            sent += len(payload)
            packets += 1
        # Drain to EOF: closing with unread data makes the stack send RST instead of FIN.
        received = 0
        try:
            while received < _MAX_RESPONSE_BYTES:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                received += len(chunk)
                packets += 1
        except OSError:
            pass
    return sent, packets


def _line_session(
    host: str,
    port: int,
    lines: Sequence[bytes],
    think_seconds: Callable[[], float],
    sleep: Callable[[float], None],
    *,
    timeout: float = 3.0,
) -> tuple[int, int]:
    """Send each line on one TCP connection, waiting for a reply line in between."""
    sent = 0
    packets = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        for index, line in enumerate(lines):
            if index:
                sleep(think_seconds())
            sock.sendall(line)
            sent += len(line)
            packets += 1
            if sock.recv(1024):
                packets += 1
    return sent, packets


def _build_dos_request(host: str, port: int, cycle: int) -> bytes:
    """Hulk-like browser GET (full headers, no-cache) padded to ``DOS_REQUEST_BYTES``."""
    headers = (
        f"Host: {host}:{port}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) MLCN-Lab-Generator/1.0\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n\r\n"
    )
    path = f"/lab/dos/{cycle}?q="
    head_len = len(f"GET {path} HTTP/1.1\r\n") + len(headers)
    path += "x" * max(0, DOS_REQUEST_BYTES - head_len)
    return f"GET {path} HTTP/1.1\r\n{headers}".encode("ascii")


def _tcp_probe(host: str, port: int, *, timeout: float = PORT_SCAN_PROBE_TIMEOUT_SECONDS) -> bool:
    """Single SYN/connect probe (Port Scan profile)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


class BenignTrafficGenerator(BaseTrafficGenerator):
    """Periodic HTTP GET traffic with moderate pacing."""

    def run(self) -> GeneratorStats:
        start = time.monotonic()
        end = start + self.params.duration_seconds
        host = self.params.target_host
        port = self.params.target_port
        delay = self.params.inter_message_delay_seconds
        cycles = 0

        while time.monotonic() < end and not self.stop_event.is_set():
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                f"BENIGN HTTP GET cycle {cycles + 1}",
            )
            self.stats.connections_attempted += 1
            try:
                req = _build_http_request(host, port, f"/lab/benign/{cycles}")
                sent, pkts = _tcp_exchange(host, port, req)
                self.stats.bytes_sent += sent
                self.stats.packets_sent += pkts
                self.stats.connections_completed += 1
            except OSError as exc:
                self._record_error(exc, context=f"BENIGN HTTP GET to {host}:{port} failed")
            cycles += 1
            self._sleep(self._jittered_delay(delay))
        return self.stats


class PortScanTrafficGenerator(BaseTrafficGenerator):
    """Sequential TCP connect probes across a bounded port range."""

    def run(self) -> GeneratorStats:
        start = time.monotonic()
        end = start + self.params.duration_seconds
        host = self.params.target_host
        delay = max(0.01, self.params.inter_message_delay_seconds)
        ports = list(range(self.params.port_scan_start, self.params.port_scan_end + 1))
        if not ports:
            return self.stats

        idx = 0
        while time.monotonic() < end and not self.stop_event.is_set():
            port = ports[idx % len(ports)]
            idx += 1
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                f"Port Scan probe {host}:{port}",
            )
            self.stats.connections_attempted += 1
            try:
                _tcp_probe(host, port)
                self.stats.packets_sent += 1
                self.stats.connections_completed += 1
            except OSError as exc:
                self._record_error(exc, context=f"Port Scan probe to {host}:{port} failed")
            self._sleep(self._jittered_delay(delay))
        return self.stats


class BruteForceTrafficGenerator(BaseTrafficGenerator):
    """
    Login-attempt *pattern*: one TCP session carrying several short
    attempt/deny line exchanges (FTP-Patator-like flow shape).

    Does NOT transmit real credentials or perform authentication attacks.
    """

    def run(self) -> GeneratorStats:
        start = time.monotonic()
        end = start + self.params.duration_seconds
        host = self.params.target_host
        port = self.params.target_port
        session = 0

        while time.monotonic() < end and not self.stop_event.is_set():
            session += 1
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                f"Brute Force lab session {session} "
                f"({BRUTE_FORCE_ATTEMPTS_PER_SESSION} attempts)",
            )
            self.stats.connections_attempted += 1
            lines = [
                BRUTE_FORCE_ATTEMPT_PREFIX + b"%02d\r\n" % (attempt % 100)
                for attempt in range(1, BRUTE_FORCE_ATTEMPTS_PER_SESSION + 1)
            ]
            try:
                sent, pkts = _line_session(
                    host,
                    port,
                    lines,
                    lambda: random.uniform(*BRUTE_FORCE_THINK_SECONDS),
                    self._sleep,
                )
                self.stats.bytes_sent += sent
                self.stats.packets_sent += pkts
                self.stats.connections_completed += 1
            except OSError as exc:
                self._record_error(
                    exc,
                    context=f"Brute Force lab session to {host}:{port} failed",
                )
            self._sleep(self._jittered_delay(self.params.inter_message_delay_seconds))
        return self.stats


class DDoSTrafficGenerator(BaseTrafficGenerator):
    """Several concurrent workers sending tiny page requests (LOIC-like, rate-limited)."""

    def run(self) -> GeneratorStats:
        start = time.monotonic()
        end = start + self.params.duration_seconds
        host = self.params.target_host
        port = self.params.target_port
        lock = threading.Lock()
        workers: list[threading.Thread] = []

        def worker(worker_id: int) -> None:
            while time.monotonic() < end and not self.stop_event.is_set():
                with lock:
                    self.stats.connections_attempted += 1
                try:
                    sent, pkts = _tcp_exchange(host, port, DDOS_REQUEST, timeout=3.0)
                    with lock:
                        self.stats.bytes_sent += sent
                        self.stats.packets_sent += pkts
                        self.stats.connections_completed += 1
                except OSError as exc:
                    with lock:
                        self.stats.errors += 1
                        self.stats.last_error = f"DDoS HTTP POST to {host}:{port} failed: {exc}"
                        if self.stats.errors == 1:
                            self._report(0.0, self.stats.last_error)
                self._sleep(self._jittered_delay(self.params.forward_inter_delay_seconds))

        worker_count = max(1, self.params.max_concurrent_connections)
        for i in range(worker_count):
            thread = threading.Thread(target=worker, args=(i,), daemon=True)
            workers.append(thread)
            thread.start()

        while time.monotonic() < end and not self.stop_event.is_set():
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                f"DDoS lab workers active: {worker_count}",
            )
            self._sleep(0.25)

        self.stop_event.set()
        for thread in workers:
            thread.join(timeout=2.0)
        return self.stats


class DoSTrafficGenerator(BaseTrafficGenerator):
    """Bursts of Hulk-like full-header page requests separated by idle gaps (>5s)."""

    def run(self) -> GeneratorStats:
        start = time.monotonic()
        end = start + self.params.duration_seconds
        host = self.params.target_host
        port = self.params.target_port

        while time.monotonic() < end and not self.stop_event.is_set():
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                "DoS lab burst phase",
            )
            self.stats.connections_attempted += 1
            try:
                for cycle in range(self.params.request_response_cycles):
                    if self.stop_event.is_set() or time.monotonic() >= end:
                        break
                    req = _build_dos_request(host, port, cycle)
                    sent, pkts = _tcp_exchange(host, port, req, timeout=5.0)
                    self.stats.bytes_sent += sent
                    self.stats.packets_sent += pkts
                    self._sleep(self._jittered_delay(self.params.inter_message_delay_seconds))
                self.stats.connections_completed += 1
            except OSError as exc:
                self._record_error(exc, context=f"DoS HTTP POST to {host}:{port} failed")

            idle = max(5.5, self.params.idle_gap_seconds)
            self._report(
                (time.monotonic() - start) / self.params.duration_seconds,
                f"DoS lab idle gap ({idle:.1f}s)",
            )
            self._sleep(idle)
        return self.stats


def build_generator(
    params: TrafficParameters,
    stop_event: threading.Event,
    progress_callback: ProgressCallback | None = None,
) -> BaseTrafficGenerator:
    """Factory for profile-specific generators."""
    mapping = {
        "BENIGN": BenignTrafficGenerator,
        "Brute Force": BruteForceTrafficGenerator,
        "DDoS": DDoSTrafficGenerator,
        "DoS": DoSTrafficGenerator,
        "Port Scan": PortScanTrafficGenerator,
    }
    cls = mapping.get(params.profile_name)
    if cls is None:
        raise ValueError(f"unsupported profile: {params.profile_name!r}")
    return cls(params, stop_event, progress_callback)
