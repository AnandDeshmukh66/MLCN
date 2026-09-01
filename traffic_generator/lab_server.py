"""Minimal HTTP responder for single-machine lab validation (generator side only)."""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable

logger = logging.getLogger(__name__)


class LabEchoServer:
    """
    Tiny HTTP server so generated lab traffic receives responses on loopback.

    This is NOT part of the MLCN receiver pipeline — it only helps produce
    bidirectional flows during local validation.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="mlcn-lab-echo", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        self._sock = sock
        try:
            sock.bind((self.host, self.port))
            sock.listen(8)
            logger.info("lab echo server listening on %s:%s", self.host, self.port)
            while not self._stop.is_set():
                try:
                    conn, _addr = sock.accept()
                except OSError:
                    continue
                threading.Thread(
                    target=self._handle,
                    args=(conn,),
                    daemon=True,
                ).start()
        except OSError as exc:
            logger.warning("lab echo server failed to bind %s:%s — %s", self.host, self.port, exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(1.0)
            data = conn.recv(4096)
            body = b'{"status":"lab_ok"}'
            if b"POST" in data[:8]:
                response = (
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 21\r\n"
                    b"Connection: close\r\n\r\n"
                    + body
                )
            else:
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 7\r\n"
                    b"Connection: close\r\n\r\n"
                    b"MLCN_OK"
                )
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()
