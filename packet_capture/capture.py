"""Live packet capture engine powered by Scapy."""

from __future__ import annotations

import logging
import signal
import sys
from typing import Callable, Iterator, Optional

from scapy.all import sniff

from packet_capture.formatter import format_divider, format_header, format_packet_row
from packet_capture.interfaces import resolve_interface
from packet_capture.models import ParsedPacket
from packet_capture.parser import parse_packet

logger = logging.getLogger(__name__)


class PacketCaptureEngine:
    """Capture live network packets and emit structured log output."""

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_handler: Optional[Callable[[ParsedPacket], None]] = None,
    ) -> None:
        self.interface = resolve_interface(interface)
        self._packet_handler = packet_handler or self._default_handler
        self._running = False
        self._packets_seen = 0
        self._packets_printed = 0

    @staticmethod
    def _default_handler(packet: ParsedPacket) -> None:
        print(format_packet_row(packet), flush=True)

    def _parse_raw_packet(self, raw_packet) -> Optional[ParsedPacket]:
        """Parse a raw Scapy packet, skipping malformed packets."""
        self._packets_seen += 1
        parsed = parse_packet(raw_packet)
        if parsed is None:
            return None
        self._packets_printed += 1
        return parsed

    def _dispatch_packet(
        self,
        packet: ParsedPacket,
        consumers: tuple[Callable[[ParsedPacket], None], ...],
    ) -> None:
        """Invoke one or more consumers for a successfully parsed packet."""
        for consumer in consumers:
            try:
                consumer(packet)
            except Exception:
                logger.debug("Packet consumer failed", exc_info=True)

    def _handle_raw_packet(self, raw_packet) -> None:
        """Parse and dispatch a single raw Scapy packet to the default handler."""
        parsed = self._parse_raw_packet(raw_packet)
        if parsed is not None:
            self._dispatch_packet(parsed, (self._packet_handler,))

    def _install_signal_handlers(self) -> None:
        def _request_stop(signum, _frame) -> None:
            logger.debug("Received signal %s; stopping capture", signum)
            self._running = False

        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, _request_stop)
        signal.signal(signal.SIGINT, _request_stop)

    def _begin_capture(self) -> None:
        self._running = True
        self._packets_seen = 0
        self._packets_printed = 0
        self._install_signal_handlers()

    def _run_sniff_loop(self, on_raw_packet: Callable[[object], None]) -> None:
        try:
            while self._running:
                sniff(
                    iface=self.interface,
                    prn=on_raw_packet,
                    store=False,
                    timeout=1,
                )
        except KeyboardInterrupt:
            self._running = False
        except PermissionError as exc:
            raise PermissionError(
                "Permission denied for packet capture. "
                "On macOS/Linux run with sudo; on Windows install Npcap and "
                "run the terminal as Administrator."
            ) from exc

    def start(self) -> None:
        """Begin continuous packet capture until stopped."""
        self._begin_capture()

        iface_label = self.interface or "default"
        print(f"Starting live capture on interface: {iface_label}")
        print("Press Ctrl+C to stop.\n")
        print(format_header())
        print(format_divider())

        try:
            self._run_sniff_loop(self._handle_raw_packet)
        finally:
            self._print_summary()

    def capture(self, callback: Callable[[ParsedPacket], None]) -> None:
        """
        Capture packets and invoke ``callback`` for each successfully parsed packet.

        No console output is produced. Stop with Ctrl+C or SIGTERM.
        """
        self._begin_capture()

        def on_raw_packet(raw_packet) -> None:
            parsed = self._parse_raw_packet(raw_packet)
            if parsed is not None:
                self._dispatch_packet(parsed, (callback,))

        self._run_sniff_loop(on_raw_packet)

    def iter_packets(self) -> Iterator[ParsedPacket]:
        """
        Yield each successfully parsed packet until capture is stopped.

        No console output is produced. Stop with Ctrl+C or SIGTERM.
        """
        self._begin_capture()
        pending: list[ParsedPacket] = []

        def on_raw_packet(raw_packet) -> None:
            parsed = self._parse_raw_packet(raw_packet)
            if parsed is not None:
                pending.append(parsed)

        try:
            while self._running:
                sniff(
                    iface=self.interface,
                    prn=on_raw_packet,
                    store=False,
                    timeout=1,
                )
                while pending:
                    yield pending.pop(0)
        except KeyboardInterrupt:
            self._running = False
        except PermissionError as exc:
            raise PermissionError(
                "Permission denied for packet capture. "
                "On macOS/Linux run with sudo; on Windows install Npcap and "
                "run the terminal as Administrator."
            ) from exc
        finally:
            while pending:
                yield pending.pop(0)

    def _print_summary(self) -> None:
        print(
            f"\nCapture stopped. "
            f"Processed {self._packets_seen} packet(s), "
            f"displayed {self._packets_printed}."
        )
