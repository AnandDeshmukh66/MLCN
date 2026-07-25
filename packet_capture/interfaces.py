"""Network interface discovery helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from scapy.all import get_if_addr, get_if_list


@dataclass(frozen=True)
class NetworkInterface:
    """A capture-capable network interface."""

    name: str
    address: Optional[str]


def list_interfaces() -> List[NetworkInterface]:
    """Return available network interfaces with their primary IPv4 address."""
    interfaces: List[NetworkInterface] = []
    for name in get_if_list():
        try:
            address = get_if_addr(name)
            if not address or address == "0.0.0.0":
                address = None
        except Exception:
            address = None
        interfaces.append(NetworkInterface(name=name, address=address))
    return interfaces


def resolve_interface(name: Optional[str]) -> Optional[str]:
    """
    Validate and return the interface name for capture.

    Returns ``None`` to let Scapy choose the default interface.
    """
    if name is None:
        return None

    available = {iface.name for iface in list_interfaces()}
    if name not in available:
        known = ", ".join(sorted(available)) or "(none detected)"
        raise ValueError(f"Interface '{name}' not found. Available: {known}")
    return name
