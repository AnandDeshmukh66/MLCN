"""Network interface discovery helpers."""

from __future__ import annotations

from dataclasses import dataclass

from scapy.all import get_if_addr, get_if_list


@dataclass(frozen=True)
class NetworkInterface:
    """A capture-capable network interface."""

    name: str
    address: str | None


def list_interfaces() -> list[NetworkInterface]:
    """Return available network interfaces with their primary IPv4 address."""
    interfaces: list[NetworkInterface] = []
    for name in get_if_list():
        try:
            address = get_if_addr(name)
            if not address or address == "0.0.0.0":
                address = None
        except Exception:  # noqa: BLE001 - ignore missing interface metadata safely
            address = None
        interfaces.append(NetworkInterface(name=name, address=address))
    return interfaces


def resolve_interface(name: str | None) -> str | None:
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


def resolve_interfaces(name: str | None) -> list[str | None]:
    """
    Resolve one or more capture interfaces.

    Comma-separated names capture on multiple adapters in parallel (needed on
    Windows when lab traffic is hairpinned to the local IP and never appears
    on Wi-Fi, or when background Internet traffic drowns out lab flows).
    """
    if name is None:
        return [None]
    parts = [part.strip() for part in name.split(",") if part.strip()]
    if not parts:
        return [None]
    return [resolve_interface(part) for part in parts]
