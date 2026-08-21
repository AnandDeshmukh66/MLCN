"""Flow Builder — Module 3 of the MLCN cybersecurity project."""

from flow_builder.builder import FlowBuilder, canonicalize_flow_key, flow_key_from_packet
from flow_builder.models import Flow, FlowKey

__all__ = [
    "Flow",
    "FlowBuilder",
    "FlowKey",
    "canonicalize_flow_key",
    "flow_key_from_packet",
]
__version__ = "1.0.0"
