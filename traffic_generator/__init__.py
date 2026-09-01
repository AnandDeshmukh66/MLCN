"""MLCN Controlled IDS Traffic Generator — laboratory test traffic only."""

from traffic_generator.controller import TrafficGeneratorController
from traffic_generator.parameter_mapper import map_profile_to_parameters
from traffic_generator.profile_loader import load_profiles, list_profile_names
from traffic_generator.traffic_profile import TrafficParameters

__all__ = [
    "TrafficGeneratorController",
    "TrafficParameters",
    "load_profiles",
    "list_profile_names",
    "map_profile_to_parameters",
]
__version__ = "1.0.0"
