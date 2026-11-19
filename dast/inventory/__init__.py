"""Inventory: discover routes, correlate with real traffic, label active/zombie/shadow."""

from .classify import build_inventory, probe_candidates  # noqa: F401
from .harvest import diff_route_sets, harvest_files, harvest_text  # noqa: F401
from .traffic import aggregate_traffic, read_gateway_log  # noqa: F401
