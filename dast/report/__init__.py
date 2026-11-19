"""Findings -> ticket-shaped markdown, SARIF, JSON."""

from .dedupe import DedupeReport, dedupe, dedupe_key  # noqa: F401
from .sarif import build_sarif, write_sarif  # noqa: F401
from .ticket import render_index, render_ticket, write_findings  # noqa: F401
