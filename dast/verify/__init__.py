"""Verification primitives.

Precision is won here. Everything in this package is deterministic code: it either
finds a proof or it stays silent. No LLM output is allowed to create a finding.
"""

from .engine import (  # noqa: F401
    Capsule,
    ControlResult,
    negative_control,
    redact_body,
    replay_capsule,
    response_signature,
)
from .invariants import INVARIANTS, Ledger, check_all  # noqa: F401
