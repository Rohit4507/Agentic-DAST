"""Exception types.

The scope hierarchy matters: every refusal is a :class:`ScopeViolation`, so callers
can catch one thing and know the request never left the process.
"""

from __future__ import annotations


class DastError(Exception):
    """Base class for everything this package raises deliberately."""


class ScopeViolation(DastError):
    """A request was refused *before* it was sent.

    This is the fail-closed path. It is never recoverable by the caller retrying
    with a modified URL -- that is the whole point.
    """

    def __init__(self, reason: str, *, url: str = "", detail: str = "") -> None:
        self.reason = reason
        self.url = url
        self.detail = detail
        msg = f"scope violation [{reason}]: {url or '<no url>'}"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


class StoppingCondition(ScopeViolation):
    """A refusal that must stop the *run*, not just the request.

    Ordinary scope denials are per-request events: a probe is refused, the rest of the
    scan continues. A spent budget or a dropped kill switch means the engagement is
    over, so these must never be swallowed into a "skipped" note.
    """


class BudgetExhausted(StoppingCondition):
    """The global request budget is spent. Treated as a scope violation on purpose."""


class KillSwitchEngaged(StoppingCondition):
    """The operator (or a monitor) dropped the kill file."""


#: tuple form, for ``except`` clauses that must re-raise before handling ScopeViolation
STOPPING = (KillSwitchEngaged, BudgetExhausted)


class TransportError(DastError):
    """The request was authorized but could not be completed (DNS, TCP, TLS, timeout)."""


class ControlFailure(DastError):
    """A test's negative control did not behave as required, so its result is void.

    Raised *instead of* reporting a finding. A verifier that cannot prove the
    request is discriminating must stay silent -- see README "precision".
    """


class ApprovalDenied(DastError):
    """A write/destructive test was refused by the human-approval gate."""
