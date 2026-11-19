"""Human-approval gate for risky tests.

The pack scores "safe autonomy: ... knows when a human must decide". AutoPenBench's
21% (fully autonomous) vs 64% (human-assisted) result is the argument for making that
gate real rather than decorative.

Policy:
  * read-only tests             -> no approval needed
  * write tests on *our own*    -> approval, auto-grantable with --approve-writes
    synthetic objects
  * anything destructive        -> always refused; it is also deny-listed in scope

In a non-interactive run (CI, tests) the gate refuses rather than silently proceeding,
which is the fail-closed choice.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any

from .errors import ApprovalDenied


@dataclass
class Approval:
    action: str
    risk: str
    granted: bool
    mode: str  # "auto" | "interactive" | "denied"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "risk": self.risk,
            "granted": self.granted,
            "mode": self.mode,
            "detail": self.detail,
        }


@dataclass
class ApprovalGate:
    auto: bool = False
    interactive: bool | None = None
    audit: Any = None
    approvals: list[Approval] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.interactive is None:
            self.interactive = sys.stdin.isatty()

    def require(self, *, action: str, risk: str, detail: str = "") -> Approval:
        if self.auto:
            approval = Approval(action=action, risk=risk, granted=True, mode="auto", detail=detail)
        elif self.interactive:
            prompt = f"\n[approval required] {action}\n  risk: {risk}\n  {detail}\n  Approve? [y/N] "
            answer = input(prompt).strip().lower()
            granted = answer in ("y", "yes")
            approval = Approval(
                action=action, risk=risk, granted=granted,
                mode="interactive", detail=detail if granted else "declined by operator",
            )
        else:
            approval = Approval(
                action=action, risk=risk, granted=False, mode="denied",
                detail=(
                    "non-interactive session: refusing to run a write test without approval. "
                    "Re-run with --approve-writes to pre-approve tests against synthetic objects."
                ),
            )
        self.approvals.append(approval)
        if self.audit is not None:
            self.audit.note(event_detail="approval", action=action, risk=risk,
                            granted=approval.granted, mode=approval.mode, detail_preview=detail[:200])
        if not approval.granted:
            raise ApprovalDenied(f"{action}: {approval.detail}")
        return approval

    @property
    def summary(self) -> str:
        if not self.approvals:
            return "no approvals requested"
        granted = sum(1 for a in self.approvals if a.granted)
        modes = ",".join(sorted({a.mode for a in self.approvals}))
        return f"{granted}/{len(self.approvals)} approvals granted ({modes})"

    @classmethod
    def from_env(cls, *, auto: bool, audit: Any = None) -> "ApprovalGate":
        if os.environ.get("DAST_NO_APPROVAL") == "1":
            raise ApprovalDenied("DAST_NO_APPROVAL=1: approvals cannot be disabled for this run")
        return cls(auto=auto, audit=audit)
