"""Credential handling.

Rules of Engagement: *"Use only the provided test accounts."*  Consequences for the
implementation: tokens are resolved from the environment at use time (never stored in
config, never written to the audit log, never sent to an LLM), and every log line about
a credential is a fingerprint, not the value.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Mapping

from .errors import DastError


def fingerprint(secret: str) -> str:
    """Stable, non-reversible handle for a credential (safe for logs and reports)."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


@dataclass
class TokenStore:
    """Resolves role -> bearer token from an ``accounts`` mapping in the scope file.

    Each value is either ``env:VAR_NAME`` (preferred) or ``literal:VALUE`` (for local
    mock targets only, where the "credential" is a fixture, not a secret).
    """

    accounts: Mapping[str, str]
    header_name: str = "Authorization"
    scheme: str = "Bearer"
    _cache: dict[str, str] = field(default_factory=dict, repr=False)

    def roles(self) -> list[str]:
        return sorted(self.accounts)

    def get(self, role: str) -> str:
        if role in self._cache:
            return self._cache[role]
        spec = self.accounts.get(role)
        if spec is None:
            raise DastError(f"no credential configured for role {role!r}; have {self.roles()}")
        if spec.startswith("env:"):
            var = spec[4:]
            val = os.environ.get(var)
            if not val:
                raise DastError(
                    f"role {role!r} expects environment variable {var}, which is unset. "
                    f"Export it before running:  export {var}=..."
                )
        elif spec.startswith("literal:"):
            val = spec[len("literal:") :]
        else:
            raise DastError(f"role {role!r}: credential spec must be 'env:VAR' or 'literal:VALUE'")
        self._cache[role] = val
        return val

    def headers(self, role: str) -> dict[str, str]:
        return {self.header_name: f"{self.scheme} {self.get(role)}".strip()}

    def handle(self, role: str) -> str:
        """Loggable identifier for a role's credential."""
        return fingerprint(self.get(role))

    def assert_available(self) -> None:
        """Fail early, with one actionable message, rather than mid-scan."""
        missing = []
        for role, spec in self.accounts.items():
            if spec.startswith("env:") and not os.environ.get(spec[4:]):
                missing.append(f"{role} -> ${spec[4:]}")
        if missing:
            raise DastError(
                "missing test-account credentials (Role of Engagement: provided accounts only):\n  "
                + "\n  ".join(missing)
            )
