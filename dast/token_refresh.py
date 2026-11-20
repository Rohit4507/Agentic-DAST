"""Getting a new bearer token mid-run, without ever logging one.

A 30-minute token and a 40-minute scan is the normal case on a real platform: the tail
of the run starts returning 401 and every test that touches it voids.  That looks like
"the target got fixed" in a report, which is the worst possible lie for a retest loop.

The refresh is declared in the scope file, so it is subject to the same rules as
everything else:

    "auth": {{"refresh": {{
        "path": "/oauth/token",
        "grant_type": "client_credentials",
        "token_field": "access_token",
        "credentials": {{
            "agency_a": {{"client_id": "env:DAST_A_ID", "client_secret": "env:DAST_A_SECRET"}}
        }}
    }}}}

* ``path`` must be **in the allowlist**, or the guard refuses the refresh request like
  any other.  That is deliberate: a token endpoint is a URL the tool sends to.
* the credentials are ``env:VAR`` references resolved at use time; the audit log and
  every error message carry a fingerprint, never the value.
* a failed refresh returns ``None``.  The caller then keeps the original 401: an
  expired credential voids the test, it never manufactures a result.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping

from .errors import DastError
from .http import Client

_KNOWN = {"path", "method", "grant_type", "token_field", "credentials", "body"}
_CRED_KEYS = {"client_id", "client_secret", "username", "password"}


@dataclass(frozen=True)
class RefreshSpec:
    path: str
    method: str = "POST"
    grant_type: str = "client_credentials"
    token_field: str = "access_token"
    credentials: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    body: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Any) -> "RefreshSpec":
        """Build from the scope's ``auth.refresh`` block.  Unknown keys are fatal."""
        if not isinstance(raw, Mapping):
            raise DastError("auth.refresh must be an object")
        unknown = sorted(set(raw) - _KNOWN)
        if unknown:
            raise DastError(
                f"unknown key(s) in auth.refresh: {', '.join(unknown)}. "
                f"Known keys: {', '.join(sorted(_KNOWN))}"
            )
        path = raw.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise DastError("auth.refresh.path must be an absolute path, e.g. /oauth/token")
        creds = raw.get("credentials") or {}
        if not isinstance(creds, Mapping):
            raise DastError("auth.refresh.credentials must be an object of role -> fields")
        for role, spec in creds.items():
            if not isinstance(spec, Mapping):
                raise DastError(f"auth.refresh.credentials.{role} must be an object")
            bad = sorted(set(spec) - _CRED_KEYS)
            if bad:
                raise DastError(
                    f"unknown credential field(s) for {role}: {', '.join(bad)}. "
                    f"Known: {', '.join(sorted(_CRED_KEYS))}"
                )
        body = raw.get("body") or {}
        if not isinstance(body, Mapping):
            raise DastError("auth.refresh.body must be an object")
        return cls(
            path=path,
            method=str(raw.get("method") or "POST").upper(),
            grant_type=str(raw.get("grant_type") or "client_credentials"),
            token_field=str(raw.get("token_field") or "access_token"),
            credentials={str(k): {kk: str(vv) for kk, vv in v.items()} for k, v in creds.items()},
            body=dict(body),
        )


class HttpTokenRefresher:
    """Callable ``role -> token | None``, used by :class:`~dast.http.Client` on a 401."""

    def __init__(self, client: Client, spec: RefreshSpec) -> None:
        self.client = client
        self.spec = spec

    def __call__(self, role: str) -> str | None:
        creds = self.spec.credentials.get(role)
        if not creds:
            # No configured credential for this role is a *void*, not an exception: the
            # caller still holds the original 401 and reports it as such.
            return None
        payload: dict[str, Any] = {"grant_type": self.spec.grant_type}
        payload.update(self.spec.body)
        for key, spec_value in creds.items():
            value = _resolve(spec_value)
            if value is None:
                return None
            payload[key] = value
        resp = self.client.request(
            self.spec.method,
            self.spec.path,
            json=payload,
            component="auth",
            note=f"token-refresh:{role}",
            allow_anonymous=True,
        )
        if resp.status != 200:
            return None
        try:
            body = resp.json()
        except ValueError:
            return None
        if not isinstance(body, Mapping):
            return None
        token = body.get(self.spec.token_field)
        if not isinstance(token, str) or not token.strip():
            return None
        return token


def _resolve(spec: str) -> str | None:
    """``env:VAR`` at use time; the value never lands in config or a log line."""
    if not isinstance(spec, str):
        return None
    if spec.startswith("env:"):
        return os.environ.get(spec[4:]) or None
    if spec.startswith("literal:"):
        return spec[len("literal:") :]
    return spec or None


def build_refresher(client: Client, cfg_auth: Mapping[str, Any]) -> HttpTokenRefresher | None:
    """No ``auth.refresh`` block means no refresh -- never a silent default endpoint."""
    raw = (cfg_auth or {}).get("refresh")
    if not raw:
        return None
    return HttpTokenRefresher(client, RefreshSpec.parse(raw))
