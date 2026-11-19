"""The only module in this package that sends a request.

Every call goes: :meth:`ScopeGuard.check` -> audit -> send -> audit -> health monitor.
There is no ``Session``-style escape hatch, redirects are never followed implicitly
(a redirect is a new URL and must re-pass the guard), and response bodies are capped
because the Rules of Engagement forbid bulk data extraction.
"""

from __future__ import annotations

import json as _json
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from .audit import AuditLog, redact_headers, redact_url
from .auth import TokenStore
from .errors import ScopeViolation, TransportError
from .scope import ScopeGuard

DEFAULT_MAX_BODY_BYTES = 512 * 1024


@dataclass
class Response:
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    truncated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return _json.loads(self.body.decode("utf-8", errors="replace"))
        except _json.JSONDecodeError as exc:
            raise ValueError(f"response is not JSON (status {self.status}): {exc}") from exc

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @property
    def content_type(self) -> str:
        return self.header("content-type")

    def summary(self) -> str:
        return f"{self.status} {self.method} {redact_url(self.url)} ({self.elapsed_ms:.0f}ms, {len(self.body)}B)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn 3xx into an HTTPError so a redirect can never silently leave scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class Client:
    """Scope-checked HTTP client."""

    def __init__(
        self,
        guard: ScopeGuard,
        audit: AuditLog,
        tokens: TokenStore | None = None,
        *,
        component: str = "unknown",
        timeout: float = 15.0,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        self.guard = guard
        self.audit = audit
        self.tokens = tokens or TokenStore({})
        self.component = component
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes

        ctx = None
        if guard.config.allow_insecure_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [_NoRedirect()]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    # -- url helpers ----------------------------------------------------------------

    def url_for(self, path: str) -> str:
        base = self.guard.config.base_url
        if not base:
            raise ScopeViolation("no-base-url", detail="scope.json has no base_url")
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{base}/{path.lstrip('/')}"

    # -- the one entry point --------------------------------------------------------

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        role: str | None = None,
        json: Any = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        charge: bool = True,
        follow_redirects: bool = False,
        component: str | None = None,
        note: str = "",
        allow_anonymous: bool = False,
    ) -> Response:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else self.url_for(path_or_url)
        comp = component or self.component
        method = method.upper()

        # --- authorised? if not, this raises and nothing leaves the process --------
        try:
            decision = self.guard.check(method, url, charge=charge)
        except ScopeViolation as exc:
            self.audit.denied(
                component=comp,
                method=method,
                url=redact_url(url),
                reason=exc.reason,
                detail=exc.detail,
                role=role,
                note=note,
            )
            raise

        hdrs: dict[str, str] = {"User-Agent": self.guard.config.user_agent, "Accept": "application/json, */*"}
        if role and not allow_anonymous:
            hdrs.update(self.tokens.headers(role))
        hdrs.update({k: v for k, v in (headers or {}).items()})

        payload = data
        if json is not None:
            payload = _json.dumps(json).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url, data=payload, headers=hdrs, method=method)
        started = time.monotonic()
        status = 0
        body = b""
        resp_headers: dict[str, str] = {}
        truncated = False
        error = ""

        try:
            with self._opener.open(req, timeout=self.timeout) as raw:
                status = raw.status
                resp_headers = dict(raw.headers.items())
                body, truncated = self._read_capped(raw)
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                body, truncated = self._read_capped(exc)
            except Exception:  # noqa: BLE001 - body already partially consumed
                body = b""
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError) as exc:
            error = str(getattr(exc, "reason", exc))
        finally:
            elapsed_ms = (time.monotonic() - started) * 1000.0
            self.guard.record_outcome(status, elapsed_ms)

        self.audit.request(
            component=comp,
            method=method,
            url=redact_url(url),
            host=decision.host,
            path=decision.path,
            role=role,
            credential=credential_handle(self.tokens, role),
            request_headers=redact_headers(hdrs),
            request_body_sha256=_sha(payload),
            request_body_bytes=len(payload) if payload else 0,
            status=status,
            elapsed_ms=round(elapsed_ms, 2),
            response_bytes=len(body),
            response_truncated=truncated,
            error=error,
            note=note,
        )

        if error:
            raise TransportError(f"{method} {url} failed: {error}")

        return Response(
            method=method,
            url=url,
            status=status,
            headers=resp_headers,
            body=body,
            elapsed_ms=elapsed_ms,
            truncated=truncated,
        )

    # -- convenience ----------------------------------------------------------------

    def get(self, path_or_url: str, **kw: Any) -> Response:
        return self.request("GET", path_or_url, **kw)

    def post(self, path_or_url: str, **kw: Any) -> Response:
        return self.request("POST", path_or_url, **kw)

    # -- internals ------------------------------------------------------------------

    def _read_capped(self, raw) -> tuple[bytes, bool]:
        blob = raw.read(self.max_body_bytes + 1)
        if len(blob) > self.max_body_bytes:
            return blob[: self.max_body_bytes], True
        return blob, False


def credential_handle(tokens: TokenStore, role: str | None) -> str:
    if not role:
        return "<anonymous>"
    try:
        return tokens.handle(role)
    except Exception:  # noqa: BLE001 - never fail a request over a log field
        return "<unresolvable>"


def _sha(payload: bytes | None) -> str:
    if not payload:
        return ""
    import hashlib

    return hashlib.sha256(payload).hexdigest()
