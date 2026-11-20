"""The only module in this package that sends a request.

Every call goes: :meth:`ScopeGuard.check` -> audit -> send -> audit -> health monitor.
There is no ``Session``-style escape hatch, redirects are never followed implicitly
(a redirect is a new URL and must re-pass the guard), and response bodies are capped
because the Rules of Engagement forbid bulk data extraction.

Against a real host three things that never happened locally start happening: the
server asks you to slow down (``429``), it is briefly unavailable (``503``), and the
bearer token expires mid-run (``401``).  All three are handled here, and all three keep
the two properties that matter:

* **a retry is a request.**  Every attempt re-passes :meth:`ScopeGuard.check`, so it is
  charged to the budget and appears as its own audit line.  Free retries would make
  ``budget_remaining`` a lie and the audit log incomplete.
* **a retry is bounded.**  ``TransportOptions.retries`` caps attempts,
  ``retry_max_wait`` caps the wait, and an optional wall-clock cap stops a slow host
  from holding the engagement open indefinitely.
"""

from __future__ import annotations

import json as _json
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping

from .audit import AuditLog, redact_headers, redact_url
from .auth import TokenStore, fingerprint
from .errors import STOPPING, DastError, ScopeViolation, TransportError, WallClockExhausted
from .scope import ScopeGuard

DEFAULT_MAX_BODY_BYTES = 512 * 1024

#: Statuses that mean "not now" rather than "not allowed".  401 is handled separately
#: because a credential problem is a different failure from a load problem.
RETRY_STATUSES = frozenset({429, 503})


@dataclass(frozen=True)
class TransportOptions:
    """How patient the client is allowed to be.  All defaults are the local behaviour."""

    timeout: float = 15.0
    retries: int = 2
    retry_max_wait: float = 10.0
    max_wall_clock: float = 0.0

    def __post_init__(self) -> None:
        if self.retries < 0:
            raise DastError("TransportOptions.retries must be >= 0")
        if self.retry_max_wait < 0:
            raise DastError("TransportOptions.retry_max_wait must be >= 0")
        if self.max_wall_clock < 0:
            raise DastError("TransportOptions.max_wall_clock must be >= 0 (0 disables it)")

    @property
    def max_attempts(self) -> int:
        return self.retries + 1


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
        transport: TransportOptions | None = None,
        refresher: Callable[[str], str | None] | None = None,
    ) -> None:
        self.guard = guard
        self.audit = audit
        self.tokens = tokens or TokenStore({})
        self.component = component
        # ``timeout`` is kept for backwards compatibility with existing call sites.
        self.options = transport or TransportOptions(timeout=timeout)
        self.timeout = self.options.timeout
        self.max_body_bytes = max_body_bytes
        self.refresher = refresher
        self._t0 = time.monotonic()

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
        if follow_redirects:
            # Deliberately unsupported: every hop must re-pass the guard, which a
            # silent redirect cannot do.  Callers that need it must issue the request.
            raise DastError("follow_redirects is not supported; issue each hop explicitly")

        url = path_or_url if path_or_url.startswith(("http://", "https://")) else self.url_for(path_or_url)
        comp = component or self.component
        method = method.upper()

        base_headers: dict[str, str] = {
            "User-Agent": self.guard.config.user_agent,
            "Accept": "application/json, */*",
        }
        hdrs = dict(base_headers)
        if role and not allow_anonymous:
            hdrs.update(self.tokens.headers(role))
        hdrs.update({k: v for k, v in (headers or {}).items()})

        payload = data
        if json is not None:
            payload = _json.dumps(json).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        attempt = 0
        refreshed = False
        while True:
            self._check_wall_clock(url)

            # --- authorised? if not, this raises and nothing leaves the process -----
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
                    note=note or ("retry" if attempt else ""),
                )
                raise

            started = time.monotonic()
            status, body, resp_headers, truncated, error = self._send(method, url, payload, hdrs)
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
                attempt=attempt + 1,
            )

            # --- (a) expired credential: refresh once, then retry once --------------
            if status == 401 and role and self.refresher and not refreshed and not error:
                refreshed = True
                if self._refresh(role, comp, note):
                    hdrs = dict(base_headers)
                    hdrs.update(self.tokens.headers(role))
                    hdrs.update({k: v for k, v in (headers or {}).items()})
                    attempt += 1
                    continue

            # --- (b) "not now": back off and retry, within the cap ------------------
            if status in RETRY_STATUSES and not error and attempt < self.options.retries:
                wait = self._retry_wait(resp_headers, attempt)
                self.audit.note(
                    stage="transport",
                    kind="retry",
                    url=redact_url(url),
                    status=status,
                    attempt=attempt + 1,
                    wait_seconds=wait,
                    retry_after=resp_headers.get("Retry-After") or resp_headers.get("retry-after") or "",
                )
                self._sleep(wait)
                attempt += 1
                continue

            break

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

    def _send(
        self, method: str, url: str, payload: bytes | None, hdrs: Mapping[str, str]
    ) -> tuple[int, bytes, dict[str, str], bool, str]:
        req = urllib.request.Request(url, data=payload, headers=dict(hdrs), method=method)
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
        return status, body, resp_headers, truncated, error

    def _read_capped(self, raw) -> tuple[bytes, bool]:
        blob = raw.read(self.max_body_bytes + 1)
        if len(blob) > self.max_body_bytes:
            return blob[: self.max_body_bytes], True
        return blob, False

    def _check_wall_clock(self, url: str) -> None:
        limit = self.options.max_wall_clock
        if limit <= 0:
            return
        elapsed = time.monotonic() - self._t0
        if elapsed >= limit:
            raise WallClockExhausted(
                f"wall-clock budget spent: {elapsed:.1f}s elapsed of {limit:.1f}s "
                f"before {redact_url(url)}. Raise --max-wall-clock or split the run."
            )

    def _retry_wait(self, headers: Mapping[str, str], attempt: int) -> float:
        """``Retry-After`` when the server states it, exponential backoff otherwise."""
        cap = self.options.retry_max_wait
        stated = _retry_after_seconds(headers)
        if stated is None:
            return round(min(cap, float(2**attempt)), 3)
        return round(min(cap, stated), 3)

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        # Slice the wait so a dropped kill file is noticed promptly by the next
        # guard.check, instead of after a long single sleep.
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))

    def _refresh(self, role: str, comp: str, note: str) -> bool:
        """Ask the refresher for a new token.  Failure is a void, never a crash."""
        assert self.refresher is not None
        try:
            token = self.refresher(role)
        except STOPPING:
            raise
        except (ScopeViolation, TransportError, DastError) as exc:
            self.audit.note(
                stage="transport",
                kind="refresh-failed",
                role=role,
                detail=str(exc)[:200],
                note=note,
            )
            return False
        if not token:
            self.audit.note(stage="transport", kind="refresh-empty", role=role, note=note)
            return False
        self.tokens.update(role, token)
        self.audit.note(
            stage="transport",
            kind="token-refreshed",
            role=role,
            credential=fingerprint(token),
            component=comp,
            note=note,
        )
        return True


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    raw = ""
    for key, value in headers.items():
        if key.lower() == "retry-after":
            raw = str(value).strip()
            break
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


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
