"""The safety layer: fail-closed scope allowlist, rate limiting, budget, kill switch.

Three properties of this module are load-bearing and deliberate:

1. **Fail-closed.**  A URL is denied unless it positively matches an allowlist
   entry. Missing config, unknown config keys, an unparseable URL, or a
   non-canonical path all deny.
2. **Immutable at runtime.**  :class:`ScopeConfig` is frozen and the guard never
   exposes it. There is no ``set_scope()``. An LLM cannot widen its own scope,
   because scope is not in the model's control surface -- only in a file a human
   wrote.
3. **Deny beats allow.**  ``/api/refund/bulk`` is refused even though
   ``/api/refund`` is allowed.

Nothing here sends a request; :mod:`dast.http` is the only module that can, and it
must call :meth:`ScopeGuard.check` first.
"""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from .errors import BudgetExhausted, DastError, KillSwitchEngaged, ScopeViolation

# --------------------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------------------

_REQUIRED_KEYS = {"allow_hosts", "allow_paths"}
_KNOWN_KEYS = {
    "name",
    "description",
    "base_url",
    "allow_hosts",
    "allow_paths",
    "deny_paths",
    "allow_methods",
    "max_rps_per_host",
    "max_burst",
    "max_total_requests",
    "max_wait_seconds",
    "accounts",
    "role_agencies",
    "kill_switch_file",
    "strain_window",
    "strain_5xx_ratio",
    "strain_pause_seconds",
    "traffic_window_days",
    "js_bundles",
    "assets_file",
    "allow_insecure_tls",
    "user_agent",
    "profile",
}

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


@dataclass(frozen=True)
class ScopeConfig:
    """A validated, immutable engagement scope. Construct via :meth:`load`."""

    allow_hosts: tuple[str, ...]
    allow_paths: tuple[str, ...]
    deny_paths: tuple[str, ...] = ()
    allow_methods: tuple[str, ...] = ("GET",)
    name: str = "unnamed-engagement"
    description: str = ""
    base_url: str = ""
    max_rps_per_host: float = 2.0
    max_burst: int = 3
    max_total_requests: int = 500
    max_wait_seconds: float = 20.0
    accounts: Mapping[str, str] = field(default_factory=dict)
    role_agencies: Mapping[str, str] = field(default_factory=dict)
    kill_switch_file: str = "KILL"
    strain_window: int = 20
    strain_5xx_ratio: float = 0.25
    strain_pause_seconds: float = 15.0
    traffic_window_days: int = 30
    js_bundles: tuple[str, ...] = ()
    assets_file: str = ""
    allow_insecure_tls: bool = False
    #: Path to the target profile (vocabulary: paths, bodies, field names).
    #: Empty means "the bundled mock's vocabulary", i.e. version-1 behaviour.
    profile: str = ""
    user_agent: str = "dast-agent/0.1 (scope-checked; security testing)"

    # -- construction ---------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "ScopeConfig":
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise DastError(f"scope file not found: {p}") from exc
        except json.JSONDecodeError as exc:
            raise DastError(f"scope file is not valid JSON ({p}): {exc}") from exc
        if not isinstance(raw, dict):
            raise DastError(f"scope file must contain a JSON object: {p}")
        return cls.from_mapping(raw, source=str(p))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, source: str = "<dict>") -> "ScopeConfig":
        unknown = set(raw) - _KNOWN_KEYS
        if unknown:
            # Loud, not silent: a typo in a *deny* key must not quietly disappear.
            raise DastError(
                f"unknown key(s) in {source}: {', '.join(sorted(unknown))}. "
                f"Known keys: {', '.join(sorted(_KNOWN_KEYS))}"
            )
        missing = _REQUIRED_KEYS - set(raw)
        if missing:
            raise DastError(f"missing required key(s) in {source}: {', '.join(sorted(missing))}")

        hosts = tuple(_norm_host(h) for h in raw["allow_hosts"])
        if not hosts:
            raise DastError("allow_hosts is empty; refusing to build a scope that permits nothing")
        for h in hosts:
            if "*" in h and not h.startswith("*."):
                raise DastError(f"unsupported host pattern {h!r}; use an exact host or '*.suffix'")

        methods = tuple(m.upper() for m in raw.get("allow_methods", _SAFE_METHODS))
        for m in methods:
            if m not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
                raise DastError(f"unsupported HTTP method in allow_methods: {m}")

        paths = tuple(_norm_path(p) for p in raw["allow_paths"])
        deny = tuple(_norm_path(p) for p in raw.get("deny_paths", ()))
        for p in paths + deny:
            if not p.startswith("/"):
                raise DastError(f"scope path must be absolute: {p!r}")

        accounts = raw.get("accounts", {}) or {}
        if not isinstance(accounts, dict):
            raise DastError("accounts must be an object of role -> 'env:VAR' / 'literal:VALUE'")

        return cls(
            allow_hosts=hosts,
            allow_paths=paths,
            deny_paths=deny,
            allow_methods=methods,
            name=str(raw.get("name", "unnamed-engagement")),
            description=str(raw.get("description", "")),
            base_url=str(raw.get("base_url", "")).rstrip("/"),
            max_rps_per_host=float(raw.get("max_rps_per_host", 2.0)),
            max_burst=int(raw.get("max_burst", 3)),
            max_total_requests=int(raw.get("max_total_requests", 500)),
            max_wait_seconds=float(raw.get("max_wait_seconds", 20.0)),
            accounts={str(k): str(v) for k, v in accounts.items()},
            role_agencies={str(k): str(v) for k, v in (raw.get("role_agencies", {}) or {}).items()},
            kill_switch_file=str(raw.get("kill_switch_file", "KILL")),
            strain_window=int(raw.get("strain_window", 20)),
            strain_5xx_ratio=float(raw.get("strain_5xx_ratio", 0.25)),
            strain_pause_seconds=float(raw.get("strain_pause_seconds", 15.0)),
            traffic_window_days=int(raw.get("traffic_window_days", 30)),
            js_bundles=tuple(str(b) for b in raw.get("js_bundles", ())),
            assets_file=str(raw.get("assets_file", "")),
            allow_insecure_tls=bool(raw.get("allow_insecure_tls", False)),
            profile=str(raw.get("profile", "") or ""),
            user_agent=str(raw.get("user_agent", "dast-agent/0.1 (scope-checked; security testing)")),
        )

    # -- presentation ---------------------------------------------------------------

    def summarize(self) -> str:
        return (
            f"{self.name}: {len(self.allow_hosts)} host(s), {len(self.allow_paths)} allowed "
            f"path(s), {len(self.deny_paths)} denied, {self.max_rps_per_host} rps/host, "
            f"budget {self.max_total_requests} requests"
        )


def _norm_host(host: str) -> str:
    h = str(host).strip().lower().rstrip(".")
    if not h:
        raise DastError("empty host in allow_hosts")
    if "://" in h:
        raise DastError(f"allow_hosts entries must be bare hostnames, got {host!r}")
    if "/" in h:
        raise DastError(f"allow_hosts entries must not contain a path, got {host!r}")
    return h


def _norm_path(path: str) -> str:
    """Normalise an allowlist path entry (not a request path)."""
    p = str(path).strip()
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return p


# --------------------------------------------------------------------------------------
# canonicalisation of *request* paths
# --------------------------------------------------------------------------------------

_WS_RE = re.compile(r"[\x00-\x20\x7f]")


class NonCanonicalPath(ValueError):
    """The request path would change meaning if normalised; refuse to send it."""


def canonical_path(raw_path: str) -> str:
    """Return the single canonical form of a request path, or raise.

    Scope checks are worthless if the checker and the HTTP stack disagree about what
    a path means. Rather than guess, we refuse anything ambiguous:

    * percent-decoding must not change the path (blocks ``%2f``, ``%2e%2e``)
    * no control characters, backslashes or whitespace
    * ``posixpath.normpath`` must not change the path (blocks ``..``, ``//``, ``.``)
    * the path must be absolute
    """
    if not raw_path:
        return "/"
    if "\\" in raw_path:
        raise NonCanonicalPath(f"backslash in path: {raw_path!r}")
    if _WS_RE.search(raw_path):
        raise NonCanonicalPath(f"control character or whitespace in path: {raw_path!r}")
    if not raw_path.startswith("/"):
        raise NonCanonicalPath(f"path is not absolute: {raw_path!r}")

    decoded = raw_path
    for _ in range(3):  # catch double/triple encoding
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if decoded != raw_path:
        raise NonCanonicalPath(f"percent-encoding changes the path: {raw_path!r} -> {decoded!r}")

    norm = posixpath.normpath(decoded)
    if norm != decoded:
        raise NonCanonicalPath(f"non-canonical path: {raw_path!r} normalises to {norm!r}")
    return decoded


def _path_matches_prefix(path: str, prefix: str) -> bool:
    """Segment-aware prefix match: ``/api/refund`` allows ``/api/refund`` and below."""
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


# --------------------------------------------------------------------------------------
# token bucket
# --------------------------------------------------------------------------------------


class TokenBucket:
    """Per-host rate limiter. ``capacity`` = burst, ``rate`` = sustained rps."""

    def __init__(self, rate: float, capacity: int, *, clock=time.monotonic) -> None:
        self.rate = max(rate, 0.001)
        self.capacity = max(capacity, 1)
        self._tokens = float(self.capacity)
        self._last = clock()
        self._clock = clock
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(now - self._last, 0.0)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def try_take(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def seconds_until_token(self) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                return 0.0
            return (1.0 - self._tokens) / self.rate

    def take(self) -> None:
        """Take a token, sleeping if needed. Raises rather than sleeping forever."""
        raise NotImplementedError  # handled by ScopeGuard with max_wait


# --------------------------------------------------------------------------------------
# guard
# --------------------------------------------------------------------------------------


@dataclass
class Decision:
    allowed: bool
    reason: str
    url: str
    host: str
    path: str


@dataclass
class GuardStats:
    checked: int = 0
    denied: int = 0
    sent: int = 0
    failed: int = 0  # cumulative transport/5xx failures; "errors" in the snapshot is windowed
    waited_seconds: float = 0.0
    strain_pauses: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "denied": self.denied,
            "sent": self.sent,
            "failed": self.failed,
            "waited_seconds": round(self.waited_seconds, 3),
            "strain_pauses": self.strain_pauses,
        }


class ScopeGuard:
    """The single chokepoint. Every outbound request is authorised here first."""

    def __init__(self, cfg: ScopeConfig, *, clock=time.monotonic, sleeper=time.sleep) -> None:
        self.__cfg = cfg
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._total = 0
        self._outcomes: list[tuple[float, int, float]] = []  # (ts, status, latency_ms)
        self._clock = clock
        self._sleep = sleeper
        self.stats = GuardStats()
        self._stopped = False

    # -- read-only surface ----------------------------------------------------------

    @property
    def config(self) -> ScopeConfig:
        """Read-only view (frozen dataclass). There is no setter, deliberately."""
        return self.__cfg

    @property
    def requests_sent(self) -> int:
        return self.stats.sent

    @property
    def budget_remaining(self) -> int:
        return max(0, self.__cfg.max_total_requests - self._total)

    def stop(self, reason: str = "operator stop") -> None:
        """Global kill switch, honoured mid-flight by the next request."""
        self._stopped = True
        self._stop_reason = reason

    # -- the gate -------------------------------------------------------------------

    def check(self, method: str, url: str, *, charge: bool = True) -> Decision:
        """Authorise one request. Raises :class:`ScopeViolation` to deny.

        ``charge=False`` is for dry runs (guard demos, --dry-run) that must not
        consume budget.
        """
        with self._lock:
            self.stats.checked += 1
        try:
            host, path = self._parse(url)
            self._check_method(method)
            self._check_host(host)
            self._check_kill_switch()
            self._check_path(path)
            if charge:
                self._charge_budget()
                self._wait_for_rate(host)
                self._maybe_pause_for_strain()
        except ScopeViolation:
            with self._lock:
                self.stats.denied += 1
            raise
        return Decision(allowed=True, reason="allowlisted", url=url, host=host, path=path)

    def record_outcome(self, status: int, latency_ms: float) -> None:
        """Feed the health monitor. ``status <= 0`` means transport failure."""
        with self._lock:
            self.stats.sent += 1
            if status <= 0 or status >= 500:
                self.stats.failed += 1
            self._outcomes.append((self._clock(), status, latency_ms))
            if len(self._outcomes) > 500:
                del self._outcomes[: len(self._outcomes) - 500]

    # -- individual checks ----------------------------------------------------------

    def _parse(self, url: str) -> tuple[str, str]:
        if not isinstance(url, str) or not url:
            raise ScopeViolation("empty-url", url=str(url))
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise ScopeViolation("unparseable-url", url=url, detail=str(exc)) from exc
        if parts.scheme not in ("http", "https"):
            raise ScopeViolation("scheme-not-allowed", url=url, detail=parts.scheme or "none")
        if "@" in (parts.netloc or ""):
            # http://allowed.host@evil.host/ -- userinfo smuggling
            raise ScopeViolation("userinfo-in-url", url=url)
        if not parts.hostname:
            raise ScopeViolation("no-host", url=url)
        if parts.fragment:
            raise ScopeViolation("fragment-in-url", url=url)
        host = _norm_host(parts.hostname)
        try:
            canonical_path(parts.path or "/")
        except NonCanonicalPath as exc:
            raise ScopeViolation("non-canonical-path", url=url, detail=str(exc)) from exc
        return host, (parts.path or "/")

    def _check_method(self, method: str) -> None:
        m = (method or "").upper()
        if m not in self.__cfg.allow_methods:
            raise ScopeViolation(
                "method-not-allowed",
                url="",
                detail=f"{m} not in {list(self.__cfg.allow_methods)}",
            )

    def _check_host(self, host: str) -> None:
        # Reject IP-vs-name confusion: a bare IP literal only matches an exact IP entry.
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        for pattern in self.__cfg.allow_hosts:
            if literal:
                if host == pattern:
                    return
            elif _host_matches(host, pattern):
                return
        raise ScopeViolation("host-not-allowed", detail=f"{host} not in {list(self.__cfg.allow_hosts)}")

    def _check_kill_switch(self) -> None:
        if self._stopped:
            raise KillSwitchEngaged("operator-stop", detail=getattr(self, "_stop_reason", ""))
        kf = self.__cfg.kill_switch_file
        if kf and Path(kf).exists():
            raise KillSwitchEngaged("kill-file-present", detail=str(kf))

    def _check_path(self, path: str) -> None:
        for denied in self.__cfg.deny_paths:
            if _path_matches_prefix(path, denied):
                raise ScopeViolation(
                    "path-denied", detail=f"{path} matches denied prefix {denied}"
                )
        for allowed in self.__cfg.allow_paths:
            if _path_matches_prefix(path, allowed):
                return
        raise ScopeViolation(
            "path-not-allowlisted",
            detail=f"{path} matches none of {list(self.__cfg.allow_paths)}",
        )

    def _charge_budget(self) -> None:
        with self._lock:
            if self._total >= self.__cfg.max_total_requests:
                raise BudgetExhausted(
                    "budget-exhausted",
                    detail=f"{self.__cfg.max_total_requests} requests already authorised",
                )
            self._total += 1

    def _bucket_for(self, host: str) -> TokenBucket:
        with self._lock:
            b = self._buckets.get(host)
            if b is None:
                b = TokenBucket(self.__cfg.max_rps_per_host, self.__cfg.max_burst, clock=self._clock)
                self._buckets[host] = b
            return b

    def _wait_for_rate(self, host: str) -> None:
        bucket = self._bucket_for(host)
        waited = 0.0
        while not bucket.try_take():
            wait = bucket.seconds_until_token()
            if waited + wait > self.__cfg.max_wait_seconds:
                raise ScopeViolation(
                    "rate-limit-wait-exceeded",
                    detail=f"would wait {waited + wait:.1f}s > {self.__cfg.max_wait_seconds}s",
                )
            self._sleep(max(wait, 0.01))
            waited += wait
        if waited:
            with self._lock:
                self.stats.waited_seconds += waited

    def _maybe_pause_for_strain(self) -> None:
        """Back off when *our own* traffic is hurting the target (RoE: 'shows strain')."""
        window = self.__cfg.strain_window
        with self._lock:
            recent = self._outcomes[-window:]
        if len(recent) < window:
            return
        failures = sum(1 for _, status, _ in recent if status <= 0 or status >= 500)
        if failures / len(recent) >= self.__cfg.strain_5xx_ratio:
            with self._lock:
                self.stats.strain_pauses += 1
            self._sleep(self.__cfg.strain_pause_seconds)
            with self._lock:
                self._outcomes.clear()  # give the target a clean slate after the pause

    # -- introspection --------------------------------------------------------------

    def health_snapshot(self) -> dict[str, Any]:
        with self._lock:
            recent = list(self._outcomes[-self.__cfg.strain_window :])
        latencies = sorted(lat for _, _, lat in recent)
        p95 = latencies[int(len(latencies) * 0.95) - 1] if latencies else 0.0
        errors = sum(1 for _, s, _ in recent if s <= 0 or s >= 500)
        return {
            "window": len(recent),
            "errors": errors,
            "error_ratio": round(errors / len(recent), 3) if recent else 0.0,
            "p95_latency_ms": round(p95, 1),
            **self.stats.as_dict(),
            "budget_remaining": self.budget_remaining,
        }
