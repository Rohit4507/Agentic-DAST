"""Change detection from a real deployment, not from a local file's mtime.

The loop's first stage is "what changed".  Version 2 diffed the hash of a JS bundle on
disk, which is only change detection if someone remembered to download the bundle after
every deploy.  A CI job already knows this precisely, so it can hand it over:

    python run.py diff --deploy-event event.json

```json
{
  "sha": "4f2c1ab",
  "service": "tbo-orders-api",
  "at": "2026-11-19T09:14:00Z",
  "changed_paths": ["/v2/orders/{id}/refund", "/v2/orders/{id}/reprice"],
  "bundle_urls": ["https://cdn.example.com/orders/app.js"]
}
```

Rules, because a trigger that lies is worse than no trigger:

* ``sha`` is required and is the idempotency key -- replaying the same event must not
  re-run the scan (a webhook that retries delivery is normal).
* ``changed_paths`` are normalised to templates and **matched against the inventory**.
  If none of them is a known route the run says so explicitly rather than reporting an
  empty delta.
* ``bundle_urls`` are fetched through the scope-checked client, so they cost budget and
  appear in the audit log like any other request.
* the event is a *hint*, never an allowlist: a path in the event that the scope forbids
  is reported, not fetched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .errors import DastError
from .model import template_of

_KNOWN = {"sha", "service", "at", "changed_paths", "bundle_urls", "actor"}
_STATE_VERSION = 1


def _fail(msg: str) -> None:
    raise DastError(f"deploy event: {msg}")


def normalise_path(raw: Any) -> str:
    """Accept a path, a URL, or a path without its leading slash.  Return a path."""
    if not isinstance(raw, str) or not raw.strip():
        _fail(f"changed_paths entries must be non-empty strings, got {raw!r}")
    text = raw.strip()
    if text.startswith(("http://", "https://")):
        text = urlsplit(text).path or "/"
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    return text


@dataclass(frozen=True)
class DeployEvent:
    sha: str
    service: str = ""
    at: str = ""
    actor: str = ""
    changed_paths: tuple[str, ...] = ()
    bundle_urls: tuple[str, ...] = ()
    source: str = "<dict>"

    @classmethod
    def load(cls, path: str | Path) -> "DeployEvent":
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise DastError(f"deploy event not found: {p}") from exc
        except json.JSONDecodeError as exc:
            raise DastError(f"deploy event is not valid JSON ({p}): {exc}") from exc
        return cls.from_mapping(raw, source=str(p))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, source: str = "<dict>") -> "DeployEvent":
        if not isinstance(raw, Mapping):
            _fail(f"{source} must be a JSON object")
        unknown = sorted(set(raw) - _KNOWN)
        if unknown:
            _fail(f"unknown key(s) {unknown} in {source}; known: {sorted(_KNOWN)}")
        sha = raw.get("sha")
        if not isinstance(sha, str) or not sha.strip():
            _fail("sha is required (it is the idempotency key: a retried webhook must not re-run)")

        def _list(key: str) -> tuple[str, ...]:
            value = raw.get(key) or []
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                _fail(f"{key} must be a list of strings")
            return tuple(value)

        urls = _list("bundle_urls")
        for url in urls:
            if not url.startswith(("http://", "https://")):
                _fail(f"bundle_urls entries must be absolute URLs, got {url!r}")

        at = raw.get("at") or ""
        if at and not isinstance(at, str):
            _fail("at must be an ISO-8601 string")

        return cls(
            sha=sha.strip(),
            service=str(raw.get("service") or ""),
            at=str(at),
            actor=str(raw.get("actor") or ""),
            changed_paths=tuple(normalise_path(p) for p in _list("changed_paths")),
            bundle_urls=urls,
            source=source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "service": self.service,
            "at": self.at,
            "actor": self.actor,
            "changed_paths": list(self.changed_paths),
            "bundle_urls": list(self.bundle_urls),
        }

    def routes(self) -> list[str]:
        """Changed paths as templates, de-duplicated, in the order the deploy listed them."""
        out: list[str] = []
        for path in self.changed_paths:
            template, _ids = template_of(path)
            if template not in out:
                out.append(template)
        return out


@dataclass
class DeployState:
    """What the last processed deployment looked like."""

    sha: str = ""
    service: str = ""
    at: str = ""
    processed_at: str = ""
    routes: tuple[str, ...] = ()
    bundle_routes: tuple[str, ...] = ()
    history: tuple[str, ...] = ()
    version: int = _STATE_VERSION

    @classmethod
    def load(cls, path: str | Path) -> "DeployState":
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corrupt state file must not stop a run; it only costs a re-diff.
            return cls()
        if not isinstance(raw, Mapping):
            return cls()
        return cls(
            sha=str(raw.get("sha") or ""),
            service=str(raw.get("service") or ""),
            at=str(raw.get("at") or ""),
            processed_at=str(raw.get("processed_at") or ""),
            routes=tuple(str(r) for r in (raw.get("routes") or [])),
            bundle_routes=tuple(str(r) for r in (raw.get("bundle_routes") or [])),
            history=tuple(str(h) for h in (raw.get("history") or [])),
            version=int(raw.get("version") or _STATE_VERSION),
        )

    def already_processed(self, event: DeployEvent) -> bool:
        return bool(self.sha) and self.sha == event.sha

    def record(
        self,
        event: DeployEvent,
        routes: Iterable[str],
        *,
        now: datetime,
        bundle_routes: Iterable[str] = (),
    ) -> "DeployState":
        keep = (event.sha,) + tuple(s for s in self.history if s != event.sha)
        return DeployState(
            sha=event.sha,
            service=event.service,
            at=event.at,
            processed_at=now.isoformat(),
            routes=tuple(routes),
            bundle_routes=tuple(sorted(bundle_routes)),
            history=keep[:20],
            version=_STATE_VERSION,
        )

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(
                {
                    "version": self.version,
                    "sha": self.sha,
                    "service": self.service,
                    "at": self.at,
                    "processed_at": self.processed_at,
                    "routes": list(self.routes),
                    "bundle_routes": list(self.bundle_routes),
                    "history": list(self.history),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return p

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "service": self.service,
            "at": self.at,
            "processed_at": self.processed_at,
            "routes": list(self.routes),
            "bundle_routes": list(self.bundle_routes),
            "history": list(self.history),
        }


@dataclass
class DeployAssessment:
    """What the event means for this engagement, including what it does *not* cover."""

    event: DeployEvent
    to_test: list[str] = field(default_factory=list)
    not_inventoried: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    new_routes: list[str] = field(default_factory=list)
    bundle_routes: list[str] = field(default_factory=list)
    inventory_known: int = 0

    @property
    def usable(self) -> bool:
        return bool(self.to_test)

    def summary(self) -> str:
        if not self.event.changed_paths and not self.event.bundle_urls:
            return "event carries no changed paths and no bundle URLs: nothing to prioritise"
        if not self.to_test:
            return (
                f"deploy {self.event.sha[:8]} touched {len(self.event.changed_paths)} path(s), "
                f"none of them an inventoried route -- run 'python run.py inventory' first"
            )
        sources: list[str] = []
        if self.event.changed_paths:
            sources.append(f"{len(self.event.changed_paths)} changed path(s)")
        if self.event.bundle_urls:
            sources.append(f"{len(self.event.bundle_urls)} bundle URL(s)")
        return (
            f"deploy {self.event.sha[:8]} touched {' + '.join(sources) or 'nothing'}; "
            f"{len(self.to_test)} route(s) to test first, "
            f"{len(self.not_inventoried)} not yet in the inventory"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "to_test": list(self.to_test),
            "not_inventoried": list(self.not_inventoried),
            "removed": list(self.removed),
            "new_routes": list(self.new_routes),
            "bundle_routes": list(self.bundle_routes),
            "inventory_known": self.inventory_known,
            "summary": self.summary(),
        }


def inventory_templates(path: str | Path) -> list[str]:
    """Read the last inventory run's endpoint templates, if there is one."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = raw.get("endpoints") if isinstance(raw, Mapping) else None
    if not isinstance(rows, list):
        return []
    out: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        # work/inventory.json calls it path_template; older/hand-made inventories use template.
        value = row.get("path_template") or row.get("template")
        if isinstance(value, str) and value:
            out.append(value)
    return out


def assess(
    event: DeployEvent,
    *,
    inventory_path: str | Path,
    previous: DeployState | None = None,
    bundle_routes: Iterable[str] = (),
) -> DeployAssessment:
    known = inventory_templates(inventory_path)
    known_set = set(known)
    current_bundle = sorted(set(bundle_routes))
    previous_bundle = set(previous.bundle_routes) if previous is not None else set()
    # Only a real comparison can produce a delta; a first bundle is a baseline, not news.
    new_routes = sorted(set(current_bundle) - previous_bundle) if previous_bundle else []
    removed = sorted(previous_bundle - set(current_bundle)) if previous_bundle and current_bundle else []

    # Candidates: what CI said changed, then genuinely new surface, then -- if the event
    # names nothing -- everything the bundle advertises.
    candidates = event.routes()
    for route in new_routes:
        if route not in candidates:
            candidates.append(route)
    if not candidates:
        candidates = list(current_bundle)

    to_test = [r for r in candidates if r in known_set] if known else list(candidates)
    not_inventoried = [r for r in candidates if known and r not in known_set]

    return DeployAssessment(
        event=event,
        to_test=to_test,
        not_inventoried=not_inventoried,
        removed=removed,
        new_routes=new_routes,
        bundle_routes=current_bundle,
        inventory_known=len(known),
    )
