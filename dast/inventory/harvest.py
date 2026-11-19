"""Static route harvest from front-end JavaScript.

The participant pack: *"reading front-end JavaScript for API routes"*, and for
zombie/shadow discovery, *"reading old front-end JavaScript bundles ... for routes no
longer called"*.

Deliberately simple: a regex over bundle text plus template normalisation. The
research pack points at heavier AST / source-map tooling (Shadow-Endpoints) for
obfuscated SPAs; this stays dependency-free and predictable, which matters more in a
48-hour build than recall on minified bundles.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Any quoted absolute path, in any quote style, including template literals with ${...}
_QUOTED = re.compile(r"""(?P<q>["'`])(?P<path>/[A-Za-z0-9_\-./{}$:]*)(?P=q)""")
# Unquoted references (route tables, concatenations). Must not be preceded by a
# word character, a quote or a slash -- that keeps us out of the middle of other tokens.
_PLAIN = re.compile(r"""(?<![\w"'`/])/?api/[A-Za-z0-9_\-./{}$:]{2,120}""")
_PLACEHOLDER = re.compile(r"\$\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\}")

# Comments are stripped before harvesting: a route mentioned only in a comment is not
# a route. (Naive tools that skip this step report dead paths as live endpoints.)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?<!:)//[^\n]*")


def strip_comments(text: str) -> str:
    """Remove /* */ and // comments. ``://`` in URLs is preserved."""
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


@dataclass
class HarvestResult:
    source: str
    sha256: str
    routes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source, "sha256": self.sha256, "routes": sorted(self.routes)}


def normalise_js_route(raw: str) -> str | None:
    """Turn a JS route string into a path template, or None if unusable."""
    if not raw or "://" in raw:
        return None
    path = raw.split("?", 1)[0].split("#", 1)[0]
    path = _PLACEHOLDER.sub("{id}", path)
    if not path.startswith("/"):
        path = "/" + path
    if not path.startswith("/api/"):
        return None
    if path.count("{id}") > 4:
        return None
    # rebuild cleanly: template_of only knows numeric ids, so re-apply placeholders here
    segments = []
    for seg in path.strip("/").split("/"):
        segments.append("{id}" if seg == "{id}" or seg.isdigit() else seg)
    return "/" + "/".join(segments)


def harvest_text(text: str) -> set[str]:
    text = strip_comments(text or "")
    found: set[str] = set()
    for m in _QUOTED.finditer(text):
        r = normalise_js_route(m.group("path"))
        if r:
            found.add(r)
    for m in _PLAIN.finditer(text):
        r = normalise_js_route(m.group(0))
        if r:
            found.add(r)
    return found


def harvest_file(path: str | Path) -> HarvestResult:
    p = Path(path)
    blob = p.read_bytes()
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - never fail the scan on a weird bundle
        text = ""
    return HarvestResult(
        source=str(p),
        sha256=hashlib.sha256(blob).hexdigest(),
        routes=sorted(harvest_text(text)),
    )


def harvest_files(paths: Iterable[str | Path]) -> list[HarvestResult]:
    return [harvest_file(p) for p in paths]


def union_routes(results: Iterable[HarvestResult]) -> set[str]:
    out: set[str] = set()
    for r in results:
        out |= set(r.routes)
    return out


# --------------------------------------------------------------------------------------
# bundle change detection (the "detect change" stage)
# --------------------------------------------------------------------------------------


def load_bundle_state(path: str | Path) -> dict[str, dict]:
    """``source -> {"sha256": ..., "routes": [...]}`` (tolerates the older hash-only form)."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    out: dict[str, dict] = {}
    for source, value in (raw or {}).items():
        if isinstance(value, str):
            out[source] = {"sha256": value, "routes": []}
        elif isinstance(value, dict):
            out[source] = {
                "sha256": str(value.get("sha256", "")),
                "routes": [str(r) for r in value.get("routes", [])],
            }
    return out


def save_bundle_state(path: str | Path, results: Iterable[HarvestResult]) -> dict[str, dict]:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    state = {r.source: {"sha256": r.sha256, "routes": sorted(r.routes)} for r in results}
    p.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return state


def routes_from_state(state: dict[str, dict], sources: Iterable[str] | None = None) -> set[str]:
    wanted = set(sources) if sources else None
    out: set[str] = set()
    for source, value in state.items():
        if wanted is not None and source not in wanted:
            continue
        out |= set(value.get("routes", []))
    return out


def diff_route_sets(old: set[str], new: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(new - old),
        "removed": sorted(old - new),
        "unchanged": sorted(new & old),
    }


def changed_bundles(results: Iterable[HarvestResult], state: dict[str, dict]) -> list[HarvestResult]:
    """Bundles whose hash differs from the stored state (a bundle with no history counts as changed)."""
    changed: list[HarvestResult] = []
    for r in results:
        if state.get(r.source, {}).get("sha256") != r.sha256:
            changed.append(r)
    return changed


# --------------------------------------------------------------------------------------
# probing for undocumented siblings (old versions, debug paths)
# --------------------------------------------------------------------------------------

_VERSION_HINTS = ("v1", "v2", "v3", "old", "legacy", "internal", "test", "beta", "debug")
_SEGMENT_HINT = re.compile(r"^/(api)/(?:" + "|".join(_VERSION_HINTS) + r")/")


def probe_candidates_from(templates: Iterable[str], *, known: Iterable[str] = (), per_prefix: int = 3) -> list[str]:
    """Guess older/undocumented siblings of known routes.

    ``/api/booking/{id}`` -> ``/api/v1/booking/{id}``, ``/api/old/booking/{id}``,
    ``/api/internal/booking/{id}`` ... exactly the naming-pattern guessing the pack
    describes. The caller must still pass every probe through the scope guard, and
    should cap the count (``per_prefix``).
    """
    known_set = set(known)
    out: list[str] = []
    for tpl in sorted(set(templates)):
        if _SEGMENT_HINT.match(tpl):
            continue
        tail = tpl[len("/api") :]
        for hint in _VERSION_HINTS[:per_prefix]:
            cand = f"/api/{hint}{tail}"
            if cand not in known_set and cand not in out:
                out.append(cand)
    return out
