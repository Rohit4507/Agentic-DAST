"""Per-role journey recording.

Two recorders:

* :func:`record_journey` — replays a declared journey through the scope-checked
  client and emits HAR entries. Dependency-free, so it works against the mock target
  and is what the test-suite exercises.
* :func:`record_with_playwright` — drives a real browser, logging in as each role and
  capturing every XHR the UI makes. This is the production path; ``playwright`` is an
  optional dependency (``pip install playwright && playwright install chromium``).

Both write the same HAR shape, so :mod:`dast.record.har` consumes either.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..errors import DastError
from ..http import Client
from ..model import utcnow
from .har import entry_from_exchange, write_har


@dataclass
class Step:
    method: str
    path: str
    body: Any = None


def record_journey(
    client: Client,
    *,
    role: str,
    steps: Sequence[Step],
    out_path: str | Path,
    stop_on_error: bool = False,
) -> Path:
    """Replay ``steps`` as ``role`` and write a HAR. All traffic goes through the guard."""
    entries: list[dict[str, Any]] = []
    for step in steps:
        started = utcnow()
        resp = client.request(
            step.method,
            step.path,
            role=role,
            json=step.body,
            component="recorder",
            note=f"journey:{role}",
        )
        if stop_on_error and resp.status >= 400:
            raise DastError(f"journey step failed for {role}: {step.method} {step.path} -> {resp.status}")
        entries.append(
            entry_from_exchange(
                method=step.method,
                url=resp.url,
                request_headers={"Authorization": "<token>", "Accept": "application/json"},
                status=resp.status,
                response_text=resp.text,
                started=started,
                elapsed_ms=resp.elapsed_ms,
            )
        )
    return write_har(out_path, entries, creator="dast-agent/record_journey")


# --------------------------------------------------------------------------------------
# browser recorder (optional dependency)
# --------------------------------------------------------------------------------------

_PLAYWRIGHT_HELP = (
    "Playwright is not installed. Install it with:\n"
    "    pip install playwright && playwright install chromium\n"
    "or record the journey with the dependency-free recorder / supply provided HARs."
)


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    return True


def record_with_playwright(
    *,
    base_url: str,
    role: str,
    login_url: str,
    login_fn: str,
    out_path: str | Path,
    headless: bool = True,
    timeout_ms: int = 20000,
) -> Path:
    """Drive the UI as ``role`` and capture every XHR into a HAR.

    ``login_fn`` is a dotted path to a callable ``fn(page, credentials)`` that performs
    the login interaction (selectors are target-specific, so they live in your
    engagement code, not here). Credentials are read from the token store by the
    caller -- they are never passed through this function's arguments or logged.
    """
    if not playwright_available():
        raise DastError(_PLAYWRIGHT_HELP)
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    import importlib

    module_name, _, attr = login_fn.rpartition(".")
    if not module_name:
        raise DastError(f"login_fn must be a dotted path, got {login_fn!r}")
    perform_login = getattr(importlib.import_module(module_name), attr)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(
            record_har_path=str(out),
            record_har_content="embed",
            ignore_https_errors=False,
        )
        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        page.goto(login_url)
        perform_login(page, role)
        context.close()  # flushes the HAR
        browser.close()
    if not out.exists():
        raise DastError(f"Playwright did not write a HAR to {out}")
    return out


def har_route_summary(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Convenience: role-by-route matrix across several HAR files."""
    from .har import read_har

    matrix: dict[str, set[str]] = {}
    for p in paths:
        for hit in read_har(p):
            matrix.setdefault(f"{hit.method} {hit.template}", set()).add(hit.role)
    return [
        {"route": k, "roles": sorted(v)} for k, v in sorted(matrix.items())
    ]


def dump(matrix: list[dict[str, Any]]) -> str:
    return json.dumps(matrix, indent=2)
