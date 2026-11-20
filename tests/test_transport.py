"""Transport behaviour against a hostile host: 429, 503, 401, and slow servers.

Two properties are asserted on every retry path and are the reason this file exists:

1. a retry is a *request* -- it passes the guard, spends budget, and gets its own audit
   line, so ``budget_remaining`` and the audit log stay truthful;
2. a retry is *bounded* -- by ``retries``, by ``retry_max_wait``, and by the wall clock.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from contextlib import redirect_stderr
from io import StringIO

from dast.audit import verify_chain
from dast.cli import main
from dast.errors import BudgetExhausted, WallClockExhausted
from dast.http import TransportOptions, _retry_after_seconds
from dast.pipeline import open_engagement

FRESH_TOKEN = "fresh-token"
SECRET = "s3cr3t-should-never-be-logged"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    verbose = False

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass

    # -- helpers --------------------------------------------------------------------
    def _send(self, status: int, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        blob = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(blob)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            parsed = json.loads(self.rfile.read(length).decode())
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        query = parse_qs(parts.query)
        state = self.server.state  # type: ignore[attr-defined]
        state["hits"][path] = state["hits"].get(path, 0) + 1

        if state.get("fail_all"):
            self._send(500, {"error": "everything is down"})
            return

        if path == "/flaky":
            allow = int(query.get("allow", ["2"])[0])
            code = int(query.get("code", ["429"])[0])
            if state["hits"][path] <= allow:
                headers = {"Retry-After": "0"} if code == 429 else {}
                self._send(code, {"error": "not now"}, headers)
                return
            self._send(200, {"ok": True, "attempts": state["hits"][path]})
            return

        if path == "/always":
            code = int(query.get("code", ["503"])[0])
            self._send(code, {"error": "still not now"})
            return

        if path == "/slow":
            time.sleep(float(query.get("ms", ["150"])[0]) / 1000.0)
            self._send(200, {"ok": True})
            return

        if path == "/token":
            body = self._body()
            state["token_requests"].append(body)
            if body.get("client_id") == "id-a" and body.get("client_secret") == SECRET:
                self._send(200, {"access_token": FRESH_TOKEN, "expires_in": 3600})
                return
            self._send(401, {"error": "bad client"})
            return

        if path == "/secure":
            header = self.headers.get("Authorization") or ""
            if header == f"Bearer {FRESH_TOKEN}":
                self._send(200, {"ok": True, "data": {"tenant": "TN-A"}})
                return
            self._send(401, {"error_expired": "token expired"})
            return

        self._send(404, {"error": "no such route"})


def _server() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.state = {"hits": {}, "token_requests": []}  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _scope_doc(base: str, *, paths: list[str], auth: dict | None = None, budget: int = 100) -> dict:
    doc: dict[str, Any] = {
        "name": "transport-test",
        "base_url": base,
        "allow_hosts": ["127.0.0.1"],
        "allow_methods": ["GET", "POST"],
        "allow_paths": paths,
        "deny_paths": [],
        "max_rps_per_host": 100,
        "max_burst": 100,
        "max_total_requests": budget,
        "max_wait_seconds": 5,
        "accounts": {"agency_a": "literal:stale-token"},
        "kill_switch_file": "/tmp/dast-transport-KILL",
    }
    if auth:
        doc["auth"] = auth
    return doc


class TransportCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base = _server()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmp.cleanup()

    def setUp(self) -> None:
        # The stub server is shared, so per-path counters must be reset per test.
        self.server.state["hits"].clear()
        self.server.state["token_requests"].clear()

    def _engage(self, name: str, *, paths: list[str], auth: dict | None = None, **options: Any):
        scope = self.root / f"{name}.json"
        scope.write_text(json.dumps(_scope_doc(self.base, paths=paths, auth=auth), indent=2))
        return open_engagement(scope, self.root / name, transport=TransportOptions(**options))

    def _audit(self, eng) -> list[dict[str, Any]]:
        return [json.loads(line) for line in eng.audit.path.read_text().splitlines()]


class TestRetryOn429(TransportCase):
    def test_retries_are_charged_and_audited(self) -> None:
        eng = self._engage("flaky", paths=["/flaky"], retries=2, retry_max_wait=1.0)
        resp = eng.client.get("/flaky?allow=2&code=429")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.json()["attempts"], 3)

        # Each attempt spent budget and produced its own audit line.
        self.assertEqual(eng.guard.stats.checked, 3)
        self.assertEqual(eng.guard.stats.sent, 3)
        self.assertEqual(eng.cfg.max_total_requests - eng.guard.stats.checked, 97)
        requests = [e for e in self._audit(eng) if e.get("event") == "request"]
        self.assertEqual(len(requests), 3)
        self.assertEqual([e["attempt"] for e in requests], [1, 2, 3])
        retries = [e for e in self._audit(eng) if e.get("kind") == "retry"]
        self.assertEqual(len(retries), 2)
        self.assertTrue(all(r["status"] == 429 for r in retries))

        ok, seq, detail = verify_chain(eng.audit.path)
        self.assertTrue(ok, f"chain broken at {seq}: {detail}")

    def test_retries_zero_means_one_attempt(self) -> None:
        eng = self._engage("no-retry", paths=["/flaky"], retries=0)
        resp = eng.client.get("/flaky?allow=5&code=429")
        self.assertEqual(resp.status, 429)
        self.assertEqual(eng.guard.stats.checked, 1)

    def test_exhausting_retries_returns_the_last_response(self) -> None:
        eng = self._engage("exhausted", paths=["/flaky"], retries=1, retry_max_wait=0.01)
        resp = eng.client.get("/flaky?allow=9&code=429")
        self.assertEqual(resp.status, 429)
        self.assertEqual(eng.guard.stats.checked, 2)

    def test_budget_still_stops_the_run(self) -> None:
        scope = self.root / "tiny-budget.json"
        scope.write_text(json.dumps(_scope_doc(self.base, paths=["/flaky"], budget=2), indent=2))
        eng = open_engagement(scope, self.root / "tiny", transport=TransportOptions(retries=5, retry_max_wait=0.01))
        with self.assertRaises(BudgetExhausted):
            eng.client.get("/flaky?allow=99&code=429")


class TestRetryOn503(TransportCase):
    def test_503_is_retried_then_reported(self) -> None:
        eng = self._engage("unavailable", paths=["/always"], retries=2, retry_max_wait=0.01)
        resp = eng.client.get("/always?code=503")
        self.assertEqual(resp.status, 503)
        self.assertEqual(eng.guard.stats.checked, 3)

    def test_500_is_not_retried(self) -> None:
        eng = self._engage("server-error", paths=["/always"], retries=2)
        resp = eng.client.get("/always?code=500")
        self.assertEqual(resp.status, 500)
        self.assertEqual(eng.guard.stats.checked, 1)


class TestRetryAfterParsing(unittest.TestCase):
    def test_seconds(self) -> None:
        self.assertEqual(_retry_after_seconds({"Retry-After": "7"}), 7.0)
        self.assertEqual(_retry_after_seconds({"retry-after": "0.5"}), 0.5)

    def test_http_date(self) -> None:
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime

        when = datetime.now(timezone.utc) + timedelta(seconds=30)
        seconds = _retry_after_seconds({"Retry-After": format_datetime(when, usegmt=True)})
        self.assertIsNotNone(seconds)
        self.assertTrue(20 <= seconds <= 31, seconds)

    def test_garbage_is_ignored(self) -> None:
        self.assertIsNone(_retry_after_seconds({"Retry-After": "soon"}))
        self.assertIsNone(_retry_after_seconds({}))


class TestTokenRefresh(TransportCase):
    def _auth(self, *, path: str = "/token") -> dict[str, Any]:
        return {
            "refresh": {
                "path": path,
                "grant_type": "client_credentials",
                "token_field": "access_token",
                "credentials": {
                    "agency_a": {
                        "client_id": "literal:id-a",
                        "client_secret": f"literal:{SECRET}",
                    }
                },
            }
        }

    def test_expired_token_is_refreshed_once_and_the_request_succeeds(self) -> None:
        eng = self._engage("refresh", paths=["/secure", "/token"], auth=self._auth(), retries=2)
        self.assertIsNotNone(eng.client.refresher, "refresher was not built from auth.refresh")

        resp = eng.client.get("/secure", role="agency_a")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.json()["ok"], True)

        entries = self._audit(eng)
        self.assertTrue([e for e in entries if e.get("kind") == "token-refreshed"])
        self.assertEqual(len(self.server.state["token_requests"]) >= 1, True)  # type: ignore[attr-defined]

        # The secret and the token must never reach the log.
        blob = eng.audit.path.read_text()
        self.assertNotIn(SECRET, blob)
        self.assertNotIn(FRESH_TOKEN, blob)

    def test_no_refresh_block_means_no_refresh(self) -> None:
        eng = self._engage("no-refresh", paths=["/secure"])
        self.assertIsNone(eng.client.refresher)
        resp = eng.client.get("/secure", role="agency_a")
        self.assertEqual(resp.status, 401)

    def test_refresh_path_outside_scope_is_refused_and_the_401_stands(self) -> None:
        eng = self._engage("refresh-blocked", paths=["/secure"], auth=self._auth(), retries=2)
        resp = eng.client.get("/secure", role="agency_a")
        self.assertEqual(resp.status, 401, "a refused refresh must leave the original 401 in place")
        notes = [e for e in self._audit(eng) if e.get("kind") == "refresh-failed"]
        self.assertTrue(notes)
        self.assertIn("scope", json.dumps(notes[0]).lower())

    def test_wrong_refresh_credentials_void_rather_than_crash(self) -> None:
        auth = {
            "refresh": {
                "path": "/token",
                "credentials": {"agency_a": {"client_id": "literal:id-a", "client_secret": "literal:wrong"}},
            }
        }
        eng = self._engage("refresh-bad", paths=["/secure", "/token"], auth=auth, retries=2)
        resp = eng.client.get("/secure", role="agency_a")
        self.assertEqual(resp.status, 401)


class TestWallClock(TransportCase):
    def test_wall_clock_stops_the_run(self) -> None:
        eng = self._engage("wall", paths=["/slow"], max_wall_clock=0.05, retries=0)
        time.sleep(0.08)
        with self.assertRaises(WallClockExhausted):
            eng.client.get("/slow?ms=1")

    def test_wall_clock_is_a_budget_stop(self) -> None:
        # Exit code 4 in the CLI depends on this inheritance.
        self.assertTrue(issubclass(WallClockExhausted, BudgetExhausted))

    def test_zero_disables_the_cap(self) -> None:
        eng = self._engage("no-wall", paths=["/slow"], max_wall_clock=0.0, retries=0)
        time.sleep(0.05)
        self.assertEqual(eng.client.get("/slow?ms=1").status, 200)


class TestDeadHost(TransportCase):
    def test_a_dead_host_is_an_error_not_a_clean_report(self) -> None:
        """Zero findings from a host that never answered must never read as "secure"."""
        scope = self.root / "dead.json"
        scope.write_text(json.dumps(_scope_doc(self.base, paths=["/api/"], budget=40)), encoding="utf-8")
        out = self.root / "dead"
        self.server.state["fail_all"] = True
        stderr = StringIO()
        try:
            with redirect_stderr(stderr):
                code = main(["scan", "--scope", str(scope), "--out", str(out), "--no-writes"])
        finally:
            self.server.state["fail_all"] = False
        self.assertEqual(code, 2, "a dead target must exit 2 (unreachable), not 0")
        self.assertIn("unreachable", stderr.getvalue())
        self.assertFalse((out / "REPORT.md").exists(), "a dead target must not produce a report")
        self.assertFalse((out / "findings.json").exists())


if __name__ == "__main__":
    unittest.main()
