"""The safety layer must refuse, and must refuse the *right* things.

Break-the-guard tests are the most valuable tests in this repository: a scope
violation disqualifies the submission, so "we tested it" is worth more than "we meant to".
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from dast.errors import BudgetExhausted, DastError, KillSwitchEngaged, ScopeViolation
from dast.scope import ScopeConfig, ScopeGuard, TokenBucket, canonical_path, NonCanonicalPath
from tests.stub import scope_mapping

BASE = "http://127.0.0.1:8080"


def make_guard(**overrides) -> ScopeGuard:
    raw = scope_mapping(BASE)
    raw.update(overrides)
    return ScopeGuard(ScopeConfig.from_mapping(raw))


class TestConfigValidation(unittest.TestCase):
    def test_unknown_key_is_rejected(self):
        raw = scope_mapping(BASE)
        raw["allow_host"] = ["127.0.0.1"]  # typo: silently ignoring this would be worse
        with self.assertRaises(DastError):
            ScopeConfig.from_mapping(raw)

    def test_missing_required_key_is_rejected(self):
        raw = scope_mapping(BASE)
        del raw["allow_paths"]
        with self.assertRaises(DastError):
            ScopeConfig.from_mapping(raw)

    def test_empty_allow_hosts_is_rejected(self):
        raw = scope_mapping(BASE)
        raw["allow_hosts"] = []
        with self.assertRaises(DastError):
            ScopeConfig.from_mapping(raw)

    def test_bad_host_pattern_is_rejected(self):
        raw = scope_mapping(BASE)
        raw["allow_hosts"] = ["*example.com"]
        with self.assertRaises(DastError):
            ScopeConfig.from_mapping(raw)

    def test_config_is_immutable(self):
        cfg = ScopeConfig.from_mapping(scope_mapping(BASE))
        with self.assertRaises(FrozenInstanceError):
            cfg.allow_hosts = ("evil.example",)  # type: ignore[misc]

    def test_wildcard_subdomain_is_allowed_but_not_the_bare_suffix(self):
        raw = scope_mapping(BASE)
        raw["allow_hosts"] = ["*.example.com"]
        guard = ScopeGuard(ScopeConfig.from_mapping(raw))
        self.assertTrue(guard.check("GET", "https://api.example.com/api/bookings", charge=False).allowed)
        with self.assertRaises(ScopeViolation):
            guard.check("GET", "https://example.com/api/bookings", charge=False)
        with self.assertRaises(ScopeViolation):
            guard.check("GET", "https://notexample.com/api/bookings", charge=False)


class TestGuardDenials(unittest.TestCase):
    def setUp(self):
        self.guard = make_guard()

    def assertDenied(self, method: str, url: str, reason: str | None = None):
        with self.assertRaises(ScopeViolation) as ctx:
            self.guard.check(method, url, charge=False)
        if reason:
            self.assertEqual(ctx.exception.reason, reason)
        return ctx.exception

    def test_allowed_request_passes(self):
        self.assertTrue(self.guard.check("GET", f"{BASE}/api/booking/8842", charge=False).allowed)

    def test_off_host_is_denied(self):
        self.assertDenied("GET", "https://api.tbo.com/api/bookings", "host-not-allowed")

    def test_unlisted_path_is_denied(self):
        self.assertDenied("GET", f"{BASE}/api/secrets", "path-not-allowlisted")

    def test_deny_beats_allow(self):
        # /api/refund is allowed; /api/refund/bulk is explicitly denied
        self.assertTrue(self.guard.check("POST", f"{BASE}/api/refund", charge=False).allowed)
        self.assertDenied("POST", f"{BASE}/api/refund/bulk", "path-denied")

    def test_traversal_is_denied(self):
        self.assertDenied("GET", f"{BASE}/api/booking/../../admin/users", "non-canonical-path")

    def test_encoded_traversal_is_denied(self):
        self.assertDenied("GET", f"{BASE}/api/booking/%2e%2e/admin", "non-canonical-path")
        self.assertDenied("GET", f"{BASE}/api/booking/%252e%252e/admin", "non-canonical-path")

    def test_userinfo_smuggling_is_denied(self):
        self.assertDenied("GET", "http://127.0.0.1:8080@evil.example/api/bookings", "userinfo-in-url")

    def test_method_not_allowed_is_denied(self):
        self.assertDenied("DELETE", f"{BASE}/api/booking/8842", "method-not-allowed")

    def test_non_http_scheme_is_denied(self):
        self.assertDenied("GET", "file:///etc/passwd", "scheme-not-allowed")

    def test_fragment_is_denied(self):
        self.assertDenied("GET", f"{BASE}/api/bookings#x", "fragment-in-url")

    def test_denials_are_counted(self):
        before = self.guard.stats.denied
        with self.assertRaises(ScopeViolation):
            self.guard.check("GET", "https://evil.example/api/bookings", charge=False)
        self.assertEqual(self.guard.stats.denied, before + 1)


class TestBudgetAndKillSwitch(unittest.TestCase):
    def test_budget_is_enforced(self):
        guard = make_guard(max_total_requests=3, max_burst=10, max_rps_per_host=100)
        for _ in range(3):
            guard.check("GET", f"{BASE}/api/bookings")
        with self.assertRaises(BudgetExhausted):
            guard.check("GET", f"{BASE}/api/bookings")
        self.assertEqual(guard.budget_remaining, 0)

    def test_dry_run_does_not_consume_budget(self):
        guard = make_guard(max_total_requests=1)
        for _ in range(5):
            guard.check("GET", f"{BASE}/api/bookings", charge=False)
        self.assertEqual(guard.budget_remaining, 1)

    def test_kill_file_stops_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            kill = Path(tmp) / "KILL"
            guard = make_guard(kill_switch_file=str(kill))
            self.assertTrue(guard.check("GET", f"{BASE}/api/bookings", charge=False).allowed)
            kill.write_text("stop")
            with self.assertRaises(KillSwitchEngaged):
                guard.check("GET", f"{BASE}/api/bookings", charge=False)

    def test_operator_stop_is_honoured(self):
        guard = make_guard()
        guard.stop("test")
        with self.assertRaises(KillSwitchEngaged):
            guard.check("GET", f"{BASE}/api/bookings", charge=False)


class TestCanonicalPath(unittest.TestCase):
    def test_clean_paths_pass_through(self):
        self.assertEqual(canonical_path("/api/booking/8842"), "/api/booking/8842")

    def test_dot_segments_rejected(self):
        for bad in ("/api/./booking", "/api/booking/../admin", "/api//booking", "/api/booking/.."):
            with self.assertRaises(NonCanonicalPath):
                canonical_path(bad)

    def test_encoded_slash_rejected(self):
        for bad in ("/api%2fbooking", "/api/%2Fbooking", "/%2e%2e/admin"):
            with self.assertRaises(NonCanonicalPath):
                canonical_path(bad)

    def test_backslash_and_whitespace_rejected(self):
        for bad in ("/api\\booking", "/api/book ing", "/api/book\x00ing"):
            with self.assertRaises(NonCanonicalPath):
                canonical_path(bad)


class TestTokenBucket(unittest.TestCase):
    def test_burst_then_refill(self):
        now = [0.0]
        bucket = TokenBucket(rate=1.0, capacity=2, clock=lambda: now[0])
        self.assertTrue(bucket.try_take())
        self.assertTrue(bucket.try_take())
        self.assertFalse(bucket.try_take())
        now[0] = 1.0
        self.assertTrue(bucket.try_take())
        self.assertFalse(bucket.try_take())

    def test_wait_time_is_positive_when_empty(self):
        bucket = TokenBucket(rate=2.0, capacity=1, clock=lambda: 0.0)
        self.assertTrue(bucket.try_take())
        self.assertGreater(bucket.seconds_until_token(), 0.0)

    def test_rate_limit_backs_off_rather_than_hanging(self):
        guard = make_guard(max_rps_per_host=0.5, max_burst=1, max_wait_seconds=0.1)
        guard.check("GET", f"{BASE}/api/bookings")
        with self.assertRaises(ScopeViolation) as ctx:
            guard.check("GET", f"{BASE}/api/bookings")
        self.assertEqual(ctx.exception.reason, "rate-limit-wait-exceeded")


class TestStoppingConditions(unittest.TestCase):
    """A kill switch or a spent budget must stop the run, not quietly skip a request.

    Regression test: the inventory probe used to catch ScopeViolation and record "probe
    refused", so `run.py inventory` exited 0 with a KILL file present and the operator
    believed the scan had run.
    """

    def client(self, tmp: Path, **overrides):
        from dast.audit import AuditLog
        from dast.auth import TokenStore
        from dast.http import Client

        raw = scope_mapping(BASE, **overrides)
        cfg = ScopeConfig.from_mapping(raw)
        return Client(ScopeGuard(cfg), AuditLog(tmp / "audit.jsonl"), TokenStore({}))

    def record(self):
        from dast.model import ZOMBIE, EndpointRecord

        return EndpointRecord(method="GET", template="/api/test/debug", label=ZOMBIE)

    def test_kill_switch_aborts_the_probe_stage(self):
        from dast.errors import KillSwitchEngaged
        from dast.inventory.classify import probe_candidates

        with tempfile.TemporaryDirectory() as tmp:
            kill = Path(tmp) / "KILL"
            kill.write_text("stop")
            client = self.client(Path(tmp), kill_file=str(kill))
            with self.assertRaises(KillSwitchEngaged):
                probe_candidates(client, [self.record()], roles=("agency_a",), known_ids=["1"])

    def test_exhausted_budget_aborts_the_probe_stage(self):
        from dast.errors import BudgetExhausted
        from dast.inventory.classify import probe_candidates

        with tempfile.TemporaryDirectory() as tmp:
            client = self.client(Path(tmp), budget=0)
            with self.assertRaises(BudgetExhausted):
                probe_candidates(client, [self.record()], roles=("agency_a",), known_ids=["1"])

    def test_ordinary_scope_denial_is_recorded_not_fatal(self):
        """The counterpart: a path outside the allowlist is a skipped probe, not a stop."""
        from dast.inventory.classify import probe_candidates

        with tempfile.TemporaryDirectory() as tmp:
            client = self.client(Path(tmp))
            rec = self.record()
            rec.template = "/unlisted/path"
            probe_candidates(client, [rec], roles=("agency_a",), known_ids=["1"])
            self.assertIsNone(rec.probe.reachable)
            self.assertIn("refused by scope guard", rec.probe.error)


if __name__ == "__main__":
    unittest.main()
