"""End-to-end: the whole loop against a live (mock) target.

This is the test that answers "does it actually work?" -- and, just as importantly,
"does it stay quiet where the target is correct?".
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from dast.audit import verify_chain
from dast.errors import DastError, ScopeViolation
from dast.model import SHADOW, ZOMBIE
from dast.pipeline import _require_live_target, collect_inventory, open_engagement, run_all
from dast.record.journey import Step, record_journey
from tests.stub import write_scope
from target.app import make_server

REPO = Path(__file__).resolve().parent.parent
GATEWAY = REPO / "target" / "traffic" / "gateway_30d.jsonl"

EXPECTED_CLASSES = {
    "bola",
    "double_refund",
    "skipped_payment",
    "fare_tampering",
    "unauthenticated_data_exposure",
}


def journey(role: str) -> list[Step]:
    if role == "agency_a":
        return [Step("GET", "/api/bookings"), Step("GET", "/api/booking/8842"), Step("GET", "/api/ledger/8842")]
    return [Step("GET", "/api/bookings"), Step("GET", "/api/booking/9101"), Step("GET", "/api/ledger/9101")]


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = f"http://127.0.0.1:{self.port}"
        self.scope = write_scope(
            self.root / "scope.json", self.base, budget=400, kill_file=str(self.root / "KILL")
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # -- helpers -------------------------------------------------------------------

    def run_pipeline(self):
        eng = open_engagement(self.scope, self.root / "work", approve_writes=True)
        captures = self.root / "captures"
        for role in ("agency_a", "agency_b"):
            record_journey(eng.client, role=role, steps=journey(role), out_path=captures / f"{role}.har")
        result = run_all(
            eng, capture_dir=captures, gateway_paths=[GATEWAY], approve_writes=True, max_probes=12
        )
        return eng, result

    # -- the loop ------------------------------------------------------------------

    def test_finds_all_planted_vulnerability_classes(self):
        eng, result = self.run_pipeline()
        kinds = {f.vuln_class for f in result.report.findings}
        self.assertTrue(
            EXPECTED_CLASSES <= kinds,
            f"missing classes: {EXPECTED_CLASSES - kinds}; got {sorted(kinds)}",
        )
        for f in result.report.findings:
            self.assertEqual(f.confidence, "proven")
            self.assertTrue(f.evidence is not None)
            self.assertTrue(f.remediation)
            self.assertTrue(f.owner and f.owner != "unassigned")

    def test_stays_quiet_where_the_target_is_correct(self):
        """The ledger endpoint enforces ownership, so it must produce no finding."""
        eng, result = self.run_pipeline()
        self.assertFalse(
            [f for f in result.report.findings if "/api/ledger" in f.endpoint],
            "the correctly-authorised ledger endpoint produced a false positive",
        )

    def test_no_finding_is_below_high_when_money_or_tenant_is_involved(self):
        eng, result = self.run_pipeline()
        for f in result.report.findings:
            self.assertIn(f.severity, ("critical", "high"), f"{f.id} scored {f.severity}")

    def test_severity_is_not_saturated(self):
        eng, result = self.run_pipeline()
        scores = [f.cvss for f in result.report.findings]
        self.assertGreater(len(set(scores)), 1, "every finding scored the same: ranking is useless")
        self.assertLessEqual(max(scores), 10.0)

    def test_inventory_labels_zombie_and_shadow(self):
        eng, result = self.run_pipeline()
        labels = {r.template: r.label for r in result.inventory.records}
        zombies = [t for t, l in labels.items() if l == ZOMBIE]
        shadows = [t for t, l in labels.items() if l == SHADOW]
        self.assertIn("/api/v1/booking/{id}", zombies)
        self.assertIn("/api/internal/agency/AGENCY-A/export", shadows)
        self.assertEqual(len(shadows), 1)

    def test_artefacts_are_written(self):
        eng, result = self.run_pipeline()
        work = self.root / "work"
        for name in ("REPORT.md", "inventory.json", "openapi.generated.json", "report.sarif",
                     "findings.json", "audit.head.json"):
            self.assertTrue((work / name).exists(), f"{name} missing")
        for f in result.report.findings:
            self.assertTrue((work / "findings" / f.id / "report.md").exists())
            self.assertTrue((work / "findings" / f.id / "capsule.json").exists())
        sarif = json.loads((work / "report.sarif").read_text())
        self.assertEqual(len(sarif["runs"][0]["results"]), len(result.report.findings))

    def test_audit_chain_is_intact_and_every_request_carries_a_component(self):
        eng, _ = self.run_pipeline()
        ok, seq, detail = verify_chain(eng.audit.path)
        self.assertTrue(ok, f"audit chain broken at {seq}: {detail}")
        entries = [e for e in eng.audit if e.get("event") == "request"]
        self.assertGreater(len(entries), 20)
        for e in entries:
            self.assertTrue(e.get("component"), f"request without an owning component: {e.get('seq')}")
            self.assertLessEqual(e.get("status", 0) if e["status"] else 999, 599)

    def test_published_audit_head_matches_the_log(self):
        """The run must publish a head that actually verifies -- otherwise the anchor is noise."""
        eng, _ = self.run_pipeline()
        anchor = json.loads((self.root / "work" / "audit.head.json").read_text())
        ok, seq, detail = verify_chain(eng.audit.path, expect_head=(anchor["seq"], anchor["entry_hash"]))
        self.assertTrue(ok, f"published head does not match the log: {detail}")
        self.assertEqual(anchor["entries"], anchor["seq"])

    def test_credentials_never_reach_the_audit_log(self):
        eng, _ = self.run_pipeline()
        blob = Path(eng.audit.path).read_text()
        self.assertNotIn("tok-agency-a", blob)
        self.assertNotIn("tok-agency-b", blob)

    def test_passport_numbers_never_reach_the_reports(self):
        eng, result = self.run_pipeline()
        for path in (self.root / "work").rglob("*.json"):
            text = path.read_text()
            self.assertNotIn("P<SYNTHA1", text, f"raw PII in {path.name}")
            self.assertNotIn("P<SYNTHB1", text, f"raw PII in {path.name}")
        for path in (self.root / "work").rglob("*.md"):
            text = path.read_text()
            self.assertNotIn("P<SYNTHA1", text, f"raw PII in {path.name}")

    def test_scope_violation_never_reaches_the_target(self):
        eng, _ = self.run_pipeline()
        server_store = self.server.RequestHandlerClass.api.store
        before = server_store.request_count
        with self.assertRaises(ScopeViolation):
            eng.client.get("/api/admin/users", component="test", note="must be refused")
        with self.assertRaises(ScopeViolation):
            eng.client.post("/api/refund/bulk", component="test", note="destructive, denied")
        self.assertEqual(server_store.request_count, before, "a refused request still reached the target")
        denied = [e for e in eng.audit if e.get("event") == "denied"]
        self.assertGreaterEqual(len(denied), 2)

    def test_dedupe_collapses_repeat_findings(self):
        eng, result = self.run_pipeline()
        self.assertGreaterEqual(result.report.dedupe.raw, result.report.dedupe.unique)
        keys = [f.dedupe_key for f in result.report.findings]
        self.assertEqual(len(keys), len(set(keys)), "duplicate findings survived dedupe")


class TestWriteGate(unittest.TestCase):
    """Without approval, write tests must not run. Fail closed, not open."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_write_tests_are_skipped_without_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = write_scope(root / "scope.json", f"http://127.0.0.1:{self.port}", budget=400,
                                kill_file=str(root / "KILL"))
            eng = open_engagement(scope, root / "work", approve_writes=False)
            captures = root / "captures"
            for role in ("agency_a", "agency_b"):
                record_journey(eng.client, role=role, steps=journey(role), out_path=captures / f"{role}.har")
            # interactive=True with a non-tty stdin refuses; simulate by pinning it
            import dast.gate as gate_mod

            original = gate_mod.ApprovalGate.__post_init__
            gate_mod.ApprovalGate.__post_init__ = lambda self: setattr(self, "interactive", False)
            try:
                result = run_all(eng, capture_dir=captures, gateway_paths=[GATEWAY], approve_writes=False)
            finally:
                gate_mod.ApprovalGate.__post_init__ = original

            kinds = {f.vuln_class for f in result.report.findings}
            self.assertNotIn("double_refund", kinds)
            self.assertNotIn("skipped_payment", kinds)
            self.assertIn("bola", kinds, "read-only detection must still work without approval")
            self.assertIn("denied", result.execution.approvals)


class TestUnreachableTarget(unittest.TestCase):
    """A dead target must not be reported as a clean scan.

    Zero findings from a target that never answered is indistinguishable from a
    secure target. That false-clean is the worst thing a DAST tool can print, so
    total transport failure is fatal and says why.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # a port that is bound and immediately released: nothing is listening there
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.dead_port = sock.getsockname()[1]
        sock.close()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_requests_failing_is_fatal_not_clean(self) -> None:
        scope = write_scope(
            self.root / "scope.json",
            f"http://127.0.0.1:{self.dead_port}",
            budget=50,
            kill_file=str(self.root / "KILL"),
        )
        eng = open_engagement(scope, self.root / "work", approve_writes=True)
        with self.assertRaises(DastError) as caught:
            collect_inventory(eng, probe=True, max_probes=3)
        message = str(caught.exception)
        self.assertIn("unreachable", message)
        self.assertIn(str(self.dead_port), message)
        self.assertGreater(eng.guard.stats.sent, 0)
        self.assertEqual(eng.guard.stats.failed, eng.guard.stats.sent)

    def test_no_requests_means_no_verdict(self) -> None:
        # With probing off nothing was sent, so "no findings" is a statement about
        # the inventory, not about reachability, and must not raise.
        scope = write_scope(
            self.root / "scope.json",
            f"http://127.0.0.1:{self.dead_port}",
            budget=50,
            kill_file=str(self.root / "KILL"),
        )
        eng = open_engagement(scope, self.root / "work", approve_writes=True)
        inv = collect_inventory(eng, probe=False)
        self.assertEqual(eng.guard.stats.sent, 0)
        self.assertTrue(inv.records, "inventory is built from bundles and logs, not from the wire")

    def test_partial_failure_is_tolerated(self) -> None:
        # Some 5xx among successes is normal noise and must not abort a run.
        class _Stub:
            def __init__(self) -> None:
                self.sent = 0
                self.failed = 0

        stub = _Stub()
        stub.sent, stub.failed = 10, 10
        eng = type("E", (), {"guard": type("G", (), {"stats": stub})(), "cfg": type("C", (), {"base_url": "http://x"})()})()
        with self.assertRaises(DastError):
            _require_live_target(eng, stage="probe")
        stub.sent, stub.failed = 10, 9
        _require_live_target(eng, stage="probe")  # must not raise


if __name__ == "__main__":
    unittest.main()
