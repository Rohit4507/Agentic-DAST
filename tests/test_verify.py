"""Precision tests: the verifier must stay silent unless it has real proof.

Every test in ``TestBolaStaysSilent`` is a reason a naive scanner reports a false
positive. They are the cheapest defence of the 20% "precision and noise control" score.
"""

from __future__ import annotations

import json
import unittest

from dast.attacks.bola import BolaTarget, test_cross_tenant_read
from dast.attacks.common import FindingFactory
from dast.attacks.exposure import test_unauthenticated_exposure
from dast.errors import ControlFailure
from dast.http import Response
from dast.model import ZOMBIE, EndpointRecord
from dast.verify.engine import (
    Capsule,
    compare_identity,
    excerpt,
    negative_control,
    redact_body,
    replay_capsule,
    response_signature,
)
from dast.verify.invariants import Ledger, check_all, violations
from tests.stub import StubClient

BOOKING_A = {
    "bookingId": "8842",
    "agencyId": "AGENCY-A",
    "status": "CONFIRMED",
    "quotedAmount": 48500.0,
    "traveller": {"name": "SYNTHETIC Traveller A1", "passport": "P<SYNTHA1<<0001", "email": "a1@example.test"},
}
BOOKING_B = {
    "bookingId": "9101",
    "agencyId": "AGENCY-B",
    "status": "CONFIRMED",
    "quotedAmount": 31000.0,
    "traveller": {"name": "SYNTHETIC Traveller B1", "passport": "P<SYNTHB1<<0003"},
}


def target() -> BolaTarget:
    return BolaTarget(
        template="/api/booking/{id}",
        owner_role="agency_a",
        other_role="agency_b",
        owner_agency="AGENCY-A",
        other_agency="AGENCY-B",
        object_id="8842",
    )


class TestBolaDetection(unittest.TestCase):
    def test_reports_when_the_other_tenant_gets_the_same_object(self):
        client = StubClient(
            {
                ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                ("/api/booking/8842", "agency_b"): (200, BOOKING_A),  # the bug
                ("/api/booking/990001", "agency_a"): (404, {"error": "not found"}),
            }
        )
        finding = test_cross_tenant_read(client, target(), factory=FindingFactory())
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vuln_class, "bola")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.confidence, "proven")
        self.assertEqual(finding.evidence.extracted["object_id"], "8842")

    def test_evidence_is_redacted_not_dumped(self):
        client = StubClient(
            {
                ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                ("/api/booking/8842", "agency_b"): (200, BOOKING_A),
                ("/api/booking/990001", "agency_a"): (404, {}),
            }
        )
        finding = test_cross_tenant_read(client, target(), factory=FindingFactory())
        excerpt_text = finding.evidence.response["excerpt"]
        self.assertNotIn("P<SYNTHA1<<0001", excerpt_text, "passport number must never be copied into a report")
        self.assertIn("passport", excerpt_text, "but the field name must be visible as evidence")
        self.assertGreater(finding.evidence.redactions, 0)


class TestBolaStaysSilent(unittest.TestCase):
    """Each of these would be a false positive if verification were status-code-only."""

    def assertSilent(self, client: StubClient, why: str):
        finding = test_cross_tenant_read(client, target(), factory=FindingFactory())
        self.assertIsNone(finding, why)

    def test_403_for_the_other_tenant(self):
        self.assertSilent(
            StubClient(
                {
                    ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                    ("/api/booking/8842", "agency_b"): (403, {"error": "forbidden"}),
                    ("/api/booking/990001", "agency_a"): (404, {}),
                }
            ),
            "a correct 403 must not be reported",
        )

    def test_other_tenant_receives_its_own_object(self):
        self.assertSilent(
            StubClient(
                {
                    ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                    ("/api/booking/8842", "agency_b"): (200, BOOKING_B),  # different object
                    ("/api/booking/990001", "agency_a"): (404, {}),
                }
            ),
            "a tenant seeing a different object is not a cross-tenant read",
        )

    def test_generic_success_page_is_not_proof(self):
        self.assertSilent(
            StubClient(
                {
                    ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                    ("/api/booking/8842", "agency_b"): (200, {"status": "ok"}),
                    ("/api/booking/990001", "agency_a"): (404, {}),
                }
            ),
            "no identity field in the body means no proof",
        )

    def test_failed_negative_control_voids_the_finding(self):
        self.assertSilent(
            StubClient(
                {
                    ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                    ("/api/booking/8842", "agency_b"): (200, BOOKING_A),
                    # the endpoint answers non-existent objects too -> test is broken
                    ("/api/booking/990001", "agency_a"): (200, BOOKING_A),
                }
            ),
            "if the control returns 200, the app answers anything and the 200 proves nothing",
        )

    def test_owner_cannot_read_the_object(self):
        self.assertSilent(
            StubClient({("/api/booking/8842", "agency_a"): (404, {})}),
            "without a baseline there is nothing to compare against",
        )

    def test_same_agency_is_not_a_boundary_crossing(self):
        t = target()
        t.other_agency = "AGENCY-A"  # same agency: not a finding
        client = StubClient(
            {
                ("/api/booking/8842", "agency_a"): (200, BOOKING_A),
                ("/api/booking/8842", "agency_b"): (200, BOOKING_A),
                ("/api/booking/990001", "agency_a"): (404, {}),
            }
        )
        self.assertIsNone(test_cross_tenant_read(client, t, factory=FindingFactory()))


class TestExposureStaysSilent(unittest.TestCase):
    def record(self, label=ZOMBIE, template="/api/test/debug"):
        return EndpointRecord(method="GET", template=template, label=label)

    def test_no_finding_without_sensitive_data(self):
        client = StubClient({("/api/test/debug", None): (200, {"ok": True, "build": "1.2.3"})})
        finding = test_unauthenticated_exposure(
            client, self.record(), factory=FindingFactory(), candidate_ids=["1"]
        )
        self.assertIsNone(finding, "an unauthenticated but boring endpoint is not a finding")

    def test_finding_when_pii_is_exposed_anonymously(self):
        client = StubClient(
            {
                ("/api/v1/booking/8842", None): (200, BOOKING_A),
                ("/api/v1/booking/990001", None): (404, {}),
            }
        )
        rec = self.record(template="/api/v1/booking/{id}")
        finding = test_unauthenticated_exposure(
            client, rec, factory=FindingFactory(), candidate_ids=["8842"]
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vuln_class, "unauthenticated_data_exposure")
        self.assertTrue(finding.evidence.extracted["reachable_without_auth"])

    def test_active_endpoints_are_not_tested_for_exposure(self):
        client = StubClient({("/api/v1/booking/8842", None): (200, BOOKING_A)})
        rec = self.record(label="active", template="/api/v1/booking/{id}")
        self.assertIsNone(test_unauthenticated_exposure(client, rec, factory=FindingFactory()))


class TestPrimitives(unittest.TestCase):
    def test_negative_control_raises_when_endpoint_answers_anything(self):
        client = StubClient({("/api/booking/990001", "agency_a"): (200, BOOKING_A)})
        with self.assertRaises(ControlFailure):
            negative_control(client, "/api/booking/{id}", role="agency_a")

    def test_negative_control_passes_on_404(self):
        client = StubClient({("/api/booking/990001", "agency_a"): (404, {})})
        result = negative_control(client, "/api/booking/{id}", role="agency_a")
        self.assertTrue(result.passed)
        self.assertEqual(result.status, 404)

    def test_negative_control_is_not_applicable_without_an_id(self):
        client = StubClient({})
        result = negative_control(client, "/api/test/debug", role=None)
        self.assertTrue(result.passed)
        self.assertIn("not applicable", result.detail)

    def test_redaction_keeps_keys_and_masks_values(self):
        redacted, count = redact_body(BOOKING_A)
        self.assertEqual(redacted["traveller"]["passport"], redacted["traveller"]["passport"])
        self.assertIn("*", redacted["traveller"]["passport"])
        self.assertGreaterEqual(count, 3)  # name, passport, email
        self.assertEqual(redacted["bookingId"], "8842")  # identifiers are evidence, not PII

    def test_excerpt_is_line_limited(self):
        resp = Response("GET", "http://x/api", 200, {}, json.dumps({"k": ["x"] * 200}).encode(), 1.0)
        text, _ = excerpt(resp, max_lines=5)
        self.assertLessEqual(len(text.splitlines()), 6)
        self.assertIn("withheld", text)

    def test_compare_identity_rejects_different_objects(self):
        a = Response("GET", "u", 200, {}, json.dumps(BOOKING_A).encode(), 1.0)
        b = Response("GET", "u", 200, {}, json.dumps(BOOKING_B).encode(), 1.0)
        self.assertIsNone(compare_identity(a, b))

    def test_signature_detects_shape(self):
        a = Response("GET", "u", 200, {}, json.dumps(BOOKING_A).encode(), 1.0)
        self.assertEqual(response_signature(a)["status"], 200)
        self.assertIn("bookingId", response_signature(a)["keys"])

    def test_replay_reports_fixed_when_status_changes(self):
        capsule = Capsule(finding_id="F-1", title="t", endpoint="/api/booking/{id}", method="GET")
        capsule.add("as_other", Response("GET", "/api/booking/8842", 200, {}, json.dumps(BOOKING_A).encode(), 1.0),
                    role="agency_b")
        capsule.expected = {"status": 200, "identity_field": "bookingId", "identity_value": "8842"}
        fixed = StubClient({("/api/booking/8842", "agency_b"): (403, {"error": "forbidden"})})
        still, detail = replay_capsule(capsule, fixed)
        self.assertFalse(still)
        self.assertIn("resolved", detail)

    def test_replay_confirms_still_open(self):
        capsule = Capsule(finding_id="F-1", title="t", endpoint="/api/booking/{id}", method="GET")
        capsule.add("as_other", Response("GET", "/api/booking/8842", 200, {}, json.dumps(BOOKING_A).encode(), 1.0),
                    role="agency_b")
        capsule.expected = {"status": 200, "identity_field": "bookingId", "identity_value": "8842"}
        alive = StubClient({("/api/booking/8842", "agency_b"): (200, BOOKING_A)})
        still, detail = replay_capsule(capsule, alive)
        self.assertTrue(still)
        self.assertIn("still exploitable", detail)


class TestInvariants(unittest.TestCase):
    def ledger(self, **kw) -> Ledger:
        base = dict(booking_id="1", status="CONFIRMED", quoted=1000.0, final=1000.0,
                    payments=[{"amount": 1000.0}], refunds=[])
        base.update(kw)
        return Ledger(**base)

    def test_healthy_ledger_passes(self):
        self.assertEqual(violations(self.ledger()), [])

    def test_double_refund_violates_single_refund(self):
        led = self.ledger(
            status="REFUNDED",
            refunds=[{"amount": 1000.0, "status": "ok"}, {"amount": 1000.0, "status": "ok"}],
        )
        names = {v.name for v in violations(led)}
        self.assertIn("single_refund", names)
        self.assertIn("refund_le_paid", names)

    def test_skipped_payment_is_detected(self):
        led = self.ledger(payments=[])
        self.assertIn("paid_before_confirm", {v.name for v in violations(led)})

    def test_fare_tampering_is_detected(self):
        led = self.ledger(final=100.0)
        self.assertIn("monotonic_amount", {v.name for v in violations(led)})

    def test_negative_pax_is_detected(self):
        led = self.ledger(pax=-1)
        self.assertIn("no_negative_pax", {v.name for v in violations(led)})

    def test_rounding_tolerance(self):
        led = self.ledger(payments=[{"amount": 999.995}])
        self.assertNotIn("refund_le_paid", {v.name for v in violations(led)})

    def test_check_all_reports_every_invariant(self):
        self.assertGreaterEqual(len(check_all(self.ledger())), 6)


if __name__ == "__main__":
    unittest.main()
