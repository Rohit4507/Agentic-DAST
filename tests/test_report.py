"""Severity, dedupe, inventory labelling and report rendering."""

from __future__ import annotations

import json
import unittest
from datetime import timedelta

from dast.inventory.classify import build_inventory, render_table
from dast.model import SHADOW, ZOMBIE, Finding, TrafficHit, utcnow
from dast.report.dedupe import dedupe, normalize_endpoint
from dast.report.sarif import build_sarif
from dast.report.severity import band, from_finding_kind, score
from dast.report.ticket import render_ticket


class TestSeverity(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(band(9.5), "critical")
        self.assertEqual(band(7.0), "high")
        self.assertEqual(band(4.0), "medium")
        self.assertEqual(band(1.0), "low")

    def test_additive_modifiers_keep_ordering_sane(self):
        """The whole point of additive scoring: business findings must not all pin at 10."""
        bola = from_finding_kind("bola", cross_tenant=True, pii=True)
        unauth = from_finding_kind("unauthenticated_data_exposure", cross_tenant=True, unauth=True, pii=True)
        refund = from_finding_kind("double_refund", money=True, write=True)
        self.assertAlmostEqual(bola.score, 8.3)
        self.assertEqual(unauth.score, 10.0)
        self.assertAlmostEqual(refund.score, 8.1)
        self.assertGreater(unauth.score, bola.score)
        self.assertGreater(bola.score, refund.score)

    def test_rationale_shows_the_arithmetic(self):
        result = from_finding_kind("double_refund", money=True, write=True)
        self.assertIn("6.2", result.rationale)
        self.assertIn("money_movement", result.rationale)
        self.assertIn("8.1", result.rationale)

    def test_tenant_findings_are_never_low(self):
        result = score(1.0, ["cross_agency"])
        self.assertGreaterEqual(result.score, 7.0)
        self.assertIn("never below high", result.rationale)

    def test_cap_is_respected(self):
        self.assertLessEqual(score(9.9, ["cross_agency", "auth_bypass", "money_movement", "pii"]).score, 10.0)

    def test_internal_only_lowers_the_score(self):
        self.assertLess(score(6.0, ["internal_only"]).score, 6.0)


class TestDedupe(unittest.TestCase):
    def finding(self, **kw) -> Finding:
        base = dict(
            id="F-1",
            title="Cross-tenant read",
            vuln_class="bola",
            endpoint="/api/booking/8842",
            method="GET",
        )
        base.update(kw)
        return Finding(**base)

    def test_endpoint_normalisation(self):
        self.assertEqual(normalize_endpoint("GET", "/api/booking/8842"), "GET /api/booking/{id}")
        self.assertEqual(normalize_endpoint("GET", "/api/booking/9101"), "GET /api/booking/{id}")

    def test_same_bug_on_two_objects_collapses(self):
        unique, report = dedupe([self.finding(id="F-1"), self.finding(id="F-2", endpoint="/api/booking/8843")])
        self.assertEqual(len(unique), 1)
        self.assertEqual(report.raw, 2)
        self.assertEqual(report.unique, 1)
        self.assertIn("2 raw hits -> 1 findings", report.ratio)

    def test_different_classes_do_not_collapse(self):
        unique, _ = dedupe([self.finding(id="F-1"), self.finding(id="F-2", vuln_class="double_refund",
                                                               endpoint="/api/refund", method="POST")])
        self.assertEqual(len(unique), 2)

    def test_stronger_evidence_is_kept(self):
        weak = self.finding(id="F-1")
        strong = self.finding(id="F-2", proof_hash="abc123")
        unique, _ = dedupe([weak, strong])
        self.assertEqual(unique[0].proof_hash, "abc123")


class TestInventory(unittest.TestCase):
    def hit(self, method, path, age_days, role="agency_a"):
        return TrafficHit.build(
            method=method,
            path=path,
            status=200,
            ts=utcnow() - timedelta(days=age_days),
            role=role,
        )

    def test_three_way_diff_labels(self):
        records = build_inventory(
            har_hits=[self.hit("GET", "/api/booking/8842", 0)],
            gateway_hits=[self.hit("GET", "/api/booking/8842", 1), self.hit("GET", "/api/internal/export", 3)],
            js_routes={"/api/booking/{id}", "/api/v1/booking/{id}"},
            window_days=30,
        )
        by_tpl = {r.template: r for r in records}
        self.assertEqual(by_tpl["/api/booking/{id}"].label, "active")
        self.assertEqual(by_tpl["/api/internal/export"].label, SHADOW)   # traffic, not in JS
        self.assertEqual(by_tpl["/api/v1/booking/{id}"].label, ZOMBIE)   # in JS, no traffic

    def test_stale_traffic_becomes_zombie(self):
        records = build_inventory(
            gateway_hits=[self.hit("GET", "/api/booking/8842", 90)],
            js_routes={"/api/booking/{id}"},
            window_days=30,
        )
        self.assertEqual(records[0].label, ZOMBIE)
        self.assertAlmostEqual(records[0].age_days(), 90, places=0)

    def test_prefix_matching_avoids_duplicate_rows(self):
        """A bundle containing '/api/booking' must not create a second row for '/api/booking/{id}'."""
        records = build_inventory(
            gateway_hits=[self.hit("GET", "/api/booking/8842", 1)],
            js_routes={"/api/booking"},
            window_days=30,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].label, "active")

    def test_owner_mapping_uses_longest_prefix(self):
        records = build_inventory(
            gateway_hits=[self.hit("GET", "/api/booking/8842", 1)],
            js_routes={"/api/booking/{id}"},
            asset_map={"/api": "Platform", "/api/booking": "Bookings team"},
            window_days=30,
        )
        self.assertEqual(records[0].owner, "Bookings team")

    def test_table_renders(self):
        records = build_inventory(
            gateway_hits=[self.hit("GET", "/api/booking/8842", 1)],
            js_routes={"/api/booking/{id}"},
            window_days=30,
        )
        table = render_table(records)
        self.assertIn("/api/booking/{id}", table)
        self.assertIn("1 active", table)

    def test_inventory_row_carries_the_required_fields(self):
        records = build_inventory(
            gateway_hits=[self.hit("GET", "/api/v1/booking/8842", 5)],
            js_routes={"/api/v1/booking/{id}", "/api/v3/booking/{id}"},
            window_days=30,
        )
        row = records[0].to_dict()
        for field in (
            "last_seen_real_traffic",
            "reachable_without_auth",
            "data_exposed",
            "owner",
            "recommendation",
        ):
            self.assertIn(field, row)


class TestReports(unittest.TestCase):
    def finding(self) -> Finding:
        from dast.model import Evidence
        from dast.report.severity import from_finding_kind

        sev = from_finding_kind("bola", cross_tenant=True, pii=True)
        return Finding(
            id="F-001",
            title="Cross-tenant read on /api/booking/{id}",
            vuln_class="bola",
            endpoint="/api/booking/8842",
            method="GET",
            severity=sev.severity,
            cvss=sev.score,
            business_impact=sev.rationale,
            confidence="proven",
            owner="Bookings API team",
            owasp="API1:2023",
            cwe="CWE-639",
            evidence=Evidence(
                request={"method": "GET", "path": "/api/booking/8842", "role": "agency_b"},
                response={"status": 200, "excerpt": '{"bookingId": "8842"}'},
                extracted={"negative_control": {"path": "/api/booking/990001", "status": 404,
                                                "expected": [404], "passed": True}},
            ),
            impact="Agency B can read Agency A bookings.",
            remediation="Check ownership in the authorization layer.",
        )

    def test_ticket_contains_the_actionable_fields(self):
        text = render_ticket(self.finding())
        for needle in ("# [HIGH]", "Agency B can read", "Fix", "Retest", "Negative control passed"):
            self.assertIn(needle, text)

    def test_sarif_is_valid_and_maps_severity(self):
        sarif = build_sarif([self.finding()])
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["ruleId"], "bola")
        json.dumps(sarif)  # must be serialisable

    def test_sarif_fingerprint_is_stable(self):
        a = build_sarif([self.finding()])["runs"][0]["results"][0]["fingerprints"]
        b = build_sarif([self.finding()])["runs"][0]["results"][0]["fingerprints"]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
