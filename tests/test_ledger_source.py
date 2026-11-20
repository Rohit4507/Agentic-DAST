"""Ledger adapters: the proof has to survive a target that names money differently."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dast.profile import LedgerSpec
from dast.verify.invariants import Ledger, violations
from dast.verify.ledger_source import (
    FixtureLedgerSource,
    HttpLedgerSource,
    NullLedgerSource,
    canonicalise,
)
from tests.stub import StubClient

NESTED = {
    "data": {
        "status": "REFUNDED",
        "quote_total": 4800.0,
        "final_total": 4800.0,
        "pax": 2,
        "settlements": [{"value": 4800.0, "state": "settled"}],
        "reversals": [
            {"value": 4800.0, "state": "settled"},
            {"value": 4800.0, "state": "settled"},
        ],
    }
}

SPEC = LedgerSpec(
    adapter="http",
    endpoint="/v2/orders/{id}/statement",
    map={
        "status": "data.status",
        "quotedAmount": "data.quote_total",
        "finalAmount": "data.final_total",
        "paxCount": "data.pax",
        "payments": "data.settlements",
        "refunds": "data.reversals",
    },
    item_map={"amount": "value", "status": "state"},
)


class TestCanonicalise(unittest.TestCase):
    def test_foreign_names_become_the_canonical_ledger(self) -> None:
        payload = canonicalise(NESTED, SPEC)
        self.assertEqual(payload["status"], "REFUNDED")
        self.assertEqual(payload["quotedAmount"], 4800.0)
        self.assertEqual(len(payload["reversals"] if "reversals" in payload else payload["refunds"]), 2)
        self.assertEqual(payload["refunds"][0], {"amount": 4800.0, "status": "settled"})

    def test_invariants_read_the_mapped_ledger(self) -> None:
        ledger = Ledger.from_api(canonicalise(NESTED, SPEC))
        names = {v.name for v in violations(ledger, only=["single_refund", "refund_le_paid"])}
        self.assertIn("single_refund", names)

    def test_synonym_ladder_without_a_map(self) -> None:
        payload = canonicalise(
            {"status": "ok", "quote_total": 100, "settlements": [{"amt": "100.00"}], "reversals": []},
            LedgerSpec(adapter="http", endpoint="/x"),
        )
        self.assertEqual(payload["quotedAmount"], 100.0)
        self.assertEqual(payload["payments"], [{"amount": 100.0}])

    def test_money_as_formatted_string(self) -> None:
        payload = canonicalise({"finalAmount": "Rs 1,234.50", "refunds": [{"amount": "1,234.50"}]},
                               LedgerSpec(adapter="http", endpoint="/x"))
        self.assertEqual(payload["finalAmount"], 1234.5)
        self.assertEqual(payload["refunds"][0]["amount"], 1234.5)


class TestHttpSource(unittest.TestCase):
    def test_reads_and_maps(self) -> None:
        client = StubClient({("/v2/orders/o-1/statement", "tenant_a"): (200, NESTED)})
        source = HttpLedgerSource(client, SPEC)
        payload = source.read("o-1", role="tenant_a")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["status"], "REFUNDED")

    def test_non_200_is_none_with_a_reason(self) -> None:
        client = StubClient({})
        source = HttpLedgerSource(client, SPEC)
        self.assertIsNone(source.read("missing", role="tenant_a"))
        self.assertIn("404", source.last_error)

    def test_non_json_is_none_with_a_reason(self) -> None:
        client = StubClient({("/v2/orders/o-1/statement", None): (200, b"<html>nope</html>")})
        source = HttpLedgerSource(client, SPEC)
        self.assertIsNone(source.read("o-1"))
        self.assertIn("not JSON", source.last_error)


class TestFixtureSource(unittest.TestCase):
    def test_json_keyed_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "statement.json"
            p.write_text(json.dumps({"o-1": {"status": "CONFIRMED", "payments": [], "refunds": []}}))
            payload = FixtureLedgerSource(p, LedgerSpec(adapter="fixture", path=str(p))).read("o-1")
            self.assertEqual(payload["status"], "CONFIRMED")

    def test_json_list_of_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "statement.json"
            p.write_text(json.dumps([{"orderId": "o-9", "finalAmount": 10.0}]))
            payload = FixtureLedgerSource(p).read("o-9")
            self.assertEqual(payload["finalAmount"], 10.0)

    def test_csv_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "statement.csv"
            p.write_text(
                "booking_id,kind,amount,status\n"
                "b-1,payment,1000.00,settled\n"
                "b-1,refund,1000.00,settled\n"
                "b-1,refund,1000.00,settled\n"
            )
            payload = FixtureLedgerSource(p).read("b-1")
            self.assertEqual(len(payload["payments"]), 1)
            self.assertEqual(len(payload["refunds"]), 2)
            ledger = Ledger.from_api(payload)
            self.assertEqual(ledger.successful_refunds, 2)

    def test_missing_booking_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "statement.json"
            p.write_text(json.dumps({"other": {}}))
            source = FixtureLedgerSource(p)
            self.assertIsNone(source.read("b-404"))
            self.assertIn("no ledger row", source.last_error)

    def test_missing_file_is_none_with_a_reason(self) -> None:
        source = FixtureLedgerSource("/nonexistent/statement.json")
        self.assertIsNone(source.read("b-1"))
        self.assertIn("missing", source.last_error)


class TestNullSource(unittest.TestCase):
    def test_never_invents_a_proof(self) -> None:
        source = NullLedgerSource()
        self.assertIsNone(source.read("b-1"))
        self.assertIn("no ledger adapter", source.last_error)
        self.assertIn("none", source.describe())


if __name__ == "__main__":
    unittest.main()
