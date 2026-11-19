"""The audit log must be replayable and tamper-evident.

A hash chain detects edits, deletions and reordering. It cannot, by itself, detect
truncation -- so the run publishes its head, and verification takes that head as an
argument. These tests cover all four.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dast.audit import AuditLog, audit_head, iter_entries, redact_headers, redact_url, verify_chain


class TestAuditChain(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.jsonl"
        log = AuditLog(self.path)
        for i in range(6):
            log.request(component="test", method="GET", url=f"/api/booking/{i}", status=200, seq_hint=i)
        self.entries = [json.loads(l) for l in self.path.read_text().splitlines()]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def rewrite(self, rows) -> Path:
        p = Path(self.tmp.name) / "tampered.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return p

    def test_untouched_log_verifies(self):
        ok, seq, detail = verify_chain(self.path)
        self.assertTrue(ok, detail)

    def test_edited_line_is_detected(self):
        rows = [dict(r, status=201) if r.get("seq") == 3 else r for r in self.entries]
        ok, seq, detail = verify_chain(self.rewrite(rows))
        self.assertFalse(ok)
        self.assertEqual(seq, 3)
        self.assertIn("edited", detail)

    def test_deleted_line_is_detected(self):
        rows = [r for r in self.entries if r.get("seq") != 4]
        ok, seq, detail = verify_chain(self.rewrite(rows))
        self.assertFalse(ok)
        self.assertIn("sequence gap", detail)

    def test_reordered_lines_are_detected(self):
        rows = self.entries[:2] + [self.entries[3], self.entries[2]] + self.entries[4:]
        ok, seq, detail = verify_chain(self.rewrite(rows))
        self.assertFalse(ok)

    def test_truncation_is_detected_against_the_recorded_head(self):
        head = audit_head(self.path)
        ok, _, _ = verify_chain(self.rewrite(self.entries), expect_head=head)
        self.assertTrue(ok)
        ok, seq, detail = verify_chain(self.rewrite(self.entries[:-3]), expect_head=head)
        self.assertFalse(ok, "a truncated log must not verify against the published head")
        self.assertIn("truncated", detail)

    def test_head_advances(self):
        seq, digest = audit_head(self.path)
        self.assertEqual(seq, 6)
        self.assertEqual(len(digest), 64)
        AuditLog(self.path).request(component="test", method="GET", url="/api/x", status=200)
        self.assertEqual(audit_head(self.path)[0], 7)

    def test_reopening_continues_the_chain(self):
        AuditLog(self.path).request(component="test", method="GET", url="/api/y", status=200)
        ok, _, detail = verify_chain(self.path)
        self.assertTrue(ok, detail)


class TestRedaction(unittest.TestCase):
    def test_token_query_params_are_masked(self):
        url = redact_url("https://x/api/a?access_token=abc123&id=7")
        self.assertNotIn("abc123", url)
        self.assertIn("id=7", url)

    def test_auth_headers_are_masked(self):
        h = redact_headers({"Authorization": "Bearer tok-secret", "Accept": "application/json"})
        self.assertEqual(h["Authorization"], "<redacted>")
        self.assertEqual(h["Accept"], "application/json")

    def test_bearer_strings_inside_other_headers_are_masked(self):
        h = redact_headers({"X-Note": "sent with Bearer abcdef123456 yesterday"})
        self.assertNotIn("abcdef123456", h["X-Note"])

    def test_no_secret_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.jsonl"
            log = AuditLog(p)
            log.request(component="test", method="GET", url="/api/x?token=tok-agency-a",
                        request_headers={"Authorization": "Bearer tok-agency-a"})
            blob = p.read_text()
            self.assertNotIn("tok-agency-a", blob)


if __name__ == "__main__":
    unittest.main()
