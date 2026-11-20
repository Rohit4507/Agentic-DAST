"""The claim this whole layer exists to support: one scanner, two different APIs.

`target2` speaks ``/v2/...`` with everything nested under ``data``, ``tenant`` instead
of ``agencyId``, ``value``/``state`` instead of ``amount``/``status``.  The bundled mock
speaks ``/api/...`` flat.  Both are vulnerable in the same classes.

If the scanner is genuinely target-independent it finds those classes on both, through
a profile, with no code change.  If it is not, this file fails -- which is the point.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from dast.audit import verify_chain
from dast.pipeline import open_engagement, run_all
from target2.app import make_server
from target2.fixtures import ORDER_A, write_all

REPO = Path(__file__).resolve().parent.parent
TARGET2_PROFILE = REPO / "profiles" / "target2.json"
MOCK_PROFILE = REPO / "profiles" / "mock.json"

#: Classes that need *no* knowledge of the target's vocabulary.
ROUTE_ONLY = {"unauthenticated_data_exposure"}
#: Classes that only fire if identity / boundary / body / ledger vocabulary is right.
VOCABULARY_DEPENDENT = {"bola", "double_refund", "skipped_payment", "fare_tampering"}


def _scope(
    base_url: str,
    profile: Path,
    bundle: Path,
    assets: Path,
    *,
    extra_paths: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "name": "target2-genericity",
        "base_url": base_url,
        "profile": str(profile),
        "allow_hosts": ["127.0.0.1"],
        "allow_methods": ["GET", "POST"],
        "allow_paths": [
            "/v2/health",
            "/v2/orders",
            "/v2/legacy/orders",
            "/v2/internal/reports",
            *extra_paths,
        ],
        "deny_paths": ["/v2/admin"],
        "max_rps_per_host": 50,
        "max_burst": 50,
        "max_total_requests": 200,
        "max_wait_seconds": 5,
        "accounts": {"tenant_a": "literal:tok-tenant-a", "tenant_b": "literal:tok-tenant-b"},
        "kill_switch_file": "/tmp/dast-test-KILL",
        "traffic_window_days": 30,
        "js_bundles": [str(bundle)],
        "assets_file": str(assets),
    }


class TestSecondTarget(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.fixtures = write_all(cls.root / "fixtures", base=cls.base)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmp.cleanup()

    def _run(self, profile: Path, name: str):
        # The negative control keeps the mock's /api/... paths in the allowlist so the
        # open-time scope check does not fire; nothing listens there, which is the point.
        extra = (
            ("/api/hold", "/api/pay", "/api/confirm", "/api/cancel", "/api/refund",
             "/api/rebook", "/api/ledger", "/api/bookings", "/api/booking")
            if profile == MOCK_PROFILE
            else ()
        )
        scope_path = self.root / f"{name}.json"
        scope_path.write_text(
            json.dumps(
                _scope(
                    self.base,
                    profile,
                    REPO / "target2" / "static" / "app.js",
                    REPO / "target2" / "assets.json",
                    extra_paths=extra,
                ),
                indent=2,
            ),
            encoding="utf-8",
        )
        out = self.root / name
        eng = open_engagement(scope_path, out)
        result = run_all(
            eng,
            capture_dir=self.fixtures["captures"],
            gateway_paths=[self.fixtures["gateway"]],
            approve_writes=True,
        )
        return eng, result

    # -- the proof ------------------------------------------------------------------
    def test_same_classes_found_with_no_code_change(self) -> None:
        eng, result = self._run(TARGET2_PROFILE, "target2")

        classes = {f.vuln_class for f in result.report.findings}
        self.assertTrue(
            VOCABULARY_DEPENDENT <= classes,
            f"missing {VOCABULARY_DEPENDENT - classes}; found {classes}",
        )
        self.assertTrue(ROUTE_ONLY <= classes)

        # Every finding is on this target's vocabulary, not the mock's.
        for finding in result.report.findings:
            self.assertTrue(finding.endpoint.startswith("/v2/"), finding.endpoint)
            self.assertNotIn("/api/", finding.endpoint)

        # Cross-tenant proof came from a *nested* identity field.
        bola = [f for f in result.report.findings if f.vuln_class == "bola"]
        self.assertTrue(bola)
        extracted = bola[0].evidence.extracted
        self.assertEqual(extracted["identity_field"], "data.order.id")
        self.assertEqual(extracted["object_id"], ORDER_A)
        self.assertEqual(extracted["data_classes"], ["PII"])

        # The safety layer held: nothing denied, nothing outside scope, chain intact.
        self.assertEqual(eng.guard.stats.denied, 0)
        ok, seq, detail = verify_chain(eng.audit.path)
        self.assertTrue(ok, f"audit chain broken at {seq}: {detail}")

    def test_ledger_proof_used_the_mapped_statement(self) -> None:
        _eng, result = self._run(TARGET2_PROFILE, "target2-ledger")
        refund = [f for f in result.report.findings if f.vuln_class == "double_refund"]
        self.assertTrue(refund, "double refund not proven against the mapped ledger")
        ledger = refund[0].evidence.extracted["ledger"]
        self.assertEqual(ledger["successfulRefunds"], 2)

        # The capsule's ledger step is the statement route, not a mock path.
        capsule = refund[0].to_dict()["evidence"]
        steps = json.dumps(capsule)
        self.assertIn("/v2/orders/", steps)
        self.assertNotIn("/api/ledger", steps)

    def test_noun_is_the_targets_own(self) -> None:
        _eng, result = self._run(TARGET2_PROFILE, "target2-noun")
        titles = " ".join(f.title for f in result.report.findings)
        self.assertIn("order ", titles)
        self.assertNotIn("booking", titles)

    # -- the negative control -------------------------------------------------------
    def test_mock_profile_on_target2_finds_no_logic_or_bola(self) -> None:
        """Swap in the mock's vocabulary and the vocabulary-dependent tests go quiet.

        This is what isolates the cause: same target, same traffic, same code -- only
        the profile changes.  Route-driven exposure still works, which is why this is
        a *partial* failure rather than total silence: it is exactly the silent
        false-negative the profile layer exists to remove.
        """
        _eng, result = self._run(MOCK_PROFILE, "target2-with-mock-profile")
        classes = {f.vuln_class for f in result.report.findings}
        self.assertFalse(classes & VOCABULARY_DEPENDENT, f"unexpected {classes & VOCABULARY_DEPENDENT}")

    def test_skipped_tests_are_recorded_with_a_reason(self) -> None:
        eng, _result = self._run(MOCK_PROFILE, "target2-skipped")
        notes = [json.loads(line) for line in eng.audit.path.read_text().splitlines()]
        skipped = [n for n in notes if n.get("kind") == "tests-skipped"]
        self.assertTrue(skipped, "no tests-skipped note was written")
        reasons = json.dumps(skipped[0])
        self.assertIn("not an inventoried route", reasons)


class TestProfileGuardsTheScope(unittest.TestCase):
    def test_profile_naming_out_of_scope_paths_fails_at_open_time(self) -> None:
        """A profile pointing outside the allowlist must fail loudly, not run silently."""
        from dast.errors import DastError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_path = root / "scope.json"
            scope_path.write_text(
                json.dumps(
                    {
                        "name": "narrow",
                        "base_url": "http://127.0.0.1:9",
                        "profile": str(TARGET2_PROFILE),
                        "allow_hosts": ["127.0.0.1"],
                        "allow_methods": ["GET", "POST"],
                        "allow_paths": ["/v2/health"],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(DastError) as ctx:
                open_engagement(scope_path, root / "out")
            self.assertIn("allowlist", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
