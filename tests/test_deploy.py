"""Deploy events as the change trigger: real, idempotent, and honest about coverage."""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dast.attacks.bola import BolaTarget
from dast.cli import _deploy_priority, main
from dast.deploy import DeployEvent, DeployState, assess, normalise_path
from dast.errors import DastError
from dast.pipeline import PlannedTest, prioritise_plan

BUNDLE_JS = """
export const A = "/v2/orders";
export const B = `/v2/orders/${id}/refund`;
export const C = `/v2/orders/${id}/reprice`;
export const D = `/v2/orders/${id}/statement`;
"""


class _BundleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/static/app.js"):
            blob = BUNDLE_JS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            return
        blob = b'{"error":"not found"}'
        self.send_response(404)
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)


class TestNormalise(unittest.TestCase):
    def test_paths_and_urls(self) -> None:
        self.assertEqual(normalise_path("/v2/orders"), "/v2/orders")
        self.assertEqual(normalise_path("v2/orders"), "/v2/orders")
        self.assertEqual(normalise_path("https://api.example.com/v2/orders/7f3a?x=1"), "/v2/orders/7f3a")
        self.assertEqual(normalise_path("/v2/orders/7f3a#frag"), "/v2/orders/7f3a")

    def test_empty_is_fatal(self) -> None:
        with self.assertRaises(DastError):
            normalise_path("")


class TestDeployEvent(unittest.TestCase):
    def test_minimal_event(self) -> None:
        event = DeployEvent.from_mapping({"sha": "abc123", "changed_paths": ["/v2/orders/42/refund"]})
        self.assertEqual(event.sha, "abc123")
        self.assertEqual(event.routes(), ["/v2/orders/{id}/refund"])

    def test_unknown_key_is_fatal(self) -> None:
        with self.assertRaises(DastError) as ctx:
            DeployEvent.from_mapping({"sha": "abc123", "commits": []})
        self.assertIn("commits", str(ctx.exception))

    def test_sha_is_required(self) -> None:
        with self.assertRaises(DastError) as ctx:
            DeployEvent.from_mapping({"changed_paths": ["/x"]})
        self.assertIn("sha", str(ctx.exception))

    def test_bundle_urls_must_be_absolute(self) -> None:
        with self.assertRaises(DastError):
            DeployEvent.from_mapping({"sha": "abc", "bundle_urls": ["static/app.js"]})

    def test_routes_are_template_and_deduplicated(self) -> None:
        event = DeployEvent.from_mapping(
            {
                "sha": "abc",
                "changed_paths": ["/v2/orders/1", "/v2/orders/2", "/v2/orders/1/refund"],
            }
        )
        self.assertEqual(event.routes(), ["/v2/orders/{id}", "/v2/orders/{id}/refund"])

    def test_load_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "event.json"
            p.write_text(json.dumps({"sha": "d1", "service": "orders", "at": "2026-11-19T09:00:00Z"}))
            event = DeployEvent.load(p)
            self.assertEqual(event.service, "orders")

    def test_missing_file(self) -> None:
        with self.assertRaises(DastError):
            DeployEvent.load("/nonexistent/event.json")

    def test_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "event.json"
            p.write_text("{nope")
            with self.assertRaises(DastError):
                DeployEvent.load(p)


class TestAssess(unittest.TestCase):
    def _inventory(self, tmp: Path, templates: list[str]) -> Path:
        p = tmp / "inventory.json"
        p.write_text(json.dumps({"endpoints": [{"template": t} for t in templates]}))
        return p

    def test_routes_are_split_into_known_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = self._inventory(root, ["/v2/orders/{id}", "/v2/orders/{id}/statement"])
            event = DeployEvent.from_mapping(
                {"sha": "s1", "changed_paths": ["/v2/orders/9/refund", "/v2/orders/9"]}
            )
            result = assess(event, inventory_path=inv)
            self.assertEqual(result.to_test, ["/v2/orders/{id}"])
            self.assertEqual(result.not_inventoried, ["/v2/orders/{id}/refund"])
            self.assertIn("not yet in the inventory", result.summary())

    def test_reads_the_real_inventory_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "inventory.json"
            inv.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {"method": "GET", "path_template": "/v2/orders/{id}", "label": "active"},
                            {"method": "POST", "path_template": "/v2/orders", "label": "active"},
                        ]
                    }
                )
            )
            event = DeployEvent.from_mapping({"sha": "s1", "changed_paths": ["/v2/orders/9/refund"]})
            result = assess(event, inventory_path=inv)
            self.assertEqual(result.inventory_known, 2)
            self.assertEqual(result.not_inventoried, ["/v2/orders/{id}/refund"])

    def test_no_inventory_yet_still_plans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            event = DeployEvent.from_mapping({"sha": "s1", "changed_paths": ["/v2/orders/9/refund"]})
            result = assess(event, inventory_path=Path(tmp) / "missing.json")
            self.assertEqual(result.to_test, ["/v2/orders/{id}/refund"])
            self.assertEqual(result.inventory_known, 0)

    def test_only_new_bundle_routes_become_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = self._inventory(root, ["/v2/orders/{id}", "/v2/orders/{id}/refund", "/v2/orders/{id}/cancel"])
            previous = DeployState(sha="old", bundle_routes=("/v2/orders/{id}",))
            event = DeployEvent.from_mapping({"sha": "new", "changed_paths": ["/v2/orders/9/refund"]})
            result = assess(
                event,
                inventory_path=inv,
                previous=previous,
                bundle_routes={"/v2/orders/{id}", "/v2/orders/{id}/refund", "/v2/orders/{id}/cancel"},
            )
            # /cancel is in the bundle but was already there last deploy: not news.
            self.assertEqual(result.new_routes, ["/v2/orders/{id}/cancel", "/v2/orders/{id}/refund"])
            self.assertEqual(result.to_test[0], "/v2/orders/{id}/refund", "CI's word comes first")
            self.assertNotIn("/v2/orders/{id}", result.to_test)

    def test_unchanged_bundle_produces_no_news(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inv = self._inventory(Path(tmp), ["/v2/orders/{id}"])
            bundle = ("/v2/orders/{id}", "/v2/orders/{id}/refund")
            previous = DeployState(sha="old", bundle_routes=bundle)
            event = DeployEvent.from_mapping({"sha": "new", "changed_paths": ["/v2/orders/9/refund"]})
            result = assess(event, inventory_path=inv, previous=previous, bundle_routes=bundle)
            self.assertEqual(result.new_routes, [])
            self.assertEqual(result.removed, [])

    def test_route_leaving_the_bundle_is_reported_as_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inv = self._inventory(Path(tmp), ["/v2/orders/{id}/cancel"])
            previous = DeployState(sha="old", bundle_routes=("/v2/orders/{id}", "/v2/orders/{id}/cancel"))
            event = DeployEvent.from_mapping({"sha": "new", "changed_paths": ["/v2/orders/9/cancel"]})
            result = assess(
                event, inventory_path=inv, previous=previous, bundle_routes={"/v2/orders/{id}/cancel"}
            )
            self.assertEqual(result.removed, ["/v2/orders/{id}"])
            self.assertEqual(result.new_routes, [])

    def test_empty_event_says_so(self) -> None:
        event = DeployEvent.from_mapping({"sha": "s1"})
        result = assess(event, inventory_path="/nonexistent")
        self.assertFalse(result.usable)
        self.assertIn("nothing to prioritise", result.summary())


class TestDeployState(unittest.TestCase):
    def test_round_trip_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deploy_state.json"
            event = DeployEvent.from_mapping({"sha": "s1", "changed_paths": ["/v2/orders/9/refund"]})
            state = DeployState().record(event, ["/v2/orders/{id}/refund"], now=datetime.now(timezone.utc))
            state.save(path)
            loaded = DeployState.load(path)
            self.assertTrue(loaded.already_processed(event))
            self.assertEqual(loaded.routes, ("/v2/orders/{id}/refund",))
            other = DeployEvent.from_mapping({"sha": "s2"})
            self.assertFalse(loaded.already_processed(other))

    def test_corrupt_state_does_not_stop_a_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deploy_state.json"
            path.write_text("{not json")
            self.assertEqual(DeployState.load(path).sha, "")

    def test_history_is_bounded(self) -> None:
        state = DeployState()
        now = datetime.now(timezone.utc)
        for i in range(30):
            state = state.record(DeployEvent.from_mapping({"sha": f"s{i}"}), [], now=now)
        self.assertLessEqual(len(state.history), 20)
        self.assertEqual(state.sha, "s29")


class TestDeployEventCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _BundleHandler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.out = self.root / "work"
        self.scope = self.root / "scope.json"
        # The bundle's prefixes come from the profile, exactly as in a real engagement.
        profile = self.root / "profile.json"
        raw_profile = json.loads((Path(__file__).resolve().parents[1] / "profiles" / "target2.json").read_text())
        raw_profile["name"] = "deploy-test"
        raw_profile["bundle"] = {"route_prefixes": ["/v2/"]}
        profile.write_text(json.dumps(raw_profile))
        self.scope.write_text(
            json.dumps(
                {
                    "name": "deploy-test",
                    "base_url": self.base,
                    "profile": str(profile),
                    "allow_hosts": ["127.0.0.1"],
                    "allow_methods": ["GET"],
                    "allow_paths": [
                        "/v2/health",
                        "/v2/orders",
                        "/v2/legacy/orders",
                        "/v2/internal/reports",
                        "/static/app.js",
                    ],
                    "max_rps_per_host": 50,
                    "max_burst": 50,
                    "max_total_requests": 50,
                    "kill_switch_file": "/tmp/dast-deploy-KILL",
                }
            )
        )
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "inventory.json").write_text(
            json.dumps({"endpoints": [{"template": "/v2/orders/{id}"}, {"template": "/v2/orders/{id}/refund"}]})
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _event(self, sha: str, **extra: Any) -> Path:
        p = self.root / f"event-{sha}.json"
        p.write_text(json.dumps({"sha": sha, "service": "tbo-orders-api", **extra}))
        return p

    def test_event_prioritises_routes_and_records_state(self) -> None:
        event = self._event(
            "aaa111",
            changed_paths=["/v2/orders/9/refund", "/v2/orders/9/reprice"],
        )
        code = main(["diff", "--scope", str(self.scope), "--out", str(self.out), "--deploy-event", str(event)])
        self.assertEqual(code, 0)
        state = DeployState.load(self.out / "deploy_state.json")
        self.assertEqual(state.sha, "aaa111")
        self.assertIn("/v2/orders/{id}/refund", state.routes)

    def test_same_sha_is_not_reprocessed(self) -> None:
        event = self._event("bbb222", changed_paths=["/v2/orders/9/refund"])
        self.assertEqual(main(["diff", "--scope", str(self.scope), "--out", str(self.out),
                               "--deploy-event", str(event)]), 0)
        state_first = DeployState.load(self.out / "deploy_state.json").processed_at
        # Replaying the webhook must be a no-op, not a second scan.
        self.assertEqual(main(["diff", "--scope", str(self.scope), "--out", str(self.out),
                               "--deploy-event", str(event)]), 0)
        self.assertEqual(DeployState.load(self.out / "deploy_state.json").processed_at, state_first)

    def test_bundle_url_is_fetched_through_the_guard(self) -> None:
        event = self._event("ccc333", bundle_urls=[f"{self.base}/static/app.js"])
        code = main(["diff", "--scope", str(self.scope), "--out", str(self.out), "--deploy-event", str(event)])
        self.assertEqual(code, 0)
        state = DeployState.load(self.out / "deploy_state.json")
        # Routes came from the fetched bundle, not from changed_paths.
        self.assertIn("/v2/orders/{id}/refund", state.routes)
        audit = (self.out / "audit.jsonl").read_text()
        self.assertIn("/static/app.js", audit, "the bundle fetch was not audited")

    def test_bundle_url_outside_scope_is_refused(self) -> None:
        event = self._event("ddd444", bundle_urls=["http://elsewhere.example.com/app.js"])
        code = main(["diff", "--scope", str(self.scope), "--out", str(self.out), "--deploy-event", str(event)])
        self.assertEqual(code, 2, "an out-of-scope bundle fetch must fail, not silently skip")
        self.assertEqual(DeployState.load(self.out / "deploy_state.json").sha, "")

    def test_no_deploy_event_keeps_bundle_hash_behaviour(self) -> None:
        # The old path still works: --bundle with a local file.
        bundle = self.root / "app.js"
        bundle.write_text(BUNDLE_JS)
        code = main(["diff", "--scope", str(self.scope), "--out", str(self.out), "--bundle", str(bundle)])
        self.assertEqual(code, 0)
        self.assertTrue((self.out / "bundle_state.json").exists())


class TestPrioritisePlan(unittest.TestCase):
    @staticmethod
    def _plan() -> list[PlannedTest]:
        return [
            PlannedTest("bola_dual_token", "/v2/orders/{id}", "read another tenant's order", False),
            PlannedTest("exposure_unauthenticated", "/v2/legacy/orders", "zombie route", False),
            PlannedTest("logic_double_refund", "/v2/orders/{id}/refund", "replay the refund", True),
            PlannedTest("logic_fare_tampering", "/v2/orders/{id}/reprice", "tamper the total", True),
        ]

    @staticmethod
    def _bola() -> list[BolaTarget]:
        return [
            BolaTarget("/v2/orders/{id}", "agency_a", "agency_b", "A", "B", "8842"),
            BolaTarget("/v2/orders/{id}/refund", "agency_a", "agency_b", "A", "B", "8842"),
        ]

    def test_no_priority_leaves_the_plan_alone(self) -> None:
        plan = self._plan()
        out, bola, deferred = prioritise_plan(plan, self._bola(), [])
        self.assertEqual([p.endpoint for p in out], [p.endpoint for p in plan])
        self.assertEqual(len(bola), 2)
        self.assertEqual(deferred, 0)

    def test_priority_routes_move_to_the_front(self) -> None:
        out, bola, deferred = prioritise_plan(self._plan(), self._bola(), ["/v2/orders/{id}/refund"])
        self.assertEqual(out[0].endpoint, "/v2/orders/{id}/refund")
        self.assertEqual(len(out), 4, "ordering must not drop tests")
        self.assertEqual([t.template for t in bola][0], "/v2/orders/{id}/refund")
        # 3 untouched plan entries + 1 untouched cross-tenant target
        self.assertEqual(deferred, 4)

    def test_changed_only_drops_the_untouched_routes(self) -> None:
        out, bola, deferred = prioritise_plan(
            self._plan(), self._bola(), ["/v2/orders/{id}/refund"], drop_others=True
        )
        self.assertEqual([p.endpoint for p in out], ["/v2/orders/{id}/refund"])
        self.assertEqual([t.template for t in bola], ["/v2/orders/{id}/refund"])
        self.assertEqual(deferred, 4)

    def test_concrete_paths_match_their_template(self) -> None:
        out, _bola, _deferred = prioritise_plan(
            self._plan(), [], ["/v2/orders/8842/reprice"], drop_others=True
        )
        self.assertEqual([p.endpoint for p in out], ["/v2/orders/{id}/reprice"])


class TestDeployPriorityArg(unittest.TestCase):
    def test_reads_the_default_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            DeployState(sha="f00d", routes=("/v2/orders/{id}/refund",)).save(out / "deploy_state.json")
            priority, source = _deploy_priority(
                argparse.Namespace(deploy_event="", deploy_state=""), out
            )
            self.assertEqual(priority, ["/v2/orders/{id}/refund"])
            self.assertIn("f00d", source)

    def test_no_state_means_a_full_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priority, source = _deploy_priority(
                argparse.Namespace(deploy_event="", deploy_state=""), Path(tmp)
            )
            self.assertEqual((priority, source), ([], ""))

    def test_event_wins_over_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            DeployState(sha="old", routes=("/v2/orders/{id}",)).save(root / "deploy_state.json")
            event = root / "event.json"
            event.write_text(json.dumps({"sha": "new", "changed_paths": ["/v2/orders/1/refund"]}))
            priority, source = _deploy_priority(
                argparse.Namespace(deploy_event=str(event), deploy_state=""), root
            )
            self.assertEqual(priority, ["/v2/orders/{id}/refund"])
            self.assertIn("new", source)


if __name__ == "__main__":
    unittest.main()
