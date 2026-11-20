"""The target profile: fail-closed validation, and no drift from the mock's defaults."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dast.errors import DastError
from dast.profile import FlowProfile, LedgerSpec, StepSpec, TargetProfile
from dast.scope import ScopeConfig

REPO = Path(__file__).resolve().parent.parent
MOCK_PROFILE = REPO / "profiles" / "mock.json"
TARGET2_PROFILE = REPO / "profiles" / "target2.json"


class TestMockProfileIsTheBuiltInDefault(unittest.TestCase):
    """profiles/mock.json must not drift from the vocabulary the code falls back to."""

    def test_flows_match(self) -> None:
        built_in = TargetProfile.mock_defaults()
        on_disk = TargetProfile.load(MOCK_PROFILE)
        self.assertEqual(
            {k: v.to_dict() for k, v in built_in.flows.steps.items()},
            {k: v.to_dict() for k, v in on_disk.flows.steps.items()},
        )

    def test_identifiers_and_ledger_match(self) -> None:
        built_in = TargetProfile.mock_defaults()
        on_disk = TargetProfile.load(MOCK_PROFILE)
        self.assertEqual(built_in.identifiers.to_dict(), on_disk.identifiers.to_dict())
        self.assertEqual(built_in.ledger.to_dict(), on_disk.ledger.to_dict())
        self.assertEqual(built_in.bundle.to_dict(), on_disk.bundle.to_dict())

    def test_bundle_prefixes_default_to_api(self) -> None:
        self.assertEqual(TargetProfile.mock_defaults().bundle.route_prefixes, ("/api/",))


class TestStepRendering(unittest.TestCase):
    def test_path_substitution(self) -> None:
        step = StepSpec(name="refund", path="/v2/orders/{id}/refund", method="POST", body={})
        self.assertEqual(step.url(id="abc"), "/v2/orders/abc/refund")

    def test_whole_placeholder_keeps_its_type(self) -> None:
        step = StepSpec(
            name="pay", path="/x", method="POST", body={"value": "{amount}", "label": "INR {amount}"}
        )
        payload = step.payload(amount=750.0)
        self.assertEqual(payload["value"], 750.0)
        self.assertIsInstance(payload["value"], float)
        self.assertEqual(payload["label"], "INR 750.0")

    def test_nested_body(self) -> None:
        step = StepSpec(
            name="pay",
            path="/x",
            method="POST",
            body={"data": {"order": {"id": "{id}"}}, "tags": ["{id}"]},
        )
        self.assertEqual(step.payload(id="g-1"), {"data": {"order": {"id": "g-1"}}, "tags": ["g-1"]})


class TestFailClosed(unittest.TestCase):
    def _profile(self, raw: dict) -> TargetProfile:
        return TargetProfile.from_mapping(raw)

    def test_unknown_top_level_key_is_fatal(self) -> None:
        with self.assertRaises(DastError) as ctx:
            self._profile({"name": "x", "flowz": {}})
        self.assertIn("flowz", str(ctx.exception))

    def test_unknown_step_is_fatal(self) -> None:
        with self.assertRaises(DastError) as ctx:
            self._profile({"flows": {"refnd": {"path": "/x"}}})
        self.assertIn("refnd", str(ctx.exception))

    def test_unknown_placeholder_is_fatal(self) -> None:
        with self.assertRaises(DastError) as ctx:
            self._profile({"flows": {"refund": {"path": "/x", "body": {"a": "{amont}"}}}})
        self.assertIn("amont", str(ctx.exception))

    def test_relative_path_is_fatal(self) -> None:
        with self.assertRaises(DastError):
            self._profile({"flows": {"refund": {"path": "refund"}}})

    def test_bad_ledger_adapter_is_fatal(self) -> None:
        with self.assertRaises(DastError):
            self._profile({"ledger": {"adapter": "telepathy"}})

    def test_fixture_adapter_requires_a_path(self) -> None:
        with self.assertRaises(DastError):
            self._profile({"ledger": {"adapter": "fixture"}})

    def test_ledger_none_is_allowed_and_reported_unusable(self) -> None:
        profile = self._profile({"ledger": "none"})
        self.assertEqual(profile.ledger.adapter, "none")
        self.assertFalse(profile.ledger.usable)

    def test_missing_step_is_allowed(self) -> None:
        profile = self._profile({"flows": {"hold": {"path": "/hold", "id_from": "id"}}})
        self.assertIsNotNone(profile.flows.get("hold"))
        self.assertIsNone(profile.flows.get("rebook"))
        self.assertIn("rebook", profile.flows.missing)

    def test_bundle_prefix_must_be_absolute(self) -> None:
        with self.assertRaises(DastError):
            self._profile({"bundle": {"route_prefixes": ["v2/"]}})

    def test_empty_object_noun_is_fatal(self) -> None:
        with self.assertRaises(DastError):
            self._profile({"identifiers": {"object_noun": "  "}})


class TestTarget2Profile(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = TargetProfile.load(TARGET2_PROFILE)

    def test_every_step_is_configured(self) -> None:
        self.assertEqual(self.profile.flows.missing, [])

    def test_identity_and_boundary_are_nested(self) -> None:
        self.assertIn(".", self.profile.identifiers.identity_field)
        self.assertIn(".", self.profile.identifiers.boundary_field)

    def test_ledger_maps_foreign_field_names(self) -> None:
        mapping = self.profile.ledger.map
        self.assertEqual(mapping["refunds"], "data.reversals")
        self.assertEqual(self.profile.ledger.item_map["amount"], "value")

    def test_bola_exclusions_do_not_swallow_the_whole_api(self) -> None:
        # The mock's default excludes /v2/, which would exclude every real route here.
        self.assertNotIn("/v2/orders", " ".join(self.profile.bola.exclude_templates))

    def test_noun_and_prefixes(self) -> None:
        self.assertEqual(self.profile.identifiers.object_noun, "order")
        self.assertEqual(self.profile.bundle.route_prefixes, ("/v2/",))


class TestRoutesOutsideScope(unittest.TestCase):
    def _scope(self, paths: list[str]) -> ScopeConfig:
        raw = {
            "name": "t",
            "base_url": "http://127.0.0.1:9",
            "allow_hosts": ["127.0.0.1"],
            "allow_methods": ["GET", "POST"],
            "allow_paths": paths,
        }
        return ScopeConfig.from_mapping(raw)

    def test_detects_uncovered_flow_paths(self) -> None:
        from dast.pipeline import routes_outside_scope

        scope = self._scope(["/v2/health"])
        outside = routes_outside_scope(scope, TargetProfile.load(TARGET2_PROFILE))
        self.assertTrue(outside)
        self.assertIn("/v2/orders/{id}/refund", outside)

    def test_covered_paths_pass(self) -> None:
        from dast.pipeline import routes_outside_scope

        scope = self._scope(["/v2/orders", "/v2/orders/{id}", "/v2/ledger"])
        profile = TargetProfile.from_mapping(
            {"flows": {"refund": {"path": "/v2/orders/:id/refund"}}, "ledger": "none"}
        )
        self.assertEqual(routes_outside_scope(scope, profile), [])


class TestLoadErrors(unittest.TestCase):
    def test_missing_file(self) -> None:
        with self.assertRaises(DastError):
            TargetProfile.load("/nonexistent/profile.json")

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            with self.assertRaises(DastError):
                TargetProfile.load(p)

    def test_summary_mentions_vocabulary(self) -> None:
        summary = TargetProfile.load(TARGET2_PROFILE).summarize()
        self.assertIn("target2-orders-api", summary)
        self.assertIn("data.order.id", summary)


if __name__ == "__main__":
    unittest.main()
