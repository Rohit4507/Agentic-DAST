"""Change detection: bundle hashing and the route delta."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dast.inventory.harvest import (
    changed_bundles,
    diff_route_sets,
    harvest_file,
    harvest_text,
    load_bundle_state,
    probe_candidates_from,
    routes_from_state,
    save_bundle_state,
    strip_comments,
)

BUNDLE_V1 = """
export const bookings = {
  list: () => api("/api/bookings"),
  get: (id) => api(`/api/booking/${id}`),
};
export const legacy = { v1: (id) => api(`/api/v1/booking/${id}`) };
"""

BUNDLE_V2 = BUNDLE_V1 + """
export const supplierQuotes = (id) => api(`/api/supplier/quote/${id}`);
"""


class TestHarvest(unittest.TestCase):
    def test_extracts_templated_routes(self):
        routes = harvest_text(BUNDLE_V1)
        self.assertIn("/api/bookings", routes)
        self.assertIn("/api/booking/{id}", routes)
        self.assertIn("/api/v1/booking/{id}", routes)

    def test_comments_are_not_routes(self):
        text = """
        // old: api("/api/legacy/thing")
        /* api("/api/blocked/thing") */
        api("/api/real/thing");
        """
        routes = harvest_text(text)
        self.assertIn("/api/real/thing", routes)
        self.assertNotIn("/api/legacy/thing", routes)
        self.assertNotIn("/api/blocked/thing", routes)

    def test_urls_in_strings_survive_the_stripper(self):
        # a naive `//` stripper would truncate a URL inside a string literal
        text = 'const base = "http://example.test/x"; // note\napi("/api/real");'
        out = strip_comments(text)
        self.assertIn("http://example.test/x", out)
        self.assertIn("/api/real", out)
        self.assertNotIn("note", out)

    def test_junk_is_dropped(self):
        routes = harvest_text('const API = "/api"; const x = "/not-an-api";')
        self.assertEqual(routes, set())

    def test_old_version_probes_are_derived_from_known_routes(self):
        probes = probe_candidates_from({"/api/booking/{id}"}, known={"/api/booking/{id}"}, per_prefix=3)
        self.assertIn("/api/v1/booking/{id}", probes)
        self.assertLessEqual(len(probes), 3)
        wider = probe_candidates_from({"/api/booking/{id}"}, per_prefix=6)
        self.assertIn("/api/old/booking/{id}", wider)


class TestChangeDetection(unittest.TestCase):
    def test_route_delta(self):
        delta = diff_route_sets({"/api/a", "/api/b"}, {"/api/b", "/api/c"})
        self.assertEqual(delta["added"], ["/api/c"])
        self.assertEqual(delta["removed"], ["/api/a"])
        self.assertEqual(delta["unchanged"], ["/api/b"])

    def test_state_round_trip_and_change_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_file = root / "state.json"
            v1 = root / "app.js"
            v1.write_text(BUNDLE_V1)
            first = harvest_file(v1)
            state = save_bundle_state(state_file, [first])

            reloaded = load_bundle_state(state_file)
            self.assertEqual(routes_from_state(reloaded), set(first.routes))
            self.assertEqual(changed_bundles([first], reloaded), [])

            v1.write_text(BUNDLE_V2)
            second = harvest_file(v1)
            self.assertEqual(len(changed_bundles([second], reloaded)), 1)
            delta = diff_route_sets(routes_from_state(reloaded), set(second.routes))
            self.assertEqual(delta["added"], ["/api/supplier/quote/{id}"])
            self.assertEqual(delta["removed"], [])

    def test_legacy_hash_only_state_is_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state.json"
            p.write_text('{"a.js": "deadbeef"}')
            state = load_bundle_state(p)
            self.assertEqual(state["a.js"]["routes"], [])


if __name__ == "__main__":
    unittest.main()
