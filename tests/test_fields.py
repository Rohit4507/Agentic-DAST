"""Dotted-path resolution: the layer that stops "which key holds the id" being a guess."""

from __future__ import annotations

import unittest

from dast.fields import as_float, as_int, dig, first, identity_of, rows, same, where


class TestDig(unittest.TestCase):
    def test_nested_key(self) -> None:
        payload = {"data": {"order": {"id": "abc"}}}
        self.assertEqual(dig(payload, "data.order.id"), "abc")

    def test_list_index(self) -> None:
        payload = {"data": {"orders": [{"id": "first"}, {"id": "second"}]}}
        self.assertEqual(dig(payload, "data.orders.1.id"), "second")

    def test_miss_returns_default(self) -> None:
        self.assertIsNone(dig({"a": 1}, "a.b.c"))
        self.assertEqual(dig({"a": 1}, "missing", "fallback"), "fallback")

    def test_empty_path_is_the_payload(self) -> None:
        payload = {"a": 1}
        self.assertEqual(dig(payload, ""), payload)

    def test_scalar_traversal_is_a_miss(self) -> None:
        self.assertIsNone(dig({"a": "text"}, "a.b"))


class TestFirst(unittest.TestCase):
    def test_picks_first_that_resolves(self) -> None:
        self.assertEqual(first({"booking_id": "42"}, ("data.id", "booking_id", "id")), "42")

    def test_empty_string_counts_as_absent(self) -> None:
        self.assertEqual(first({"id": "  ", "booking_id": "42"}, ("id", "booking_id")), "42")

    def test_zero_is_a_value_not_a_miss(self) -> None:
        self.assertEqual(first({"tenant": 0, "other": "x"}, ("tenant", "other")), 0)

    def test_false_is_a_value(self) -> None:
        self.assertIs(first({"deleted": False}, ("deleted",)), False)


class TestNumbers(unittest.TestCase):
    def test_plain_and_float(self) -> None:
        self.assertEqual(as_float(12.5), 12.5)
        self.assertEqual(as_float("12.5"), 12.5)

    def test_formatted_money(self) -> None:
        self.assertEqual(as_float("1,234.50"), 1234.5)
        self.assertEqual(as_float("INR 4500"), 4500.0)
        self.assertEqual(as_float("\u20b94500.25"), 4500.25)

    def test_garbage_is_default(self) -> None:
        self.assertEqual(as_float("n/a", 7.0), 7.0)
        self.assertEqual(as_float(None, 3.0), 3.0)
        self.assertEqual(as_int("41"), 41)


class TestRows(unittest.TestCase):
    def test_list_of_objects(self) -> None:
        self.assertEqual(rows([{"a": 1}, {"b": 2}]), [{"a": 1}, {"b": 2}])

    def test_single_object(self) -> None:
        self.assertEqual(rows({"a": 1}), [{"a": 1}])

    def test_junk_is_empty(self) -> None:
        self.assertEqual(rows("nope"), [])
        self.assertEqual(rows(None), [])


class TestIdentity(unittest.TestCase):
    def test_reports_which_path_matched(self) -> None:
        payload = {"data": {"order": {"id": "x"}}}
        self.assertEqual(identity_of(payload, ("data.order.id", "id")), ("data.order.id", "x"))

    def test_no_match(self) -> None:
        self.assertEqual(identity_of({}, ("a", "b")), ("", None))

    def test_cross_type_equality(self) -> None:
        self.assertTrue(same("8842", 8842))
        self.assertTrue(same("AB-12", "ab-12"))
        self.assertFalse(same(None, "x"))

    def test_where(self) -> None:
        self.assertEqual(where({"a": {"b": 1}}, ("a.b", "c")), "a.b")
        self.assertEqual(where({}, ("a",)), "")


if __name__ == "__main__":
    unittest.main()
