import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pii_mask as pm

K = b"k"


class ValueTests(unittest.TestCase):
    def test_hash_is_stable_and_keyed(self):
        self.assertEqual(pm.mask_value("a", "hash", "", K), pm.mask_value("a", "hash", "", K))
        self.assertNotEqual(pm.mask_value("a", "hash", "", K), pm.mask_value("a", "hash", "", b"other"))

    def test_partial(self):
        self.assertEqual(pm.mask_value("+971501234567", "partial", "4", K), "*********4567")
        self.assertEqual(pm.mask_value("12", "partial", "4", K), "**")

    def test_email_keeps_domain(self):
        self.assertTrue(pm.mask_value("ali@example.com", "email", "", K).endswith("@example.com"))
        self.assertNotIn("ali", pm.mask_value("ali@example.com", "email", "", K))

    def test_empty_stays_empty(self):
        self.assertEqual(pm.mask_value("", "redact", "", K), "")

    def test_bad_rules(self):
        for bad in ["email", "x=nope", "x=partial:a"]:
            with self.assertRaises(ValueError):
                pm.parse_rule(bad)


class RowTests(unittest.TestCase):
    def test_drop_and_missing(self):
        fields, rows = pm.mask_rows([{"a": "1", "b": "2"}], ["a", "b"], {"b": ("drop", "")}, K)
        self.assertEqual((fields, rows), (["a"], [{"a": "1"}]))
        with self.assertRaises(KeyError):
            pm.mask_rows([], ["a"], {"z": ("redact", "")}, K)

    def test_cli_requires_key_for_hash(self):
        src = os.path.join(os.path.dirname(__file__), "samples", "customers.csv")
        with mock.patch.dict(os.environ, {}, clear=True), redirect_stderr(io.StringIO()):
            self.assertEqual(pm.main([src, "--rule", "name=hash"]), 2)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"PII_MASK_KEY": "s"}), redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(pm.main([src, "--rule", "name=hash", "--rule", "iban=drop", "--rule", "phone=partial:4"]), 0)
        text = out.getvalue()
        self.assertNotIn("Ali Khan", text)
        self.assertNotIn("iban", text)
        self.assertIn("*********4567", text)


if __name__ == "__main__":
    unittest.main()
