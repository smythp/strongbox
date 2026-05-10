from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from tests.helpers import load_strongbox


class InjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = load_strongbox()
        self.env = patch.dict(os.environ, {"STRONGBOX_CACHE_DIR": self.tmp.name}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_bare_ref_substitution(self):
        with patch.object(self.module, "resolve_ref", return_value="secret"):
            self.assertEqual(self.module.render_template("x=op://vault/item/field"), "x=secret")

    def test_braced_ref_substitution_with_and_without_whitespace(self):
        with patch.object(self.module, "resolve_ref", side_effect=["a", "b"]):
            self.assertEqual(self.module.render_template("{{ op://a/b/c }} {{op://d/e/f}}"), "a b")

    def test_mixed_bare_and_braced(self):
        refs = {"op://a/b/c": "one", "op://d/e/f": "two"}
        with patch.object(self.module, "resolve_ref", side_effect=lambda ref: refs[ref]):
            self.assertEqual(self.module.render_template("A={{ op://a/b/c }} B=op://d/e/f"), "A=one B=two")

    def test_multiple_refs_same_ref_resolved_once(self):
        with patch.object(self.module, "resolve_ref", return_value="secret") as mock_resolve:
            out = self.module.render_template("{{ op://a/b/c }} and op://a/b/c and {{op://a/b/c}}")
        self.assertEqual(out, "secret and secret and secret")
        self.assertEqual(mock_resolve.call_count, 1)

    def test_resolved_value_containing_op_ref_is_not_reprocessed(self):
        refs = {
            "op://a/b/c": "literal op://d/e/f",
            "op://d/e/f": "second",
        }
        with patch.object(self.module, "resolve_ref", side_effect=lambda ref: refs[ref]) as mock_resolve:
            out = self.module.render_template("{{ op://a/b/c }}")
        self.assertEqual(out, "literal op://d/e/f")
        self.assertEqual(mock_resolve.call_args_list, [(("op://a/b/c",), {})])

    def test_non_ref_lookalikes_not_matched(self):
        with patch.object(self.module, "resolve_ref", return_value="secret"):
            self.assertEqual(self.module.render_template("https://op.example/foo"), "https://op.example/foo")

    def test_multiline_templates_preserved(self):
        with patch.object(self.module, "resolve_ref", return_value="secret"):
            template = "line1\n{{ op://a/b/c }}\nline3 op://a/b/c\n"
            self.assertEqual(self.module.render_template(template), "line1\nsecret\nline3 secret\n")
