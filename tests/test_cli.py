from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from tests.helpers import load_strongbox


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = load_strongbox()
        self.env = patch.dict(os.environ, {"STRONGBOX_CACHE_DIR": self.tmp.name}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_missing_subcommand(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main([])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("usage:", err.getvalue())

    def test_read_with_no_ref(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["read"])
        self.assertEqual(ctx.exception.code, 2)

    def test_revoke_with_no_args_and_no_all(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["revoke"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("strongbox revoke: specify REF or --all", err.getvalue())

    def test_inject_with_tty_stdin_refused(self):
        with patch.object(sys.stdin, "isatty", return_value=True):
            with self.assertRaises(SystemExit) as ctx:
                self.module.main(["inject"])
        self.assertIn("stdin is a tty", str(ctx.exception))

    def test_op_not_on_path(self):
        with patch.object(self.module.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(SystemExit) as ctx:
                self.module.main(["read", "op://a/b/c"])
        self.assertIn("'op' (1Password CLI) not found on PATH", str(ctx.exception))

    def test_op_read_non_zero_propagates(self):
        err = io.StringIO()
        cp = subprocess.CompletedProcess(["op", "read"], 1, "", "denied\n")
        with patch.object(self.module.subprocess, "run", return_value=cp), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                self.module.main(["read", "op://a/b/c"])
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("denied", err.getvalue())
