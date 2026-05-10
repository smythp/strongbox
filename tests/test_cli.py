from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.helpers import load_strongbox


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = load_strongbox()
        self.env = patch.dict(
            os.environ,
            {"STRONGBOX_CACHE_DIR": self.tmp.name},
            clear=False,
        )
        self.env.start()
        os.environ.pop("STRONGBOX_OP_TIMEOUT", None)
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

    def test_revoke_ref_and_all_are_mutually_exclusive(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["revoke", "op://a/b/c", "--all"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("strongbox revoke: REF and --all are mutually exclusive", err.getvalue())

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

    def test_op_read_timeout_exits_with_clear_message(self):
        with patch.object(
            self.module.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["op", "read"], timeout=60),
        ):
            with self.assertRaises(SystemExit) as ctx:
                self.module.main(["read", "op://a/b/c"])
        self.assertEqual(
            str(ctx.exception),
            "strongbox: 'op read' timed out after 60s; biometric prompt may be stuck or 1Password is unreachable",
        )

    def test_op_read_timeout_zero_disables_subprocess_timeout(self):
        cp = subprocess.CompletedProcess(["op", "read"], 0, "secret\n", "")
        out = io.StringIO()
        with patch.dict(os.environ, {"STRONGBOX_OP_TIMEOUT": "0"}, clear=False), patch.object(
            self.module.subprocess,
            "run",
            return_value=cp,
        ) as run_mock, redirect_stdout(out):
            self.assertEqual(self.module.main(["read", "op://a/b/c"]), 0)
        self.assertIsNone(run_mock.call_args.kwargs["timeout"])

    def test_revoke_all_removes_cache_dir(self):
        self.module._save_cached("op://a/b/c", "secret")
        cache_dir = Path(self.tmp.name)
        self.assertTrue(any(cache_dir.iterdir()))
        self.assertEqual(self.module.main(["revoke", "--all"]), 0)
        self.assertFalse(cache_dir.exists())

    def test_revoke_all_without_runtime_base_is_noop(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(self.module, "_find_runtime_base", return_value=None):
            self.assertEqual(self.module.main(["revoke", "--all"]), 0)

    def test_status_empty_cache_prints_cache_empty(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.module.main(["status"]), 0)
        self.assertEqual(out.getvalue().strip(), "cache empty")

    def test_status_lists_cached_entries(self):
        self.module._save_cached("op://a/b/c", "one")
        self.module._save_cached("op://d/e/f", "two")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.module.main(["status"]), 0)
        lines = [line for line in out.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertIn("op://a/b/c", lines[0] + lines[1])
        self.assertIn("op://d/e/f", lines[0] + lines[1])

    def test_status_ref_not_cached_exits_one(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(self.module.main(["status", "op://a/b/c"]), 1)
        self.assertIn("not cached: op://a/b/c", err.getvalue())

    def test_status_without_runtime_base_treats_cache_as_empty(self):
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(self.module, "_find_runtime_base", return_value=None), redirect_stdout(out):
            self.assertEqual(self.module.main(["status"]), 0)
        self.assertEqual(out.getvalue().strip(), "cache empty")
