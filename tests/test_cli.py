from __future__ import annotations

import io
import os
import shlex
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
        self.manifest_path = Path(self.tmp.name) / "manifest.toml"
        self.env = patch.dict(
            os.environ,
            {
                "STRONGBOX_CACHE_DIR": self.tmp.name,
                "STRONGBOX_MANIFEST": str(self.manifest_path),
            },
            clear=False,
        )
        self.env.start()
        os.environ.pop("STRONGBOX_OP_TIMEOUT", None)
        self.addCleanup(self.env.stop)

    def write_manifest(self, contents: str) -> None:
        self.manifest_path.write_text(contents, encoding="utf-8")

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

    def test_read_manifest_name_resolves_via_op(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\n')
        cp = subprocess.CompletedProcess(["op", "read"], 0, "secret\n", "")
        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", return_value=cp) as run_mock, redirect_stdout(out):
            self.assertEqual(self.module.main(["read", "kagi"]), 0)
        self.assertEqual(out.getvalue(), "secret\n")
        self.assertEqual(run_mock.call_args.args[0], ["op", "read", "op://Private/kagi.com/api_key"])

    def test_read_direct_ref_still_works_unchanged(self):
        cp = subprocess.CompletedProcess(["op", "read"], 0, "secret\n", "")
        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", return_value=cp) as run_mock, redirect_stdout(out):
            self.assertEqual(self.module.main(["read", "op://a/b/c"]), 0)
        self.assertEqual(out.getvalue(), "secret\n")
        self.assertEqual(run_mock.call_args.args[0], ["op", "read", "op://a/b/c"])

    def test_read_unknown_manifest_name_lists_known_names(self):
        self.write_manifest(
            '[keys.kagi]\nref = "op://Private/kagi.com/api_key"\n\n'
            '[keys.github_token]\nref = "op://Personal/GitHub PAT/credential"\n'
        )
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["read", "openai"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("unknown manifest name 'openai'", err.getvalue())
        self.assertIn("known names: github_token, kagi", err.getvalue())

    def test_read_name_with_no_manifest_file_mentions_missing_manifest(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["read", "kagi"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn(f"no manifest at {self.manifest_path}", err.getvalue())

    def test_load_emits_shell_quoted_exports(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\n')
        cp = subprocess.CompletedProcess(["op", "read"], 0, "s p'ace\n", "")
        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", return_value=cp), redirect_stdout(out):
            self.assertEqual(self.module.main(["load", "kagi"]), 0)
        expected = shlex.quote("s p'ace")
        self.assertEqual(out.getvalue(), f"export KAGI={expected}\n")

    def test_load_uses_env_override(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\nenv = "KAGI_KEY"\n')
        cp = subprocess.CompletedProcess(["op", "read"], 0, "secret\n", "")
        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", return_value=cp), redirect_stdout(out):
            self.assertEqual(self.module.main(["load", "kagi"]), 0)
        self.assertEqual(out.getvalue(), "export KAGI_KEY=secret\n")

    def test_load_defaults_env_to_uppercase_name(self):
        self.write_manifest('[keys.github_token]\nref = "op://Personal/GitHub PAT/credential"\n')
        cp = subprocess.CompletedProcess(["op", "read"], 0, "secret\n", "")
        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", return_value=cp), redirect_stdout(out):
            self.assertEqual(self.module.main(["load", "github_token"]), 0)
        self.assertEqual(out.getvalue(), "export GITHUB_TOKEN=secret\n")

    def test_load_multiple_names_preserves_input_order(self):
        self.write_manifest(
            '[keys.b]\nref = "op://vault/b"\n'
            '[keys.a]\nref = "op://vault/a"\n'
            '[keys.c]\nref = "op://vault/c"\n'
        )

        def fake_run(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, args[-1].split("/")[-1] + "\n", "")

        out = io.StringIO()
        with patch.object(self.module.subprocess, "run", side_effect=fake_run), redirect_stdout(out):
            self.assertEqual(self.module.main(["load", "a", "c", "b"]), 0)
        self.assertEqual(
            out.getvalue().splitlines(),
            ["export A=a", "export C=c", "export B=b"],
        )

    def test_load_partial_failure_emits_no_stdout_and_loads_manifest_once(self):
        self.write_manifest(
            '[keys.a]\nref = "op://vault/a"\n'
            '[keys.c]\nref = "op://vault/c"\n'
        )
        out = io.StringIO()
        err = io.StringIO()
        load_manifest = self.module._load_manifest
        with patch.object(self.module, "_load_manifest", wraps=load_manifest) as load_manifest_mock:
            with self.assertRaises(SystemExit) as ctx, redirect_stdout(out), redirect_stderr(err):
                self.module.main(["load", "a", "unknown_b", "c"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("unknown manifest names: 'unknown_b'", err.getvalue())
        self.assertEqual(load_manifest_mock.call_count, 1)

    def test_load_unknown_name_lists_known_names(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\n')
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stderr(err):
            self.module.main(["load", "openai"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("known names: kagi", err.getvalue())

    def test_manifest_lists_entries_and_env_overrides(self):
        self.write_manifest(
            '[keys.github_token]\nref = "op://Personal/GitHub PAT/credential"\n\n'
            '[keys.kagi]\nref = "op://Private/kagi.com/api_key"\nenv = "KAGI_KEY"\n'
        )
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.module.main(["manifest"]), 0)
        self.assertEqual(
            out.getvalue().splitlines(),
            [
                "github_token → op://Personal/GitHub PAT/credential",
                "kagi → op://Private/kagi.com/api_key → KAGI_KEY",
            ],
        )

    def test_manifest_with_empty_manifest_file_prints_manifest_empty(self):
        self.write_manifest("")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.module.main(["manifest"]), 0)
        self.assertEqual(out.getvalue().strip(), "manifest empty")

    def test_manifest_with_no_manifest_file_prints_path(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.module.main(["manifest"]), 0)
        self.assertEqual(out.getvalue().strip(), f"no manifest at {self.manifest_path}")

    def test_malformed_manifest_toml_exits_non_zero_with_parse_error(self):
        self.write_manifest('[keys.kagi]\nref = "oops"\nunterminated = [\n')
        with self.assertRaises(SystemExit) as ctx:
            self.module.main(["manifest"])
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("parse error", str(ctx.exception))
        self.assertIn("line 4, column 1", str(ctx.exception))

    def test_invalid_manifest_name_is_rejected(self):
        self.write_manifest('[keys.Kagi]\nref = "op://Private/kagi.com/api_key"\n')
        with self.assertRaises(SystemExit) as ctx:
            self.module.main(["manifest"])
        self.assertIn("invalid key name 'Kagi'", str(ctx.exception))

    def test_invalid_manifest_env_is_rejected(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\nenv = "kagi_key"\n')
        with self.assertRaises(SystemExit) as ctx:
            self.module.main(["manifest"])
        self.assertIn("invalid env 'kagi_key'", str(ctx.exception))

    def test_invalid_manifest_env_starting_with_digit_is_rejected(self):
        self.write_manifest('[keys.kagi]\nref = "op://Private/kagi.com/api_key"\nenv = "1KAGI"\n')
        with self.assertRaises(SystemExit) as ctx:
            self.module.main(["manifest"])
        self.assertIn("invalid env '1KAGI'", str(ctx.exception))

    def test_manifest_entry_requires_ref(self):
        self.write_manifest('[keys.kagi]\nenv = "KAGI_KEY"\n')
        with self.assertRaises(SystemExit) as ctx:
            self.module.main(["manifest"])
        self.assertIn("must define a string 'ref'", str(ctx.exception))

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
