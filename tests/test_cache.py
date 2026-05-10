from __future__ import annotations

import datetime as dt
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from tests.helpers import load_strongbox


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = load_strongbox()
        self.env = patch.dict(os.environ, {"STRONGBOX_CACHE_DIR": self.tmp.name}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.ref = "op://vault/item/field"
        self.path = Path(self.tmp.name) / f"{self.module._ref_sha(self.ref)}.json"

    def test_read_write_round_trip(self):
        self.module._save_cached(self.ref, "secret")
        self.assertEqual(self.module._load_cached(self.ref), "secret")

    def test_mode_0600_enforced(self):
        self.module._save_cached(self.ref, "secret")
        self.path.chmod(0o640)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertIsNone(self.module._load_cached(self.ref))
        self.assertIn("expected 0600", err.getvalue())
        self.assertFalse(self.path.exists())

    def test_owner_mismatch_refusal(self):
        self.module._save_cached(self.ref, "secret")
        real_stat = Path.stat

        def fake_stat(path_obj, *args, **kwargs):
            st = real_stat(path_obj, *args, **kwargs)
            if path_obj != self.path:
                return st
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1, st.st_gid, st.st_size, st.st_atime, st.st_mtime, st.st_ctime))

        err = io.StringIO()
        with patch.object(Path, "stat", fake_stat), redirect_stderr(err):
            self.assertIsNone(self.module._read_cache_raw(self.path))
        self.assertIn("owned by uid", err.getvalue())

    def test_atomic_write_no_torn_file(self):
        cache_dir = Path(self.tmp.name)
        cache_dir.mkdir(exist_ok=True)
        path = cache_dir / "broken.json"

        def boom(payload, fp):
            fp.write("{")
            raise RuntimeError("boom")

        with patch.object(self.module.json, "dump", side_effect=boom):
            with self.assertRaises(RuntimeError):
                self.module._atomic_write_cache(path, {"x": 1})
        self.assertFalse(path.exists())
        self.assertEqual(list(cache_dir.glob("*.tmp.*")), [])

    def test_idle_ttl_expiry(self):
        self.module._save_cached(self.ref, "secret")
        data = json.loads(self.path.read_text())
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=5)).replace(microsecond=0)
        data["last_used"] = old.isoformat().replace("+00:00", "Z")
        self.path.write_text(json.dumps(data))
        with patch.dict(os.environ, {"STRONGBOX_TTL": "60"}, clear=False):
            self.assertIsNone(self.module._load_cached(self.ref))

    def test_last_used_touched_on_read(self):
        self.module._save_cached(self.ref, "secret")
        data = json.loads(self.path.read_text())
        recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).replace(microsecond=0)
        data["last_used"] = recent.isoformat().replace("+00:00", "Z")
        self.path.write_text(json.dumps(data))
        before = json.loads(self.path.read_text())["last_used"]
        with patch.dict(os.environ, {"STRONGBOX_TTL": "3600"}, clear=False):
            self.assertEqual(self.module._load_cached(self.ref), "secret")
        after = json.loads(self.path.read_text())["last_used"]
        self.assertNotEqual(before, after)

    def test_malformed_json_deleted_and_warned(self):
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        self.path.write_text("{bad")
        self.path.chmod(0o600)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertIsNone(self.module._load_cached(self.ref))
        self.assertIn("unreadable", err.getvalue())
        self.assertFalse(self.path.exists())

    def test_missing_required_fields_deleted_and_warned(self):
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        self.path.write_text(json.dumps({"ref": self.ref, "last_used": self.module.now_iso()}))
        self.path.chmod(0o600)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertIsNone(self.module._load_cached(self.ref))
        self.assertIn("missing ['value']", err.getvalue())
        self.assertFalse(self.path.exists())
