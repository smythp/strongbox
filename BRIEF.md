# strongbox — implementation brief

You are building **strongbox**, a drop-in replacement for `op inject` (1Password CLI) that transparently caches resolved secrets in a per-user tmpfs dir so the same secret isn't re-fetched (and re-prompted) for every invocation.

This solves a concrete problem: Claude Code spawns a fresh shell for every Bash tool call. `op` in some configurations prompts on each call. The resulting "1Password modal pops up every 30 seconds while an agent works" makes the workflow unusable. strongbox sits between tools and `op`, fronting it with a tmpfs cache.

The user has already battle-tested the cache hardening in `reference/sheet.py` (the auth section, lines ~50-342). **Read that file end-to-end before writing anything.** Reuse the actual functions where you can. The hardening rules (mode 0600, owner check, atomic writes, idle TTL with `last_used` touch, refuse-and-warn on tampering) are non-negotiable and load-bearing — adapt the code, don't rewrite the security logic from first principles.

## Surface

```
strongbox inject [-i FILE]      # like `op inject -i FILE` — substitutes op:// refs in the template, writes to stdout. Reads stdin if no -i.
strongbox read REF              # resolve a single op:// ref, print value to stdout
strongbox status [REF]          # show cache state — all entries or one
strongbox revoke (REF | --all)  # delete one cache entry or wipe the cache dir
```

`strongbox inject` is the migration path: any tool that calls `op inject -i template.tpl` swaps `op` → `strongbox` and gains caching for free. `strongbox read` is for new tools that want a single secret without a template file.

## Cache layout

Per-user, tmpfs-backed:

```
$XDG_RUNTIME_DIR/strongbox/
  <sha256-of-ref>.json    # one file per resolved op:// reference
  <sha256-of-ref>.json
  ...
```

Each cache file:

```json
{
  "ref": "op://Personal/Kagi/credential",
  "value": "the-actual-secret",
  "last_used": "2026-05-10T12:34:56Z",
  "created_at": "2026-05-10T12:34:56Z"
}
```

- Mode 0600, owner-checked (must be `geteuid()`)
- Atomic write via `os.replace` from a `.tmp.<pid>` file
- Idle TTL: env var `STRONGBOX_TTL` (default 14400 = 4h, 0 disables)
- `last_used` touched on each successful read; expiry is idle-time, not absolute
- Operator escape hatch: `STRONGBOX_CACHE_DIR` overrides the cache base
- On any tampering (wrong mode, wrong uid, malformed JSON): print a stderr warning explaining what was wrong, delete the file, fall through to op

The sha256 keying means two tools resolving the same ref share a cache entry. The cache file body holds the actual ref string for `status` to display.

## Resolution path

For each `op://...` reference:

1. Compute `sha256(ref).hexdigest()` for the cache key
2. Cache lookup. If hit and not idle-expired and validated: touch `last_used`, return cached value.
3. Cache miss / expired / invalid: shell out to `op read <ref>`. Capture stdout, strip trailing newline, that's the value. Errors propagate.
4. Save value to cache with current timestamp.
5. Return value.

Use `op read` (not `op inject`). `op read` accepts a single ref and returns its value — exactly what we want per-ref.

## Inject parsing

Support both ref formats `op inject` accepts:

**Bare**: `op://...` sitting inline. Regex: `op://[^\s"'<>{}]+`
**Braced**: `{{ op://... }}` (with or without surrounding whitespace inside braces). Regex: `\{\{\s*(op://[^{}]+?)\s*\}\}`

Match braced first (so a `{{ op://… }}` doesn't get partially matched as bare). Substitute each match with the resolved value verbatim — no quoting, no escaping. The template author owns the surrounding syntax.

The braced form exists for cases where the surrounding format would otherwise eat or break a bare URL (JSON quotes, dotenv `=`, shell escapes). Both must work.

## CLI details

- `strongbox inject -i template.tpl` → resolved template to stdout
- `strongbox inject` (no -i) → read template from stdin, resolved to stdout
- `strongbox read op://Personal/Kagi/credential` → just the value, plus a trailing newline
- `strongbox status` → list all cached entries: ref (or sha for unknown), age, last_used age, mode, size
- `strongbox status op://...` → one entry's detail; exit 1 if not cached
- `strongbox revoke op://...` → delete that entry; exit 0 even if absent
- `strongbox revoke --all` → wipe the cache dir entirely

Output for `status`: human-readable, one entry per line, plain text (Patrick uses a screen reader sometimes — no tables, no markdown columns).

Argparse messages and stderr errors should be specific and actionable. Refusal paths in sheet.py are good models: tell the user the exact mode the file has, the exact uid that owns it, and what to do.

## Reuse guidance

These functions in `reference/sheet.py` should port near-verbatim — the security/correctness logic is what you're inheriting:

- `_find_runtime_base` → unchanged
- `_resolve_sa_cache_path` → generalize: takes a sha256 hex, returns `{base}/strongbox/{hex}.json`
- `_sa_ttl` → generalize: env var `STRONGBOX_TTL`, default 14400, same semantics
- `_ensure_cache_dir` → unchanged (mode 0700, owner check, refuse on group/other bits)
- `_atomic_write_cache` → unchanged
- `_touch_last_used` → unchanged
- `_read_sa_cache_raw` → unchanged structure (mode/uid validation, deleted-and-warn paths). Validation field set is just `{"ref", "value", "last_used"}` instead of SA's `_SA_REQUIRED_FIELDS`.
- `_load_cached_sa` → `_load_cached(ref)` — sha256 the ref, idle-TTL check, return value or None
- `_save_cached_sa` → `_save_cached(ref, value)` — sha256 the ref, write payload
- `revoke_sa_cache` → `revoke(ref=None)` — single or all
- `_inject_sa_json` → replaced by `_op_read(ref)` calling `op read <ref>` instead of `op inject -i template`
- `now_iso` / `parse_iso` → unchanged

The structural change vs sheet.py: sheet.py has one cache file at one fixed path. strongbox has many cache files, keyed by `sha256(ref)`, all sharing the same hardening rules.

## Tests

stdlib `unittest` only. No pytest. No live `op` calls — mock `subprocess.run` for op invocations.

Required coverage:

- `tests/test_cache.py`
  - read/write round-trip
  - mode 0600 enforcement (refuses 0640, deletes-and-warns)
  - owner mismatch refusal
  - atomic write (write fails partway → no torn cache file)
  - idle TTL expiry (file present but expired → returns None)
  - `last_used` is touched on read
  - malformed JSON payload → deleted and warned
  - missing required fields → deleted and warned

- `tests/test_inject.py`
  - bare ref substitution
  - braced ref substitution (with and without whitespace inside braces)
  - mixed bare + braced in same template
  - multiple refs in one template (each resolved once even if the same ref appears twice)
  - non-ref `op://` lookalikes are not matched (e.g. `https://op.example/foo`, an `op://` reference inside a markdown code fence is fine to substitute)
  - multiline templates preserved

- `tests/test_cli.py`
  - argparse: missing subcommand → exit 2 with usage
  - `strongbox read` with no ref → exit 2
  - `strongbox revoke` with no args and no `--all` → exit 2
  - `strongbox inject` with no -i and stdin tty → exit 2 (refuse to read interactive stdin) OR document and accept; pick one and be consistent
  - `op` not on PATH → SystemExit with clear message
  - `op read` returning non-zero → propagate stderr, exit non-zero

Use `tempfile.TemporaryDirectory` for the cache base in tests. Set `STRONGBOX_CACHE_DIR` to point there. Never write cache files into the user's real `$XDG_RUNTIME_DIR` from a test.

Mock `subprocess.run` with `unittest.mock.patch`. Use a stand-in `op` that returns canned stdout/stderr/returncode based on the ref passed.

All tests should pass via `python -m unittest discover tests`.

## Constraints

- **stdlib only.** No `requests`, `aiohttp`, `click`, `tomli` (use `tomllib` if you somehow add a manifest, but **do not add a manifest in v1**), `pytest`. urllib + argparse + subprocess + json + hashlib + os + sys + datetime + re + pathlib are sufficient.
- Single-file `strongbox` script, executable, `#!/usr/bin/env python3`, ~300 LOC max.
- `from __future__ import annotations` is fine if you want it (sheet.py uses it).
- No type-checking dependencies. Bare type hints in source are fine.
- No secrets, refs, test fixtures with real values, or `.env` files committed.
- No `requirements.txt` / `pyproject.toml` needed.
- `Makefile` (or `install.sh`) with an `install` target that symlinks `~/.local/bin/strongbox` → `$(pwd)/strongbox`. Don't run install yourself.

## Style

Match `reference/sheet.py` — no class hierarchies for a 300-line script, minimal scaffolding, comments only where the *why* is non-obvious. Patrick's preference: factual, no winks, no editorializing in comments or docstrings.

## Deliverables

By the time you tender:

1. `strongbox` — executable, stdlib only, the CLI
2. `tests/` — all tests passing under `python -m unittest discover tests`
3. `Makefile` (or `install.sh`) with an `install` target
4. `README.md` — usage examples for each subcommand, brief migration-from-`op-inject` section, env-var docs (`STRONGBOX_TTL`, `STRONGBOX_CACHE_DIR`)
5. Clean git history — small commits, descriptive messages

Tender the shard with a one-line summary when done.

## Out of scope (do not build)

- Manifest layer (`strongbox load <name>`, `strongbox get <name>`, manifest file). Patrick may want this in v2; explicitly skipping for v1 to avoid bikeshedding.
- Backends other than `op` (no `pass`, no `bw`, no env-var fallback).
- A daemon process. The OS already gives us tmpfs and `op` already manages its own session.
- Any feature involving network calls beyond `op read`.
