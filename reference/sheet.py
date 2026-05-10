#!/usr/bin/env python3
"""sheet — agent-first CLI for the marketing tracking Google Sheet.

Read commands and a guarded two-step write surface (stage / commit) over a
specified Google Sheet. Cells are echoed inside guillemets « » with the
target row plus three rows above and below so position is verified visually.

Auth: a Google service account key is pulled from 1Password at runtime via
`op inject`, then cached in tmpfs at $XDG_RUNTIME_DIR/sheet/sa.json (mode
0600) with a 4h idle TTL so we don't hit the 1Password prompt every command.
The cache vanishes on logout/reboot. The service account has Editor on
exactly one shared sheet, so the `spreadsheets` scope effectively means
"this one sheet" — no Drive metadata, no access to anything else.

To rotate the key: mint a new JSON key for the SA in GCP, paste into
1Password, run `sheet revoke`, delete the old key in GCP.

Run `python3 sheet.py --help` (or `make sheet ARGS="..."`) for the surface.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

DEFAULT_SHEET_ID = "1RPCTmAaHsExFmC-OdaNhJSzZqzZ773xSDUKi8723dMM"
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
SA_TEMPLATE = Path(__file__).resolve().parent / "service_account.json.tpl"
DEFAULT_SA_TTL_SECONDS = 14400  # 4 hours idle
STAGED_DIR = Path("data/staged")
SNAPSHOT_DIR = Path("data/snapshots")
EDIT_LOG = Path("data/edit_log.jsonl")
HASH_SEP = "\x1f"
DATE_RE = re.compile(r"^\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\s*$")


# ---------- auth & services -------------------------------------------------

def _find_runtime_base() -> Optional[Path]:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        p = Path(xdg)
        if p.is_dir() and os.access(p, os.W_OK):
            return p
    fallback = Path(f"/run/user/{os.geteuid()}")
    if fallback.is_dir() and os.access(fallback, os.W_OK):
        return fallback
    return None


def _resolve_sa_cache_path() -> Path:
    """Resolve the SA-key tmpfs cache path. Hard-fails if no per-user tmpfs
    base is available and no $SHEET_SA_CACHE_PATH override is set."""
    override = os.environ.get("SHEET_SA_CACHE_PATH")
    if override:
        return Path(override)
    base = _find_runtime_base()
    if base is None:
        raise SystemExit(
            "auth: cannot locate a per-user tmpfs runtime dir for the SA key cache.\n"
            "  attempted: $XDG_RUNTIME_DIR, /run/user/<uid>\n"
            "  fix: log into a graphical session (sets XDG_RUNTIME_DIR), or set\n"
            "  SHEET_SA_CACHE_PATH=<path> as an operator escape hatch."
        )
    return base / "sheet" / "sa.json"


def _sa_ttl() -> int:
    """Return idle TTL in seconds. 0 disables. Defaults to 4h."""
    raw = os.environ.get("SHEET_SA_TTL")
    if raw is None:
        return DEFAULT_SA_TTL_SECONDS
    try:
        v = int(raw)
    except ValueError:
        return DEFAULT_SA_TTL_SECONDS
    if v < 0:
        return DEFAULT_SA_TTL_SECONDS
    return v


def _ensure_cache_dir(d: Path) -> None:
    """Create dir with 0700 if missing, then validate. Refuse on group/other
    bits or wrong owner — never chmod existing dirs."""
    try:
        d.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as e:
        raise SystemExit(f"auth: cannot create SA cache dir {d}: {e}")
    try:
        st = d.stat()
    except OSError as e:
        raise SystemExit(f"auth: cannot stat SA cache dir {d}: {e}")
    if st.st_uid != os.geteuid():
        raise SystemExit(
            f"auth: SA cache dir {d} owned by uid {st.st_uid}, "
            f"not current user (uid {os.geteuid()}); refusing to use"
        )
    mode = st.st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(
            f"auth: SA cache dir {d} has mode {oct(mode)}; refusing to use.\n"
            f"  required: group/other bits unset (e.g. 0700).\n"
            f"  fix manually: chmod 700 {d}"
        )


def _atomic_write_cache(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _touch_last_used(path: Path) -> None:
    try:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        data["last_used"] = now_iso()
        try:
            _atomic_write_cache(path, data)
        except OSError:
            pass
    except Exception:
        pass


_SA_REQUIRED_FIELDS = ("client_email", "private_key", "token_uri")


def _read_sa_cache_raw(path: Path) -> Optional[dict]:
    """Return parsed cache file contents, or None if absent / unreadable /
    insecure / corrupt. Emits a stderr warning before unlinking on each
    deletion path so operators can see why the cache vanished. Does NOT
    touch last_used. Does NOT validate TTL — callers do that."""
    if not path.exists():
        return None
    _ensure_cache_dir(path.parent)
    try:
        st = path.stat()
    except OSError as e:
        print(f"warning: cannot stat SA cache at {path}: {e}", file=sys.stderr)
        return None
    mode = st.st_mode & 0o777
    if mode != 0o600:
        print(
            f"warning: SA cache at {path} has mode {oct(mode)} (expected 0600); "
            "deleting and re-fetching",
            file=sys.stderr,
        )
        try:
            path.unlink()
        except OSError:
            pass
        return None
    if st.st_uid != os.geteuid():
        print(
            f"warning: SA cache at {path} owned by uid {st.st_uid}, not "
            f"current user (uid {os.geteuid()}); deleting and re-fetching",
            file=sys.stderr,
        )
        try:
            path.unlink()
        except OSError:
            pass
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(
            f"warning: SA cache at {path} unreadable ({e}); "
            "deleting and re-fetching",
            file=sys.stderr,
        )
        try:
            path.unlink()
        except OSError:
            pass
        return None


def _load_cached_sa() -> Optional[dict]:
    path = _resolve_sa_cache_path()
    data = _read_sa_cache_raw(path)
    if data is None:
        return None
    ttl = _sa_ttl()
    if ttl > 0:
        last_used = data.get("last_used")
        if not isinstance(last_used, str):
            return None
        try:
            lu = parse_iso(last_used)
        except (ValueError, TypeError):
            return None
        idle = (dt.datetime.now(dt.timezone.utc) - lu).total_seconds()
        if idle > ttl:
            return None
    info = data.get("sa")
    if not isinstance(info, dict) or not all(f in info for f in _SA_REQUIRED_FIELDS):
        print(
            f"warning: SA cache at {path} has malformed sa payload; "
            "deleting and re-fetching",
            file=sys.stderr,
        )
        try:
            path.unlink()
        except OSError:
            pass
        return None
    _touch_last_used(path)
    return info


def _save_cached_sa(info: dict) -> None:
    missing = [f for f in _SA_REQUIRED_FIELDS if f not in info]
    if missing:
        print(
            f"warning: SA payload missing required fields {missing}; not caching",
            file=sys.stderr,
        )
        return
    path = _resolve_sa_cache_path()
    _ensure_cache_dir(path.parent)
    payload = {"sa": info, "last_used": now_iso()}
    try:
        _atomic_write_cache(path, payload)
    except OSError as e:
        print(f"warning: could not cache SA key at {path}: {e}", file=sys.stderr)


def _inject_sa_json() -> dict:
    """Pull the service-account key JSON from 1Password via `op inject`."""
    if not SA_TEMPLATE.exists():
        raise SystemExit(
            f"auth: service account template not found at {SA_TEMPLATE}.\n"
            "  expected contents: a single 1Password reference, e.g.\n"
            "    op://Employee/Marketing Sheet SA Key/credentials\n"
        )
    try:
        result = subprocess.run(
            ["op", "inject", "-i", str(SA_TEMPLATE)],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise SystemExit("auth: 'op' (1Password CLI) not found on PATH")
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip() or "(no stderr)"
        raise SystemExit(
            "auth: 'op inject' failed for service account credentials.\n"
            f"  template:  {SA_TEMPLATE}\n"
            f"  op stderr: {msg}\n"
            "  fix: ensure 1Password CLI is signed in (`op signin`) and the\n"
            "  reference in the template resolves to a JSON service-account key."
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"auth: service account JSON could not be parsed: {e}\n"
            f"  template: {SA_TEMPLATE}\n"
            "  the 1Password field should contain the full SA key JSON."
        )


def _load_sa_info() -> dict:
    """Tmpfs-cached SA JSON, falling back to op inject. The cache lives at
    $XDG_RUNTIME_DIR/sheet/sa.json (mode 0600) with idle TTL — see
    SHEET_SA_TTL (default 4h)."""
    cached = _load_cached_sa()
    if cached is not None:
        return cached
    print(
        "auth: SA-key cache miss — calling 1Password (op inject)",
        file=sys.stderr,
    )
    info = _inject_sa_json()
    _save_cached_sa(info)
    return info


def get_services():
    info = _load_sa_info()
    try:
        creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    except (ValueError, KeyError) as e:
        raise SystemExit(f"auth: service account credentials invalid: {e}")
    return build("sheets", "v4", credentials=creds, cache_discovery=False)


def revoke_sa_cache() -> tuple[list[str], list[tuple[str, str]]]:
    """Delete the tmpfs SA cache. Returns (deleted_paths, failures)."""
    deleted: list[str] = []
    failed: list[tuple[str, str]] = []
    try:
        path = _resolve_sa_cache_path()
    except SystemExit:
        return deleted, failed
    if path.exists():
        try:
            path.unlink()
            deleted.append(str(path))
        except OSError as e:
            failed.append((str(path), str(e)))
    return deleted, failed


# ---------- sheet helpers ---------------------------------------------------

def col_letter(idx_zero: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    n = idx_zero + 1
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(ord("A") + r) + s
    return s


def quote_tab(tab: str) -> str:
    return "'" + tab.replace("'", "''") + "'"


def list_tabs(sheets, sheet_id: str) -> list[dict]:
    meta = sheets.spreadsheets().get(spreadsheetId=sheet_id, includeGridData=False).execute()
    return meta.get("sheets", [])


def get_tab_meta(sheets, sheet_id: str, tab: str) -> dict:
    tabs = list_tabs(sheets, sheet_id)
    for s in tabs:
        if s["properties"]["title"] == tab:
            return s["properties"]
    titles = [s["properties"]["title"] for s in tabs]
    print(f"tab not found: {tab!r}", file=sys.stderr)
    print("available tabs:", file=sys.stderr)
    for t in titles:
        print(f"  {t}", file=sys.stderr)
    raise SystemExit(2)


def load_tab(sheets, sheet_id: str, tab: str) -> list[list[str]]:
    try:
        res = sheets.spreadsheets().values().get(
            spreadsheetId=sheet_id,
            range=f"{quote_tab(tab)}!A:ZZ",
            valueRenderOption="FORMATTED_VALUE",
        ).execute()
    except HttpError as e:
        if e.resp.status == 400:
            get_tab_meta(sheets, sheet_id, tab)
            raise
        raise
    return res.get("values", [])


def width_of(rows: list[list[str]]) -> int:
    return max((len(r) for r in rows), default=0)


def pad(row: list[str], width: int) -> list[str]:
    return list(row) + [""] * max(0, width - len(row))


def row_hash(values: list[str]) -> str:
    return hashlib.sha256(HASH_SEP.join(values).encode("utf-8")).hexdigest()


def slug_for_path(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def header_width(rows: list[list[str]]) -> int:
    if not rows:
        return 0
    return len(rows[0])


def header_padded_hash(rows: list[list[str]], r: int) -> Optional[str]:
    if not rows or r < 1 or r > len(rows):
        return None
    return row_hash(pad(rows[r - 1], header_width(rows)))


def find_anchor_matches(rows: list[list[str]], anchor_value: str) -> tuple[str, Any]:
    """('numeric', int) for numeric anchors (no range validation),
    ('content', list[int]) for content anchors (matching 1-indexed sheet rows)."""
    a = anchor_value.strip()
    if a.isdigit():
        return ("numeric", int(a))
    headers = rows[0] if rows else []
    col = resolve_deliverable_col(headers)
    matches = []
    for i, row in enumerate(rows[1:], start=2):
        if col < len(row) and a.lower() in row[col].lower():
            matches.append(i)
    return ("content", matches)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fname_iso() -> str:
    return now_iso().replace(":", "-")


# ---------- formatting ------------------------------------------------------

def _g(v: str) -> str:
    """Wrap cell in guillemets, render embedded newlines as literal \\n."""
    return "«" + v.replace("\\", "\\\\").replace("\n", "\\n") + "»"


def fmt_multi(row_num: int, values: list[str], width: int) -> str:
    cells = " | ".join(_g(v) for v in pad(values, width))
    return f"  {row_num} | {cells}"


def fmt_single(tab: str, row_num: int, headers: list[str], values: list[str], width: int) -> str:
    values = pad(values, width)
    headers = pad(headers, width)
    label_w = max((len(h) for h in headers), default=0)
    lines = [f"ROW {row_num}, tab {tab}"]
    for h, v in zip(headers, values):
        lines.append(f"    {h.ljust(label_w)} : {_g(v)}")
    return "\n".join(lines)


def fmt_context(rows: list[list[str]], target_row: int, width: int, before: int = 3, after: int = 3) -> str:
    """Show rows [target-before .. target+after] inclusive (1-indexed sheet rows),
    excluding the target itself."""
    out = []
    n = len(rows)
    for r in range(max(1, target_row - before), min(n, target_row + after) + 1):
        if r == target_row:
            continue
        out.append(fmt_multi(r, rows[r - 1], width))
    return "\n".join(out)


def fmt_diff(row_num: int, col_name: str, before: str, after: str) -> str:
    return f"  ROW {row_num}, {col_name}: {_g(before)} → {_g(after)}"


def breadcrumbs(*lines: str) -> str:
    return "\n".join(f"→ {ln}" for ln in lines)


# ---------- column resolution -----------------------------------------------

def resolve_col(headers: list[str], name: str) -> int:
    """Return zero-based column index. Accepts:
      - @LETTER  : explicit column letter (e.g. @D for the 4th column).
                   Use this when a column has an empty header.
      - #N       : explicit zero-based index (e.g. #3 for the 4th column).
      - @@foo    : literal header `@foo` (escape for headers starting with @).
      - ##foo    : literal header `#foo` (escape for headers starting with #).
      - <name>   : header name. Exact (trim+case-insensitive) match wins;
                   otherwise case-insensitive substring; ambiguous → exit 2.
    """
    name_norm = name.strip()
    # @@foo / ##foo escape: drop one prefix char, treat the rest as a literal header.
    if name_norm.startswith(("@@", "##")):
        name_norm = name_norm[1:]
    elif name_norm.startswith("@") and len(name_norm) > 1:
        letters = name_norm[1:].upper()
        if not all("A" <= ch <= "Z" for ch in letters):
            print(f"column letter must be A-Z: {name!r}", file=sys.stderr)
            raise SystemExit(2)
        idx = 0
        for ch in letters:
            idx = idx * 26 + (ord(ch) - ord("A") + 1)
        idx -= 1
        if idx >= len(headers):
            print(
                f"column letter {name!r} (index {idx}) past last column "
                f"(width {len(headers)})",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return idx
    elif name_norm.startswith("#") and len(name_norm) > 1:
        try:
            idx = int(name_norm[1:])
        except ValueError:
            print(f"column index must be a non-negative integer: {name!r}", file=sys.stderr)
            raise SystemExit(2)
        if idx < 0 or idx >= len(headers):
            print(
                f"column index {idx} out of range (0..{len(headers) - 1})",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return idx
    # exact match (trim+case-insensitive)
    exact = [i for i, h in enumerate(headers) if h.strip().lower() == name_norm.lower()]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        print(f"column ambiguous (exact): {name!r}", file=sys.stderr)
        for i in exact:
            print(f"  col {col_letter(i)}: {headers[i]!r}", file=sys.stderr)
        raise SystemExit(2)
    # substring
    sub = [i for i, h in enumerate(headers) if name_norm.lower() in h.strip().lower()]
    if len(sub) == 1:
        return sub[0]
    if len(sub) == 0:
        print(f"column not found: {name!r}", file=sys.stderr)
        print(f"available columns: {[h for h in headers]}", file=sys.stderr)
        print(
            "tip: empty-header columns can be referenced as @LETTER (e.g. @D) or #INDEX (e.g. #3)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    print(f"column ambiguous: {name!r} matches multiple", file=sys.stderr)
    for i in sub:
        print(f"  col {col_letter(i)}: {headers[i]!r}", file=sys.stderr)
    raise SystemExit(2)


def resolve_deliverable_col(headers: list[str]) -> int:
    """Find the Deliverable(s) column for `near` searches."""
    for i, h in enumerate(headers):
        if h.strip().lower() in ("deliverable", "deliverables"):
            return i
    # substring fallback
    for i, h in enumerate(headers):
        if "deliverable" in h.strip().lower():
            return i
    print("could not find a Deliverable(s) column in headers", file=sys.stderr)
    raise SystemExit(2)


def resolve_anchor(rows: list[list[str]], anchor: str, mode_label: str) -> int:
    """Anchor is either a row number or substring match against Deliverable col.
    Returns 1-indexed sheet row. Multi-match → exit non-zero with candidates."""
    a = anchor.strip()
    if a.isdigit():
        r = int(a)
        if r < 1 or r > len(rows):
            print(f"anchor row {r} out of range (sheet has {len(rows)} rows)", file=sys.stderr)
            raise SystemExit(2)
        return r
    headers = rows[0] if rows else []
    col = resolve_deliverable_col(headers)
    matches = []
    for i, row in enumerate(rows[1:], start=2):
        if col < len(row) and a.lower() in row[col].lower():
            matches.append(i)
    if not matches:
        print(f"anchor matched 0 rows: {a!r}", file=sys.stderr)
        raise SystemExit(2)
    if len(matches) > 1:
        print(f"anchor matched {len(matches)} rows: {a!r}", file=sys.stderr)
        width = width_of(rows)
        for r in matches:
            print(fmt_multi(r, rows[r - 1], width), file=sys.stderr)
        print(breadcrumbs(f"narrow with --{mode_label} <row-number>"), file=sys.stderr)
        raise SystemExit(2)
    return matches[0]


# ---------- soft warnings ---------------------------------------------------

def soft_warnings(rows: list[list[str]], col_idx: int, new_value: str) -> list[str]:
    warns: list[str] = []
    if not rows:
        return warns
    col_vals: list[str] = []
    for row in rows[1:]:
        if col_idx < len(row):
            v = row[col_idx].strip()
            if v:
                col_vals.append(v)
    if not col_vals:
        return warns
    new_norm = new_value.strip().lower()
    seen_lower = {v.lower() for v in col_vals}
    if new_norm and new_norm not in seen_lower:
        sample = sorted(set(col_vals), key=lambda s: s.lower())[:6]
        warns.append(
            f"new value {_g(new_value)} not seen elsewhere in column; existing values include: "
            + ", ".join(_g(s) for s in sample)
        )
    date_count = sum(1 for v in col_vals if DATE_RE.match(v))
    if date_count >= max(3, int(len(col_vals) * 0.5)):
        if new_value.strip() and not DATE_RE.match(new_value.strip()):
            warns.append(
                f"column looks date-shaped ({date_count}/{len(col_vals)} cells parse as M/D/Y); "
                f"new value {_g(new_value)} does not"
            )
    return warns


# ---------- snapshot --------------------------------------------------------

def snapshot_tab(sheets, sheet_id: str, tab: str) -> Path:
    rows = load_tab(sheets, sheet_id, tab)
    width = width_of(rows)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    path = SNAPSHOT_DIR / f"{slug_for_path(tab)}_{fname_iso()}.tsv"
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(c.replace("\t", " ").replace("\n", "\\n") for c in pad(row, width)) + "\n")
    return path


# ---------- staged record ---------------------------------------------------

def new_staged_id() -> str:
    while True:
        sid = "s_" + os.urandom(3).hex()
        if not (STAGED_DIR / f"{sid}.json").exists():
            return sid


def staged_path(sid: str) -> Path:
    return STAGED_DIR / f"{sid}.json"


def write_staged(record: dict) -> None:
    STAGED_DIR.mkdir(parents=True, exist_ok=True)
    staged_path(record["staged_id"]).write_text(json.dumps(record, indent=2))


def read_staged(sid: str) -> dict:
    p = staged_path(sid)
    if not p.exists():
        print(f"no staged record: {sid}", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(p.read_text())


def stage_ttl_seconds() -> int:
    try:
        return int(os.environ.get("SHEET_STAGE_TTL", "1800"))
    except ValueError:
        return 1800


def parse_iso(s: str) -> dt.datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return dt.datetime.fromisoformat(s)


# ---------- commands --------------------------------------------------------

def cmd_tabs(args, sheets) -> int:
    for s in list_tabs(sheets, args.sheet_id):
        print(s["properties"]["title"])
    return 0


def cmd_show(args, sheets) -> int:
    rows = load_tab(sheets, args.sheet_id, args.tab)
    if not rows:
        print(f"tab {args.tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)
    if args.row < 1 or args.row > len(rows):
        print(f"row {args.row} out of range (tab has {len(rows)} rows)", file=sys.stderr)
        return 2
    values = pad(rows[args.row - 1], width)
    print(fmt_single(args.tab, args.row, headers, values, width))
    ctx = fmt_context(rows, args.row, width)
    if ctx:
        print()
        print(ctx)
    print()
    print(breadcrumbs(
        f"edit: sheet stage edit {quote_tab(args.tab)} {args.row} --col <name> --value <value>",
        f"insert below: sheet stage insert {quote_tab(args.tab)} --below {args.row} --col-vals key=val ...",
    ))
    return 0


def cmd_near(args, sheets) -> int:
    rows = load_tab(sheets, args.sheet_id, args.tab)
    if not rows:
        print(f"tab {args.tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)
    col = resolve_deliverable_col(headers)
    q = args.query.lower()
    matches = []
    for i, row in enumerate(rows[1:], start=2):
        if col < len(row) and q in row[col].lower():
            matches.append(i)
    if args.limit:
        matches = matches[: args.limit]
    if not matches:
        print(f"no rows in tab {args.tab!r} match {args.query!r}")
        return 0
    ranges: list[list[int]] = []
    for r in sorted(matches):
        lo = max(2, r - 3)
        hi = min(len(rows), r + 3)
        if ranges and lo <= ranges[-1][1] + 1:
            ranges[-1][1] = max(ranges[-1][1], hi)
        else:
            ranges.append([lo, hi])
    blocks = []
    for lo, hi in ranges:
        block = [fmt_multi(rr, rows[rr - 1], width) for rr in range(lo, hi + 1)]
        blocks.append("\n".join(block))
    print("\n\n".join(blocks))
    print()
    print(breadcrumbs(
        f"detail: sheet show {quote_tab(args.tab)} <row>",
        f"edit: sheet stage edit {quote_tab(args.tab)} <row> --col <name> --value <value>",
    ))
    return 0


def cmd_list(args, sheets) -> int:
    rows = load_tab(sheets, args.sheet_id, args.tab)
    if not rows:
        print(f"tab {args.tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)
    limit = args.limit if args.limit is not None else 50
    col_idx = None
    if args.col:
        col_idx = resolve_col(headers, args.col)
    needle = (args.value or "").lower()
    out_rows = []
    for i, row in enumerate(rows[1:], start=2):
        if col_idx is not None:
            cell = row[col_idx] if col_idx < len(row) else ""
            if needle and needle not in cell.lower():
                continue
            if not needle and not cell.strip():
                continue
        out_rows.append(i)
        if limit and len(out_rows) >= limit:
            break
    if not out_rows:
        print(f"no rows match in tab {args.tab!r}")
        return 0
    for r in out_rows:
        print(fmt_multi(r, rows[r - 1], width))
    print()
    print(breadcrumbs(
        f"detail: sheet show {quote_tab(args.tab)} <row>",
    ))
    return 0


# ---- staging ---------------------------------------------------------------

def cmd_stage_edit(args, sheets) -> int:
    rows = load_tab(sheets, args.sheet_id, args.tab)
    if not rows:
        print(f"tab {args.tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)
    if args.row < 2 or args.row > len(rows):
        print(f"row {args.row} out of range (data rows are 2..{len(rows)})", file=sys.stderr)
        return 2
    col_idx = resolve_col(headers, args.col)
    col_name = headers[col_idx]
    cur = pad(rows[args.row - 1], width)
    before = cur[col_idx]
    after = args.value
    if before == after:
        print(f"note: new value equals current value for {col_name}; staging anyway")
    h = header_padded_hash(rows, args.row)
    sid = new_staged_id()
    created = dt.datetime.now(dt.timezone.utc)
    expires = created + dt.timedelta(seconds=stage_ttl_seconds())
    record = {
        "staged_id": sid,
        "kind": "edit",
        "tab": args.tab,
        "row": args.row,
        "col": col_name,
        "col_index": col_idx,
        "before_value": before,
        "new_value": after,
        "row_hash": h,
        "width_basis": "header",
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": args.note or "",
        "sheet_id": args.sheet_id,
    }
    write_staged(record)
    print(fmt_single(args.tab, args.row, headers, cur, width))
    print()
    print("DIFF")
    print(fmt_diff(args.row, col_name, before, after))
    print()
    print("CONTEXT")
    ctx = fmt_context(rows, args.row, width)
    if ctx:
        print(ctx)
    print()
    print(f"staged-id: {sid}")
    warns = soft_warnings(rows, col_idx, after)
    if warns:
        print()
        print("WARNINGS (non-blocking)")
        for w in warns:
            print(f"  ! {w}")
    print()
    print(breadcrumbs(
        f"commit: sheet commit {sid}",
        f"drop: sheet stage drop {sid}",
        f"verify: sheet show {quote_tab(args.tab)} {args.row}",
    ))
    return 0


def cmd_stage_insert(args, sheets) -> int:
    rows = load_tab(sheets, args.sheet_id, args.tab)
    if not rows:
        print(f"tab {args.tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)

    if sum(x is not None for x in (args.above, args.below, args.at_row)) != 1:
        print("specify exactly one of --above / --below / --at-row", file=sys.stderr)
        return 2

    if args.at_row is not None:
        target_row = args.at_row
        anchor_mode = "at-row"
        anchor_value = str(args.at_row)
        anchor_resolved = args.at_row
        if target_row < 2 or target_row > len(rows) + 1:
            print(f"--at-row {target_row} out of range (data rows are 2..{len(rows) + 1})", file=sys.stderr)
            return 2
    elif args.above is not None:
        anchor_resolved = resolve_anchor(rows, args.above, "above")
        target_row = anchor_resolved
        anchor_mode = "above"
        anchor_value = args.above
    else:
        anchor_resolved = resolve_anchor(rows, args.below, "below")
        target_row = anchor_resolved + 1
        anchor_mode = "below"
        anchor_value = args.below

    new_row_values = [""] * width
    parsed: dict[str, str] = {}
    for kv in args.col_vals or []:
        if "=" not in kv:
            print(f"--col-vals expects name=value, got {kv!r}", file=sys.stderr)
            return 2
        k, v = kv.split("=", 1)
        ci = resolve_col(headers, k)
        new_row_values[ci] = v
        parsed[headers[ci]] = v

    anchor_hash = header_padded_hash(rows, anchor_resolved)
    above_hash = header_padded_hash(rows, anchor_resolved - 1)
    below_hash = header_padded_hash(rows, anchor_resolved + 1)

    sid = new_staged_id()
    created = dt.datetime.now(dt.timezone.utc)
    expires = created + dt.timedelta(seconds=stage_ttl_seconds())
    record = {
        "staged_id": sid,
        "kind": "insert",
        "tab": args.tab,
        "row": target_row,
        "anchor": {
            "mode": anchor_mode,
            "value": anchor_value,
            "resolved_row": anchor_resolved,
            "anchor_hash": anchor_hash,
            "above_hash": above_hash,
            "below_hash": below_hash,
        },
        "width_basis": "header",
        "row_values": new_row_values,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": args.note or "",
        "sheet_id": args.sheet_id,
    }
    write_staged(record)

    if anchor_mode != "at-row":
        print(f"ANCHOR (resolved {anchor_mode} row {anchor_resolved})")
        print(fmt_single(args.tab, anchor_resolved, headers, pad(rows[anchor_resolved - 1], width), width))
        print()
    print(f"NEW ROW (would land at row {target_row})")
    print(fmt_single(args.tab, target_row, headers, new_row_values, width))
    print()
    print("CONTEXT (current rows that will surround the insert)")
    above_lo = max(2, target_row - 3)
    above_hi = min(len(rows), target_row - 1)
    for r in range(above_lo, above_hi + 1):
        print(fmt_multi(r, rows[r - 1], width))
    below_lo = target_row
    below_hi = min(len(rows), target_row + 2)
    for r in range(below_lo, below_hi + 1):
        print(fmt_multi(r, rows[r - 1], width))
    print()
    print(f"staged-id: {sid}")
    print()
    print(breadcrumbs(
        f"commit: sheet commit {sid}",
        f"drop: sheet stage drop {sid}",
    ))
    return 0


def cmd_stage_list(args, sheets) -> int:
    if not STAGED_DIR.exists():
        return 0
    files = sorted(STAGED_DIR.glob("s_*.json"))
    if not files:
        return 0
    for f in files:
        rec = json.loads(f.read_text())
        kind = rec.get("kind", "?")
        tab = rec.get("tab", "?")
        row = rec.get("row", "?")
        if kind == "edit":
            tail = f"{rec.get('col')}: {_g(rec.get('before_value', ''))} → {_g(rec.get('new_value', ''))}"
        else:
            tail = f"insert (anchor: {rec.get('anchor', {}).get('mode')} {rec.get('anchor', {}).get('value')})"
        print(f"{rec['staged_id']} {kind} {tab!r} row {row} | {tail} | expires {rec.get('expires_at')}")
    return 0


def cmd_stage_drop(args, sheets) -> int:
    p = staged_path(args.staged_id)
    if not p.exists():
        print(f"no staged record: {args.staged_id}", file=sys.stderr)
        return 2
    p.unlink()
    print(f"dropped {args.staged_id}")
    return 0


# ---- commit ----------------------------------------------------------------

def append_log(entry: dict) -> None:
    EDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())


def cmd_commit(args, sheets) -> int:
    rec = read_staged(args.staged_id)
    sheet_id = rec.get("sheet_id", args.sheet_id)
    tab = rec["tab"]

    expires_at = parse_iso(rec["expires_at"])
    now = dt.datetime.now(dt.timezone.utc)
    if now > expires_at and not args.force:
        print(
            f"staged record expired at {rec['expires_at']} (now {now_iso()}); "
            f"re-stage or pass --force",
            file=sys.stderr,
        )
        return 2

    rows = load_tab(sheets, sheet_id, tab)
    if not rows:
        print(f"tab {tab!r} is empty", file=sys.stderr)
        return 2
    width = width_of(rows)
    headers = pad(rows[0], width)
    tab_meta = get_tab_meta(sheets, sheet_id, tab)
    sheet_inner_id = tab_meta["sheetId"]

    if rec["kind"] == "edit":
        row_num = rec["row"]
        if row_num < 2 or row_num > len(rows):
            print(f"row {row_num} out of range now (rows={len(rows)})", file=sys.stderr)
            return 2
        live_row = pad(rows[row_num - 1], width)
        live_hash = header_padded_hash(rows, row_num)
        if live_hash != rec["row_hash"] and not args.force:
            print("ROW DRIFTED since stage. Refusing to commit (use --force to override).")
            print()
            print("LIVE")
            print(fmt_multi(row_num, live_row, width))
            print()
            print(f"STAGED before-state hash: {rec['row_hash'][:12]}…")
            print(f"LIVE hash:                {live_hash[:12]}…")
            col_idx = rec["col_index"]
            if col_idx < len(live_row):
                print()
                print(
                    f"  col {headers[col_idx]!r}: live={_g(live_row[col_idx])} "
                    f"staged-before={_g(rec['before_value'])} new={_g(rec['new_value'])}"
                )
            print()
            print(breadcrumbs(
                f"re-stage: sheet stage edit {quote_tab(tab)} {row_num} --col {rec['col']!r} --value {rec['new_value']!r}",
                "force commit (overrides drift): sheet commit "
                f"{rec['staged_id']} --force",
            ))
            return 3

        if args.dry_run:
            print(f"dry-run: would write {_g(rec['new_value'])} to "
                  f"{tab}!{col_letter(rec['col_index'])}{row_num}")
            return 0

        snap = snapshot_tab(sheets, sheet_id, tab)
        before = {rec["col"]: rec["before_value"]}
        target_range = f"{quote_tab(tab)}!{col_letter(rec['col_index'])}{row_num}"
        try:
            sheets.spreadsheets().values().update(
                spreadsheetId=sheet_id,
                range=target_range,
                valueInputOption="RAW",
                body={"values": [[rec["new_value"]]]},
            ).execute()
        except HttpError as e:
            print(f"write failed: {e}", file=sys.stderr)
            print("re-reading to report actual state...", file=sys.stderr)
            try:
                rows2 = load_tab(sheets, sheet_id, tab)
                print(fmt_multi(row_num, pad(rows2[row_num - 1], width_of(rows2)), width_of(rows2)))
            except Exception:
                pass
            return 4

        rows2 = load_tab(sheets, sheet_id, tab)
        width2 = width_of(rows2)
        new_row = pad(rows2[row_num - 1], width2)
        after = {rec["col"]: new_row[rec["col_index"]] if rec["col_index"] < len(new_row) else ""}
        append_log({
            "committed_at": now_iso(),
            "staged_id": rec["staged_id"],
            "kind": "edit",
            "tab": tab,
            "row": row_num,
            "before": before,
            "after": after,
            "snapshot_path": str(snap),
        })
        staged_path(rec["staged_id"]).unlink(missing_ok=True)

        print(f"committed {rec['staged_id']}")
        print()
        print(fmt_single(tab, row_num, pad(rows2[0], width2), new_row, width2))
        print()
        ctx = fmt_context(rows2, row_num, width2)
        if ctx:
            print(ctx)
        print()
        print(f"snapshot: {snap}")
        print()
        print(breadcrumbs(f"verify: sheet show {quote_tab(tab)} {row_num}"))
        return 0

    # ---- insert ----
    target_row = rec["row"]
    if target_row < 2 or target_row > len(rows) + 1:
        print(f"insert target row {target_row} out of range (rows={len(rows)})", file=sys.stderr)
        return 2

    # Stale check: re-resolve anchor and compare hashes.
    anchor_info = rec.get("anchor", {}) or {}
    anchor_mode = anchor_info.get("mode")
    anchor_value = anchor_info.get("value", "")
    staged_anchor_row = anchor_info.get("resolved_row")
    staged_anchor_hash = anchor_info.get("anchor_hash")
    staged_above_hash = anchor_info.get("above_hash")
    staged_below_hash = anchor_info.get("below_hash")

    new_anchor_row: Optional[int] = None
    drift_reason = ""
    if anchor_mode == "at-row":
        new_anchor_row = staged_anchor_row
    elif anchor_mode in ("above", "below"):
        kind, val = find_anchor_matches(rows, anchor_value)
        if kind == "numeric":
            new_anchor_row = val
            if new_anchor_row < 1 or new_anchor_row > len(rows):
                drift_reason = f"anchor row {new_anchor_row} out of range"
                new_anchor_row = None
        else:
            if len(val) == 0:
                drift_reason = f"anchor content {anchor_value!r} no longer matches any row"
            elif len(val) > 1:
                drift_reason = (
                    f"anchor content {anchor_value!r} now matches {len(val)} rows: {val}"
                )
            else:
                new_anchor_row = val[0]
    else:
        new_anchor_row = staged_anchor_row

    if new_anchor_row is not None:
        new_anchor_hash = header_padded_hash(rows, new_anchor_row)
        new_above_hash = header_padded_hash(rows, new_anchor_row - 1)
        new_below_hash = header_padded_hash(rows, new_anchor_row + 1)
        if new_anchor_row != staged_anchor_row:
            drift_reason = (
                f"anchor moved from row {staged_anchor_row} to row {new_anchor_row}"
            )
        elif new_anchor_hash != staged_anchor_hash:
            drift_reason = f"anchor row {new_anchor_row} content changed"
        elif new_above_hash != staged_above_hash:
            drift_reason = f"row above anchor (row {new_anchor_row - 1}) changed"
        elif new_below_hash != staged_below_hash:
            drift_reason = f"row below anchor (row {new_anchor_row + 1}) changed"

    if drift_reason and not args.force:
        def _fmt_hash(h: Optional[str]) -> str:
            return f"{h[:12]}…" if h else "(none)"

        live_anchor_hash = header_padded_hash(rows, new_anchor_row) if new_anchor_row else None
        live_above_hash = header_padded_hash(rows, new_anchor_row - 1) if new_anchor_row else None
        live_below_hash = header_padded_hash(rows, new_anchor_row + 1) if new_anchor_row else None

        print("ANCHOR DRIFTED since stage. Refusing to commit (use --force to override).")
        print()
        print(f"reason: {drift_reason}")
        print()
        if new_anchor_row is not None and 1 <= new_anchor_row <= len(rows):
            print("LIVE ANCHOR")
            print(fmt_multi(new_anchor_row, pad(rows[new_anchor_row - 1], width), width))
            print()
        print(f"STAGED anchor row:    {staged_anchor_row}")
        print(f"LIVE anchor row:      {new_anchor_row if new_anchor_row is not None else '(unresolved)'}")
        print(f"STAGED anchor hash:   {_fmt_hash(staged_anchor_hash)}")
        print(f"LIVE anchor hash:     {_fmt_hash(live_anchor_hash)}")
        print(f"STAGED above hash:    {_fmt_hash(staged_above_hash)}")
        print(f"LIVE above hash:      {_fmt_hash(live_above_hash)}")
        print(f"STAGED below hash:    {_fmt_hash(staged_below_hash)}")
        print(f"LIVE below hash:      {_fmt_hash(live_below_hash)}")
        print()
        print(breadcrumbs(
            f"re-stage: sheet stage insert {quote_tab(tab)} --{anchor_mode} {anchor_value!r} ...",
            "force commit (overrides drift): sheet commit "
            f"{rec['staged_id']} --force",
        ))
        return 3

    if args.dry_run:
        print(f"dry-run: would insert blank row at {tab}!row {target_row} and write values")
        return 0

    snap = snapshot_tab(sheets, sheet_id, tab)

    # 1) insert blank dimension
    try:
        sheets.spreadsheets().batchUpdate(
            spreadsheetId=sheet_id,
            body={
                "requests": [
                    {
                        "insertDimension": {
                            "range": {
                                "sheetId": sheet_inner_id,
                                "dimension": "ROWS",
                                "startIndex": target_row - 1,
                                "endIndex": target_row,
                            },
                            "inheritFromBefore": False,
                        }
                    }
                ]
            },
        ).execute()
    except HttpError as e:
        print(f"insert failed: {e}", file=sys.stderr)
        return 4

    # 2) write values into the new row
    new_vals = rec["row_values"]
    end_col = col_letter(max(0, len(new_vals) - 1))
    try:
        sheets.spreadsheets().values().update(
            spreadsheetId=sheet_id,
            range=f"{quote_tab(tab)}!A{target_row}:{end_col}{target_row}",
            valueInputOption="RAW",
            body={"values": [new_vals]},
        ).execute()
    except HttpError as e:
        err_msg = str(e)
        print(f"value write failed (row was inserted but is blank): {err_msg}", file=sys.stderr)
        try:
            rows_post = load_tab(sheets, sheet_id, tab)
        except Exception:
            rows_post = []
        if rows_post and 1 <= target_row <= len(rows_post):
            width_post = width_of(rows_post)
            headers_post = pad(rows_post[0], width_post)
            blank_row = pad(rows_post[target_row - 1], width_post)
            print(file=sys.stderr)
            print(fmt_single(tab, target_row, headers_post, blank_row, width_post), file=sys.stderr)
            print(file=sys.stderr)
            for r in range(max(2, target_row - 3), min(len(rows_post), target_row + 3) + 1):
                if r == target_row:
                    continue
                print(fmt_multi(r, rows_post[r - 1], width_post), file=sys.stderr)
        append_log({
            "committed_at": now_iso(),
            "staged_id": rec["staged_id"],
            "kind": "insert_partial",
            "tab": tab,
            "row": target_row,
            "row_values": new_vals,
            "error": err_msg,
            "snapshot_path": str(snap),
        })
        staged_path(rec["staged_id"]).unlink(missing_ok=True)
        print(file=sys.stderr)
        intended = [f"  {headers[i] if i < len(headers) else col_letter(i)}: {_g(v)}"
                    for i, v in enumerate(new_vals) if v]
        breadcrumb_lines = [
            f"a blank row was inserted at {tab} row {target_row}; values were not written",
            "intended values:",
            *intended,
            f"staged record {rec['staged_id']} has been removed (re-running commit will not double-insert)",
            "fix manually in the sheet UI, or re-stage the insert",
        ]
        print(breadcrumbs(*breadcrumb_lines), file=sys.stderr)
        return 4

    rows2 = load_tab(sheets, sheet_id, tab)
    width2 = width_of(rows2)
    new_row = pad(rows2[target_row - 1], width2)
    headers2 = pad(rows2[0], width2)
    append_log({
        "committed_at": now_iso(),
        "staged_id": rec["staged_id"],
        "kind": "insert",
        "tab": tab,
        "row": target_row,
        "before": {},
        "after": dict(zip(headers2, new_row)),
        "snapshot_path": str(snap),
    })
    staged_path(rec["staged_id"]).unlink(missing_ok=True)

    print(f"committed {rec['staged_id']}")
    print()
    print(fmt_single(tab, target_row, headers2, new_row, width2))
    print()
    ctx = fmt_context(rows2, target_row, width2)
    if ctx:
        print(ctx)
    print()
    print(f"snapshot: {snap}")
    print()
    print(breadcrumbs(f"verify: sheet show {quote_tab(tab)} {target_row}"))
    return 0


# ---- log & snapshot --------------------------------------------------------

def cmd_log(args, sheets) -> int:
    if not EDIT_LOG.exists():
        print("no edit log yet")
        return 0
    lines = EDIT_LOG.read_text().splitlines()
    if args.limit:
        lines = lines[-args.limit:]
    for ln in lines:
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        kind = e.get("kind")
        if kind == "edit":
            ((col, after_v),) = e["after"].items() if e.get("after") else (("?", "?"),)
            before_v = next(iter(e.get("before", {}).values()), "")
            print(
                f"{e['committed_at']}  {e['staged_id']}  edit  {e['tab']!r} "
                f"row {e['row']}  {col}: {_g(before_v)} → {_g(after_v)}"
            )
        elif kind == "insert_partial":
            print(
                f"{e['committed_at']}  {e['staged_id']}  insert_partial  {e['tab']!r} "
                f"row {e['row']} (blank row inserted, values not written)"
            )
        else:
            print(
                f"{e['committed_at']}  {e['staged_id']}  insert  {e['tab']!r} row {e['row']}"
            )
    return 0


def cmd_snapshot(args, sheets) -> int:
    p = snapshot_tab(sheets, args.sheet_id, args.tab)
    print(f"snapshot: {p}")
    return 0


# ---- auth introspection ---------------------------------------------------

def cmd_whoami(args) -> int:
    """Show the SA identity from the tmpfs cache plus cache state. Pure
    introspection: does not refresh the cache, does not call 1Password.
    On an empty cache, prints a hint and exits 0 — run any other sheet
    command to populate."""
    print("auth: service account")
    print(f"  template:       {SA_TEMPLATE}")
    try:
        cache_path = _resolve_sa_cache_path()
    except SystemExit:
        print("  cache:          (no tmpfs base; SA never cached on this host)")
        return 0

    try:
        raw = _read_sa_cache_raw(cache_path)
    except SystemExit as e:
        print(f"  cache:          {cache_path} (cannot read — see error)")
        print(f"  error:          {e}")
        return 0
    if raw is None:
        print(f"  cache:          {cache_path} (empty)")
        print("  hint:           run any other sheet command (e.g. `sheet tabs`) to populate")
        return 0

    info = raw.get("sa") if isinstance(raw.get("sa"), dict) else None
    last_used_str = raw.get("last_used") if isinstance(raw.get("last_used"), str) else None

    if info is None:
        print(f"  cache:          {cache_path} (present but malformed — will refresh next call)")
        return 0

    pkid = info.get("private_key_id", "") or ""
    print(f"  client_email:   {info.get('client_email', '(missing)')}")
    print(f"  project_id:     {info.get('project_id', '(missing)')}")
    print(f"  private_key_id: ...{pkid[-8:] if pkid else '(missing)'}")
    print(f"  scopes:         {' '.join(SCOPES)}")
    print("  validity:       requires API call to verify (key may be revoked in GCP)")
    print(f"  cache:          {cache_path}")
    try:
        st = cache_path.stat()
        print(f"  cache mode:     {oct(st.st_mode & 0o777)}")
    except OSError:
        pass
    if last_used_str:
        try:
            lu = parse_iso(last_used_str)
            age = (dt.datetime.now(dt.timezone.utc) - lu).total_seconds()
            print(f"  cache age:      {age:.0f}s ({age / 3600:.2f}h)")
        except (ValueError, TypeError):
            print("  cache age:      (unparseable last_used)")
    else:
        print("  cache age:      (missing last_used)")
    ttl = _sa_ttl()
    if ttl == 0:
        print("  cache ttl:      0 (idle expiry disabled)")
    else:
        print(f"  cache ttl:      {ttl}s ({ttl / 3600:.2f}h)")
    return 0


def cmd_revoke(args) -> int:
    deleted, failed = revoke_sa_cache()
    if failed:
        for p, err in failed:
            print(f"failed to delete {p}: {err}", file=sys.stderr)
        return 1
    if not deleted:
        print("no cache present")
        return 0
    for d in deleted:
        print(f"deleted {d}")
    return 0


# ---------- argparse --------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sheet",
        description=(
            "Agent-first CLI for the marketing tracking Google Sheet. "
            "Reads echo target row plus 3 above/below in « » guillemets. Writes "
            "are two-step (stage → commit) with a stale-check at commit time. "
            "Auth is a Google service account key pulled from 1Password via "
            "`op inject` at runtime (no key on disk, no browser flow). The SA "
            "has Editor on exactly the configured sheet — its scope is "
            "effectively that one document."
        ),
        epilog=(
            "Environment variables:\n"
            "  SHEET_ID             default sheet id (CLI --sheet-id wins over env)\n"
            "  SHEET_STAGE_TTL      staged write expiry seconds (default 1800)\n"
            "  SHEET_SA_TTL         SA-key tmpfs cache idle TTL seconds (default 14400; 0 disables)\n"
            "  SHEET_SA_CACHE_PATH  override SA cache path (operator escape hatch; primary\n"
            "                       lives at $XDG_RUNTIME_DIR/sheet/sa.json)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--sheet-id",
        default=os.environ.get("SHEET_ID", DEFAULT_SHEET_ID),
        help="override default sheet id (env: SHEET_ID)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("tabs", help="list tab names")
    sp.set_defaults(func=cmd_tabs)

    sp = sub.add_parser("show", help="show a single row plus 3 above/below")
    sp.add_argument("tab")
    sp.add_argument("row", type=int)
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("near", help="substring search against the Deliverable column")
    sp.add_argument("tab")
    sp.add_argument("query")
    sp.add_argument(
        "--limit",
        type=int,
        default=0,
        help="cap matches considered (0 = unlimited, default); merged "
        "context blocks may still include neighboring rows",
    )
    sp.set_defaults(func=cmd_near)

    sp = sub.add_parser("list", help="filter rows by column substring")
    sp.add_argument("tab")
    sp.add_argument("--col")
    sp.add_argument("--value")
    sp.add_argument("--limit", type=int, default=50, help="0 = unlimited")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("stage", help="stage an edit or insert (two-step write)")
    ssub = sp.add_subparsers(dest="stage_cmd", required=True)

    se = ssub.add_parser("edit", help="stage a single-cell edit")
    se.add_argument("tab")
    se.add_argument("row", type=int)
    se.add_argument("--col", required=True)
    se.add_argument("--value", required=True)
    se.add_argument("--note")
    se.set_defaults(func=cmd_stage_edit)

    si = ssub.add_parser("insert", help="stage a new row")
    si.add_argument("tab")
    si.add_argument("--above")
    si.add_argument("--below")
    si.add_argument("--at-row", type=int)
    si.add_argument("--col-vals", nargs="*", help="name=value pairs for the new row")
    si.add_argument("--note")
    si.set_defaults(func=cmd_stage_insert)

    sl = ssub.add_parser("list", help="list active staged operations")
    sl.set_defaults(func=cmd_stage_list)

    sd = ssub.add_parser("drop", help="drop a staged record")
    sd.add_argument("staged_id")
    sd.set_defaults(func=cmd_stage_drop)

    sp = sub.add_parser("commit", help="commit a staged operation (with stale-check)")
    sp.add_argument("staged_id")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true", help="override drift / expiry")
    sp.set_defaults(func=cmd_commit)

    sp = sub.add_parser("log", help="tail edit log")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(func=cmd_log)

    sp = sub.add_parser("snapshot", help="manual snapshot of a tab")
    sp.add_argument("tab")
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser(
        "whoami",
        help="show SA email, project, key id, scopes, cache state",
    )
    sp.set_defaults(func=cmd_whoami)

    sp = sub.add_parser("revoke", help="delete the tmpfs SA-key cache")
    sp.set_defaults(func=cmd_revoke)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd in ("whoami", "revoke"):
        return args.func(args)
    sheets = get_services()
    try:
        return args.func(args, sheets)
    except HttpError as e:
        print(f"google api error: {e}", file=sys.stderr)
        if "403" in str(e):
            print(
                "  • check that the sheet is shared with the SA email "
                "(see `sheet whoami`) as Editor",
                file=sys.stderr,
            )
            print("  • check that Sheets API is enabled in the GCP project", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())
