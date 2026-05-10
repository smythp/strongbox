# strongbox

`strongbox` exists for a specific failure mode: 1Password CLI prompts on every shell invocation, which makes per-tool-call shell spawns impractical when each call surfaces a biometric or desktop modal. It sits between tools and `op`, fronting `op read` with a tmpfs cache so each secret resolves once per idle window instead of once per subprocess.

## Install

Requirements:

- `op` (1Password CLI 2.x) available on `PATH`
- Python 3.11+ available on `PATH` (`strongbox` uses `tomllib`)

Clone the repository and install the shim into `~/.local/bin`:

```sh
git clone https://github.com/smythp/strongbox.git
cd strongbox
make install
```

Confirm the command is available:

```sh
strongbox --help
```

## Usage

Resolve a template file to stdout:

```sh
strongbox inject -i template.tpl
```

Resolve a template from stdin:

```sh
cat template.tpl | strongbox inject
```

Read one secret value:

```sh
strongbox read op://Personal/Kagi/credential
strongbox read kagi
```

Load one or more manifest-backed secrets into the shell:

```sh
eval "$(strongbox load kagi github_token)"
```

List manifest entries:

```sh
strongbox manifest
```

Show all cached entries or one entry:

```sh
strongbox status
strongbox status op://Personal/Kagi/credential
```

Delete one cached entry or wipe the cache:

```sh
strongbox revoke op://Personal/Kagi/credential
strongbox revoke --all
```

## Migration

If a tool currently runs `op inject -i template.tpl`, replace `op` with `strongbox`:

```sh
strongbox inject -i template.tpl
```

`strongbox` resolves each distinct `op://...` reference with `op read` once, then serves later reads from cache until the entry goes idle past its TTL.

## Manifest

Strongbox can map logical names to 1Password references via a manifest file at
`$XDG_CONFIG_HOME/strongbox/manifest.toml` (default `~/.config/strongbox/manifest.toml`).
Set `STRONGBOX_MANIFEST` to override the path.

Schema:

```toml
[keys.kagi]
ref = "op://Private/kagi.com/api_key"
env = "KAGI_KEY"

[keys.github_token]
ref = "op://Personal/GitHub PAT/credential"
```

Rules:

- `strongbox read NAME` resolves `NAME` through the manifest, while `strongbox read op://...` keeps the direct-ref behavior unchanged.
- `strongbox load NAME [NAME ...]` prints eval-able `export ...` lines in input order.
- `strongbox manifest` prints one entry per line as `NAME → REF` and adds `→ ENV` only when `env` is overridden.
- Missing manifest files are treated as empty for listing, and named lookups fail with a clear error.

## Walkthrough

Assume 1Password has an item in the `Private` vault with a concealed field holding an API key:

```text
Vault: Private
Item: Kagi
Field: credential
Reference: op://Private/Kagi/credential
```

Map that reference to a logical name in `~/.config/strongbox/manifest.toml`:

```toml
[keys.kagi]
ref = "op://Private/Kagi/credential"
env = "KAGI_API_KEY"
```

Load it into the current shell:

```sh
eval "$(strongbox load kagi)"
```

A downstream tool can then consume the exported variable normally:

```sh
env | grep '^KAGI_API_KEY='
curl -H "Authorization: Bearer $KAGI_API_KEY" https://example.invalid/api
```

On the first lookup across all shells after the cache has gone idle, `strongbox` calls `op read`, 1Password prompts once, and the resolved secret is written to tmpfs. Later lookups in the same shell or sibling shells hit the shared cache silently until the entry sits unused past its idle TTL.

## How It Works

- Resolution path: tools call `strongbox read REF`, strongbox checks `$XDG_RUNTIME_DIR/strongbox/<sha256-of-ref>.json`, returns the cached value on hit, or shells out to `op read REF`, caches the result, and returns it on miss.
- TTL is idle-based, not age-based: `last_used` is refreshed on every successful read, and expiry only happens after `STRONGBOX_TTL` seconds without use. The default is `14400` seconds (4 hours).
- The cache lives in tmpfs, typically under `$XDG_RUNTIME_DIR` or `/run/user/<uid>`, so entries are RAM-backed and disappear on logout or reboot.
- Each secret reference gets one cache file keyed by `sha256(ref)`, which means separate tools requesting the same ref share the same cache entry.
- `strongbox inject -i template.tpl` resolves each distinct ref once per render, even if the same `op://...` token appears multiple times in the template.

## Security Model

- Cache directories are created with mode `0700`. Strongbox refuses to use a cache directory if group or other permission bits are set.
- Cache files are written with mode `0600`, checked for ownership (`st_uid == geteuid()`), and replaced atomically with `os.replace()`.
- If a cache entry fails the mode, ownership, or structural checks, strongbox deletes it, prints a warning to stderr, and re-fetches the secret.
- The default cache path is tmpfs-backed, so plaintext secrets stay in RAM and do not persist across logout or reboot.
- This does not protect against same-UID attackers. Any process already running as your user can read the cache files. On multi-user systems, use separate accounts.
- This does not protect against privileged access. If an attacker can escalate to `root`, strongbox does not change that threat model.
- `STRONGBOX_OP_TIMEOUT` bounds `op read` subprocesses so a stuck biometric or desktop prompt does not hang forever. The default is `60` seconds; set `0` to disable the timeout.

## Environment

- `STRONGBOX_TTL`: idle TTL in seconds. Default `14400`. Set `0` to disable expiry.
- `STRONGBOX_CACHE_DIR`: override the cache directory. By default strongbox uses `$XDG_RUNTIME_DIR/strongbox` or `/run/user/<uid>/strongbox`.
- `STRONGBOX_OP_TIMEOUT`: timeout in seconds for `op read`. Default `60`. Set `0` to disable the timeout.
- `STRONGBOX_MANIFEST`: override the manifest path. Default `$XDG_CONFIG_HOME/strongbox/manifest.toml` or `~/.config/strongbox/manifest.toml`.

## Troubleshooting

- `cache: cannot locate a per-user tmpfs runtime dir`: you are likely outside a normal login session and do not have `XDG_RUNTIME_DIR`. Log into a session that sets it, or set `STRONGBOX_CACHE_DIR` to a tmpfs path manually.
- `strongbox: 'op' (1Password CLI) not found on PATH`: install 1Password CLI 2.x and ensure `op` is reachable from the shell running `strongbox`.
- `warning: cache entry at ... has mode ...; deleting and re-fetching`: usually benign. Something changed the cache file permissions or ownership, and strongbox repaired the entry by deleting it and fetching a fresh value.
- `op read` fails with authentication errors: re-authenticate in the 1Password desktop app or run `op signin`, then retry.
- Strongbox still prompts every time: confirm the 1Password desktop app is running and CLI integration is enabled in `Settings -> Developer`.
