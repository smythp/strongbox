# strongbox

`strongbox` is a drop-in replacement for `op inject` that caches resolved `op://...` secrets in a per-user runtime directory. The cache uses one file per reference, keyed by `sha256(ref)`, with mode `0600`, owner checks, atomic writes, and idle TTL refresh on each read.

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

## Environment

- `STRONGBOX_TTL`: idle TTL in seconds. Default `14400`. Set `0` to disable expiry.
- `STRONGBOX_CACHE_DIR`: override the cache directory. By default strongbox uses `$XDG_RUNTIME_DIR/strongbox` or `/run/user/<uid>/strongbox`.
- `STRONGBOX_OP_TIMEOUT`: timeout in seconds for `op read`. Default `60`. Set `0` to disable the timeout.
- `STRONGBOX_MANIFEST`: override the manifest path. Default `$XDG_CONFIG_HOME/strongbox/manifest.toml` or `~/.config/strongbox/manifest.toml`.
