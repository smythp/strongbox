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

## Environment

- `STRONGBOX_TTL`: idle TTL in seconds. Default `14400`. Set `0` to disable expiry.
- `STRONGBOX_CACHE_DIR`: override the cache directory. By default strongbox uses `$XDG_RUNTIME_DIR/strongbox` or `/run/user/<uid>/strongbox`.
