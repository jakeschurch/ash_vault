# AshVault.KeyProviders.Local — spec

Three providers ship:

| Provider | Intended use | Key store |
|---|---|---|
| `AshVault.KeyProviders.Memory` | tests, dev | process memory, dies with the node |
| `AshVault.KeyProviders.Local` | single-node deployments, homelab, dev with persistence | files on disk |
| `AshVault.KeyProviders.OpenBao` | production / multi-node | OpenBao transit |

`Local` exists because the motivating property — "restoring a PostgreSQL backup must not
resurrect destroyed keys" — only needs the key store to be **a different system from the
database**. A directory on a different volume, excluded from the database backup job, is a
legitimate answer for a single-node app. `Memory` cannot serve that role (it forgets
everything on restart); OpenBao is overkill for one node.

## Layout

    <root>/
      <scope_dir>/
        meta.json          # {"current": 2, "versions": {"1": "<iso8601>", "2": "<iso8601>"}}
        v1.key             # raw key bytes, mode 0600
        v2.key
      <scope_dir>.tombstone   # presence == scope destroyed; JSON {"destroyed_at": "<iso8601>"}

`scope_dir` = `Base.url_encode64(scope, padding: false)` — total, reversible, filesystem-safe.
Expose `AshVault.KeyProviders.Local.scope_dir/1` so operators can find a tenant's directory.
The tombstone sits **beside** the directory, not inside it, so destroying the directory
cannot destroy the tombstone.

## Behaviour

`start_link/1` opts: `:name` (default `__MODULE__`), `:root`, `:key_bytes` (default 32).
Config fallback `Application.get_env(:ash_vault, AshVault.KeyProviders.Local)`.
`:root` is required — raise a clear error naming the config key if absent.

Runs as a **GenServer** and serializes all mutations through it. Reads (`get_key/2`,
`current_key/1` on an existing scope) may still go through the server — simplicity beats
throughput here, and the OpenBao provider is the answer for load.

On boot: `File.mkdir_p!(root)`, then verify the directory is writable and that its mode is
`0700` — if it is group- or world-readable, log a loud warning naming the path (do not refuse
to start; operators on odd filesystems need an escape hatch).

- `current_key/1` — tombstone check first → `{:error, :destroyed}`. Else read `meta.json`;
  if absent, mint v1 (see Durability). Return `%{version:, key:, created_at:}`.
- `get_key/2` — tombstone check first. Then read `v<version>.key`; missing → `{:error, :not_found}`.
- `rotate/1` — tombstone check first (a destroyed scope must never rotate back to life).
  Mint `v<current+1>.key`, then update `meta.json`.
- `destroy/1` — see below. Idempotent: destroying an already-destroyed or never-existing scope
  writes the tombstone and returns `:ok`.

## Durability rules (these are the whole point)

Every write path must be crash-safe, because a half-written `meta.json` that points at a
missing key file makes a tenant's data unreadable — an accidental crypto-erasure.

1. Write key material to a temp file in the same directory, `File.write!(path, bytes)`,
   then `:file.sync/1` the file handle, then `File.rename!/2` into place (atomic within a
   filesystem), then fsync the containing directory.
2. Write `meta.json` the same way. Key file lands **before** the meta entry that references
   it — so a crash leaves an orphan key file (harmless) rather than a dangling reference.
3. `destroy/1` order: (a) overwrite every `v*.key` with random bytes of the same length and
   fsync, (b) delete them, (c) delete `meta.json`, (d) remove the scope directory,
   (e) write the tombstone and fsync it and the root directory. Return `:ok` only if the
   tombstone write succeeded. If (e) fails, return `{:error, reason}` — a destroy that did
   not record its tombstone must not be reported as success.

Overwriting before unlinking is best-effort: on CoW and log-structured filesystems (btrfs,
ZFS, SSD FTLs) it does not guarantee the old bytes are gone. Say so in the @moduledoc —
do not imply a guarantee the filesystem does not make.

## Operational documentation (must appear in the @moduledoc and in the guides)

- The key directory must be **excluded from the database backup**. If both land in the same
  tarball, crypto-erasure is defeated and the library's central promise is void.
- It should also not be on the same volume you snapshot with the database.
- Back the key directory up **separately** and deliberately, with its own retention policy —
  losing it destroys all encrypted data. This is a real, sharp tradeoff: backups of keys make
  erasure harder, and no backups of keys make data loss easy. State the tradeoff; do not
  pretend there is a free answer.
- `Local` is single-node. Two nodes sharing one NFS mount will race; use OpenBao instead.

## Tests

Run the shared provider contract suite (`test/support/key_provider_cases.ex`) against
`Local` with a `tmp_dir` root, plus:
- keys survive a provider restart (stop the GenServer, start it on the same root, same key bytes come back)
- tombstone survives a restart → still `{:error, :destroyed}`
- **the backup/restore simulation**: copy the whole root dir (the "backup"), destroy a scope,
  then restore *only the database side* — i.e. assert that restoring anything other than the
  key root leaves the scope destroyed; and separately assert that restoring the key root
  *does* bring it back, documenting why that directory must not be in the DB backup
- `meta.json` corrupted/truncated → `AshVault.Errors.ProviderUnavailable`, never `:destroyed`
- key file missing while meta references it → `{:error, :not_found}`, never `:destroyed`
- file modes: key files are `0600`
