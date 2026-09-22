# AshVault.KeyProviders.OpenBao — spec

All facts below were verified live against `openbao/openbao:2.6.2` in dev mode
(container `ashvault-bao`, `http://127.0.0.1:8200`, token `ashvault-root`).

## Why transit *export*, not datakey

`transit/datakey/plaintext/<key>` returns a fresh DEK plus its wrapped form. Recovering
that DEK later requires storing the wrapped blob alongside the ciphertext — which our
envelope has no slot for, and which would put wrapped key material inside the PostgreSQL
backup. Instead we use an **exportable transit key** as the scope's key material:

- Key material lives in OpenBao. Nothing key-related is ever written to PostgreSQL.
- Transit key *versions* map 1:1 onto `AshVault` key versions.
- Deleting the transit key destroys every version at once — the crypto-erasure primitive,
  and it happens outside the `pg_dump` domain.

Tradeoff to document in the threat model: `exportable: true` means a holder of a
transit-export capability can read raw key material. The AshVault app needs exactly that
capability; nothing else should have it. Non-exportable transit — encrypt/decrypt round trips through OpenBao per value — now ships as
`AshVault.KeyProviders.OpenBaoTransit`, paired with `AshVault.Ciphers.OpenBaoTransit`. It serves
`AshVault.Key` handles instead of raw key material and costs one round trip per value. See the
"Choosing between the two OpenBao providers" section of `documentation/topics/threat-model.md`.

## Verified endpoints

| Operation | HTTP | Path | Notes |
|---|---|---|---|
| health | GET | `/v1/sys/health` | |
| mount transit | POST | `/v1/sys/mounts/transit` `{"type":"transit"}` | one-time setup |
| create key | POST | `/v1/transit/keys/<name>` `{"type":"aes256-gcm96","exportable":true,"allow_plaintext_backup":false}` | **`deletion_allowed` is IGNORED here** — server returns `warnings: ["Endpoint ignored these unrecognized parameters: [deletion_allowed]"]` |
| allow deletion | POST | `/v1/transit/keys/<name>/config` `{"deletion_allowed":true}` | required before DELETE, else 400 |
| read key meta | GET | `/v1/transit/keys/<name>` | `data.latest_version`, `data.keys` = `%{"1" => <unix seconds>, ...}` → `created_at` |
| rotate | POST | `/v1/transit/keys/<name>/rotate` | bumps `latest_version` |
| export all versions | GET | `/v1/transit/export/encryption-key/<name>` | `data.keys` = `%{"1" => "<base64 32 bytes>", ...}` |
| export one version | GET | `/v1/transit/export/encryption-key/<name>/<version>` | same shape, single entry |
| delete key | DELETE | `/v1/transit/keys/<name>` | `204`; afterwards read and export both `404` |

Auth header: `X-Vault-Token: <token>`.

## Tombstones are mandatory

After DELETE, the key name is simply absent. A naive `current_key/1` would create it again
and mint a fresh v1 — **resurrecting an erased scope**. So:

1. Mount a KV-v2 engine once at `ashvault/` (`POST /v1/sys/mounts/ashvault {"type":"kv","options":{"version":"2"}}`).
2. `destroy/1`: write the tombstone `POST /v1/ashvault/data/tombstones/<scope>` with
   `{"data":{"destroyed_at":"<iso8601>"}}` **before** deleting either transit key; then
   set `deletion_allowed` and DELETE both the data and lookup keys. Return `:ok` only
   after both are confirmed absent. Repeated destroys retry cleanup behind a tombstone.
3. `current_key/1` and `get_key/2`: check the tombstone **first**
   (`GET /v1/ashvault/data/tombstones/<scope>`, `200` = destroyed, `404` = not destroyed).
   If present, return `{:error, :destroyed}` without touching transit.

The tombstone lives in OpenBao, not PostgreSQL, so restoring a database backup cannot clear it.

## Scope name mapping

Transit key names allow `[a-zA-Z0-9_.-]`. Scope keys are already normalized to binaries by
the Scope module, but tenant ids can contain other characters. Map deterministically:

    name = "ashvault_" <> Base.url_encode64(scope, padding: false) |> String.replace("-", "_")

Reject nothing; the encoding is total. Document that the transit key name is derived, not
the raw tenant id (so operators need `mix ash_vault.key_name <tenant>` — provide it as a
public function `AshVault.KeyProviders.OpenBao.key_name/1`).

## Config

```elixir
config :ash_vault, AshVault.KeyProviders.OpenBao,
  address: "http://127.0.0.1:8200",
  token: {:system, "BAO_TOKEN"},
  transit_mount: "transit",
  kv_mount: "ashvault",
  key_type: "aes256-gcm96"
```

Token resolution supports a literal binary, `{:system, var}`, or a 0-arity fun.
**Never log the token.** Use `req` (already a dependency) with `retry: :transient`.

## Error mapping

| Condition | AshVault error / return |
|---|---|
| tombstone present | `{:error, :destroyed}` |
| transit key 404, no tombstone | `{:error, :not_found}` |
| requested version > latest, or below `min_decryption_version` | `{:error, :not_found}` |
| 403 | `AshVault.Errors.ProviderUnavailable` with `reason: :forbidden` |
| connection refused / timeout / 5xx | `AshVault.Errors.ProviderUnavailable` |
| 200 but export body missing the version | `{:error, :not_found}` |

`ProviderUnavailable` must never be conflated with `:destroyed`. An outage must not look
like erasure, and erasure must not look like an outage.

## Tests

Guard the suite with `@moduletag :openbao` and skip unless `BAO_ADDR`/health check passes,
so `mix test` stays green without Docker. Provide `mix test --include openbao`.
Suite mirrors the Memory provider suite exactly (same shared test cases — put them in
`test/support/key_provider_cases.ex` as a `__using__` macro so both providers run the
identical contract), plus:
- setup/teardown creates and deletes a uniquely-named scope per test
- destroy then `current_key` returns `:destroyed` (not a fresh v1)
- destroy is idempotent
- wrong token -> `ProviderUnavailable`, never `:destroyed`


---

## Corrections from the live implementation (authoritative over the table above)

Verified against openbao 2.6.2 while building the provider.

### Status codes: several failures are 400, not 404

| Probe | Actual |
|---|---|
| `GET /v1/transit/export/encryption-key/<k>/<above latest>` | `400 "version does not exist or cannot be found"` |
| same, below `min_decryption_version` | `400 "version for export is below minimum decryption version"` |
| `DELETE /v1/transit/keys/<absent>` | `400 "could not delete key; not found"` |
| `POST /v1/transit/keys/<absent>/config` | `400 "no existing key named ... could be found"` |
| `POST /v1/transit/keys/<absent>/rotate` | `400 "key not found"` |
| `POST /v1/sys/mounts/<existing>` | `400 "path is already in use"` — the mount call is **not** idempotent; idempotency must be synthesized client-side |

### Two 404 flavours that decide whether erasure holds

- **Missing KV mount** returns `404 "no handler for route ... route entry not found."` — status-identical
  to "no tombstone here". If read naively, a missing mount reads as *not destroyed* and an erased tenant
  comes back to life. The provider therefore mounts KV and retries once; if the route is still missing it
  returns `ProviderUnavailable` and **never** concludes "no tombstone". Tombstone reads fail closed.
- **Soft-deleted tombstone** returns `404` with a body carrying `metadata` / `deletion_time` and
  `data: null`. It existed, so it counts as **destroyed**.

### `key_name/1` — the spec's dash replacement was a security bug

This document originally specified:

    Base.url_encode64(scope, padding: false) |> String.replace("-", "_")

That is **not injective**. `Base.url_encode64("ab>") == "YWI-"` and `Base.url_encode64("ab?") == "YWI_"`
both collapse to `ashvault_YWI_` — two different tenants sharing one transit key, so destroying one
tenant would crypto-erase the other. Transit accepts `-` in key names directly (verified: creating
`ashvault_aB-c.d_e` returns 200). The implemented, correct form is:

    "ashvault_" <> Base.url_encode64(scope, padding: false)

The tombstone path likewise uses `tombstones/<key_name(scope)>`, not the raw scope — a scope containing
`/` would otherwise silently reshape the KV hierarchy.

### Other confirmations

- Export returns **standard** base64 (`+` and `/`), so decode with `Base.decode64/1`, not `url_decode64`.
- Creating a key that already exists is idempotent: returns the existing metadata, does not re-mint.
- Wrong token yields `403 permission denied` on every endpoint — always `ProviderUnavailable`, never `:destroyed`.
- `rotate/1` on a scope with no key returns `{:ok, 1}` (the create mints v1), matching the Memory provider.
- Extra config keys beyond those listed above: `:receive_timeout` (default 5s), `:max_retries` (default 2).
