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
capability; nothing else should have it. Non-exportable transit (encrypt/decrypt round trips
through OpenBao per value) is a possible future provider — `AshVault.KeyProviders.OpenBaoTransit` —
but it changes the `KeyProvider` contract (no raw key), so it is out of scope for v1.

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
2. `destroy/1`: set `deletion_allowed`, DELETE the transit key, then write the tombstone
   `POST /v1/ashvault/data/tombstones/<scope>` with `{"data":{"destroyed_at":"<iso8601>"}}`.
   Write the tombstone **after** the delete succeeds, and only return `:ok` if both succeed.
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
