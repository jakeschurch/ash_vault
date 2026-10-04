# MACs (signing and verification)

For API keys or bearer tokens naming a record, use a `macaroon` instead
(`usage-rules/macaroons.md`). It is built on this keyring.

A vault can also authenticate bytes, for signed URLs, opaque tokens and unforgeable record
references. MACs use their own `:mac` keyring per scope (never the data key, never the lookup
key), so rotating one never moves the others. Erasure (`destroy!/1`) destroys all of them.

```elixir
ctx = %AshVault.Context{
  resource: MyApp.Invite,
  field: :token,
  ash_context: %{tenant: org_id}
}

{version, tag} = MyApp.Vault.mac!(invite_id, ctx)      # tag: 32 raw bytes
:ok = MyApp.Vault.verify_mac!(invite_id, version, tag, ctx)

{:ok, 2} = MyApp.Vault.rotate!(org_id, purpose: :mac)
{:ok, 3} = AshVault.rotate_key!(MyApp.Vault, org_id, nil, purpose: :mac)   # with telemetry
```

- Store or transmit **both** `version` and `tag`; encode the tag for transport
  (`Base.url_encode64/2`).
- The tag is bound to scope, resource and field: a tag for tenant A or field X never verifies
  for B or Y.
- Old key versions stay fetchable, so plain tags issued before a rotation keep verifying.
  A `:mac` rotation **does** revoke macaroons outside their `accepted_key_versions` window.
- `rotate!/2` accepts only `purpose: :data | :mac`; a typo raises.
- Default MAC: `AshVault.Macs.HmacSha256` (in the BEAM); with `OpenBaoTransit` it is
  `AshVault.Macs.OpenBaoTransit` (inside OpenBao).
- With `cache:` enabled, MAC requests are never cached: expect a provider round trip per call.

## Errors from `verify_mac!/4`

| Error | Meaning | Response |
|---|---|---|
| `AshVault.Errors.KeyDestroyed` | Scope erased; every tag it issued is revoked | Reject permanently |
| `AshVault.Errors.KeyNotFound` | Claimed key version does not exist | Reject as invalid |
| `AshVault.Errors.InvalidMac` | Key found, tag wrong (tampered/forged/other scope, resource or field) | Reject as invalid |
| `AshVault.Errors.ProviderUnavailable` | Provider could not answer | **Retry**; nothing was decided |
| `AshVault.Errors.ProviderForbidden` | Provider refused the request (`403`) | Configuration fault; nothing was decided |
| `AshVault.Errors.PurposeUnsupported` | Provider has no `:mac` keyring | Configuration fault |

- Never treat `ProviderUnavailable` as an invalid tag; that logs a forgery that did not happen.
- Never log tags or signed data. A tag is a bearer credential.
- Don't compare tags yourself; call `verify_mac!/4` (constant-time).
