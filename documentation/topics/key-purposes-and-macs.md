# Key purposes and MACs

A vault encrypts, and it can also **authenticate**: compute a message authentication
code (MAC) over some bytes so that anyone holding the vault can later check that the
bytes are exactly what was signed, for exactly this tenant, resource and field. Signed
URLs, opaque API tokens, unforgeable record references and [macaroons](macaroons.md)
are all built from that one operation.

MACs get their own keys. This guide covers the keyring split that makes that safe, the
vault API, and what each error means.

## Two keyrings per scope

Every scope has one keyring per **purpose**:

| Purpose | Used by | Callbacks |
|---|---|---|
| `:data` | `AshVault.Cipher` — encrypting fields | `current_key/1`, `get_key/2`, `rotate/1` |
| `:mac` | `AshVault.Mac` — `mac!/2`, `verify_mac!/4` | `current_key/2`, `get_key/3`, `rotate/2` |

The rules for the `:mac` keyring are the rules for the `:data` keyring, plus separation:

* **Minted on first use** at version 1, from its own random bytes. A `:mac` key is never
  a `:data` key, never the lookup key, and never derived from either. It is always 32
  bytes, whatever the provider's data key size.
* **Rotated independently.** `rotate!(scope, purpose: :mac)` mints a new MAC version and
  leaves the data key where it is; `rotate!(scope)` moves the data key and leaves the MAC
  key alone.
* **Old versions stay fetchable**, so a tag minted before a rotation keeps verifying.
* **One tombstone covers both.** `destroy!/1` destroys every purpose. Afterwards every
  tag the scope ever issued answers `KeyDestroyed`, and neither keyring re-mints.

The `:data` arity forms are unchanged. A provider written before purposes existed keeps
working for encryption exactly as before; it simply cannot MAC (see
[Writing a key provider](../how-to/writing-a-key-provider.md#serving-the-mac-purpose)).

## Using it

```elixir
ctx = %AshVault.Context{
  resource: MyApp.Invite,
  field: :token,
  ash_context: %{tenant: org_id}
}

{version, tag} = MyApp.Vault.mac!(invite_id, ctx)

# later
:ok = MyApp.Vault.verify_mac!(invite_id, version, tag, ctx)
```

`mac!/2` returns the key version alongside the tag; store or transmit both. `tag` is 32
raw bytes. Encode it however your transport needs (`Base.url_encode64/2` for a URL).

The tag is bound to the scope, resource and field through the same associated data
encryption uses (the scope comes from the context through the vault's `AshVault.Scope`,
`AshVault.Scopes.AshTenant` by default), so a tag minted for one tenant, resource or field never verifies for
another. Rotation is a vault call:

```elixir
{:ok, new_version} = MyApp.Vault.rotate!(org_id, purpose: :mac)
AshVault.rotate_key!(MyApp.Vault, org_id, nil, purpose: :mac)   # with telemetry
```

`rotate!/2` accepts only `:purpose`, and only `:data` or `:mac`. A typo such as
`purpos: :mac` raises instead of silently rotating the data key.

## Which MAC

| Key provider | Default `mac:` | Where the HMAC runs |
|---|---|---|
| `Memory`, `Local`, `OpenBao`, `Cached` over any of them | `AshVault.Macs.HmacSha256` | in the BEAM, over the exported 32-byte key |
| `OpenBaoTransit` | `AshVault.Macs.OpenBaoTransit` | inside OpenBao, via `transit/hmac` and `transit/verify`; the key never leaves Bao |

Both compute HMAC-SHA256 over the same frozen frame (`AshVault.Mac.frame/2`):

    "ashvault:mac:v1|" <> <<byte_size(aad)::64>> <> aad <> data

The associated data is length-prefixed, so no `(aad, data)` pair can be re-split into
another with the same bytes. The domain prefix keeps these tags from ever equalling an
HMAC some other code computes under the same key. Because the frame is identical, the
same key bytes give the same tag in both modules.

An explicit `mac:` is checked at compile time: `AshVault.Macs.OpenBaoTransit` over any
provider but `OpenBaoTransit`, `AshVault.Macs.HmacSha256` over `OpenBaoTransit`, or any
`mac:` over a provider that does not list `:mac` in `purposes/0` is a compile error.
Without `mac:`, a vault over a data-only provider still compiles, and `mac!/2` raises
`AshVault.Errors.PurposeUnsupported` if it is ever called.

### OpenBao policy

`OpenBao` stores each scope's `:mac` keyring as a third transit key,
`<data key name>.mac`, and exports its per-version HMAC key. `OpenBaoTransit` keeps the
same-named key `exportable: false` and needs, in addition to its data-key policy:

```hcl
path "transit/hmac/*"   { capabilities = ["update"] }
path "transit/verify/*" { capabilities = ["update"] }
```

`.` is outside the base64url alphabet scope names are encoded with, so no scope's MAC
key name can equal any scope's data or lookup key name.

### Caching

`AshVault.KeyProviders.Cached` caches only the `:data` keyring. `:mac` requests pass
through to the wrapped provider every time, still short-circuited by a cached
tombstone. Expect one provider round trip per `mac!` and per `verify_mac!`.

## What the errors mean

Verification fetches the key before it looks at the tag, so the answer about the key
always wins:

| Error | Meaning | Response |
|---|---|---|
| `AshVault.Errors.KeyDestroyed` | the scope was crypto-erased | **revoked**, permanently |
| `AshVault.Errors.KeyNotFound` | the claimed key version does not exist | **invalid** |
| `AshVault.Errors.InvalidMac` | key found, tag wrong: tampered, forged, wrong version, or another scope/resource/field | **invalid** |
| `AshVault.Errors.ProviderUnavailable` | the provider could not answer | **retry**; nothing was decided |
| `AshVault.Errors.PurposeUnsupported` | the provider has no `:mac` keyring | configuration fault |

An outage is never reported as a bad tag, and a bad tag is never reported as an outage.
Do not collapse `ProviderUnavailable` into "deny and forget": a caller that treats an
outage as an invalid token will log a forgery that never happened.

Errors and telemetry never carry the tag or the data. A tag is a bearer credential.

Comparison is constant-time: `HmacSha256` uses `:crypto.hash_equals/2`, and
`OpenBaoTransit` delegates the comparison to OpenBao.

## Related

* `AshVault.Mac`, `AshVault.Macs.HmacSha256`, `AshVault.Macs.OpenBaoTransit`
* `AshVault.KeyProvider` — the *Purposes* section
* [Crypto-erasure](crypto-erasure.md) — what `destroy!/1` promises, now for tags too
* [Rotation](rotation.md)
* [Macaroons](macaroons.md) — attenuable tokens built on the `:mac` keyring, and
  `mac_at!/3`, the version-pinned MAC they verify with
