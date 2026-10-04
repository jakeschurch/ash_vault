# Changelog

All notable changes to AshVault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Macaroons. A `macaroon` entity in the `ash_vault` section declares an attenuable
  bearer token naming one record (`prefix`, `identity`, `revoked_when`, `default_ttl`,
  `accepted_key_versions`, and `caveat name, type, check:, phase:` entries). It
  generates a `:mint_<name>` generic action and a `:<name>_by_token` verifying read
  action, each with a code interface. Guide: [Macaroons](documentation/topics/macaroons.md).
  - Format: `prefix_` + base64url of a versioned envelope (scope, `:mac` key version,
    identity, caveats, signature), decoded strictly. The root signature is the vault's
    MAC at the token's stated key version; each caveat extends an HMAC-SHA256 chain
    under its own `ashvault:macaroon:caveat:v1|` domain prefix, compared in constant
    time.
  - `AshVault.Macaroon.attenuate/2`: pure, keyless narrowing by any holder.
  - `AshVault.Macaroon.Preparations.Verify`, with `mode: :sign_in` for
    AshAuthentication-style sign-in actions (`[record]` or `[]`; outages stay errors).
  - `AshVault.Checks.MacaroonAllows`: a policy check enforcing `phase: :authorize`
    caveats (`AshVault.Macaroon.Caveats.ActionIn` ships as one).
  - Revocation per record (`revoked_when`), per scope by rotating the `:mac` keyring
    past `accepted_key_versions` (default `1`: rotation revokes every outstanding
    token), and by crypto-erasure.
  - Errors `AshVault.Errors.InvalidMacaroon` and `AshVault.Errors.MacaroonRevoked`;
    `ProviderUnavailable` passes through and is never reported as an invalid token.
  - `AshVault.Verifiers.VerifyMacaroons`: prefix charset, unique identity, resolvable
    scope, a vault that serves `:mac`, serializable caveat types and compiled checks.
- Version-pinned MACs: `AshVault.Vault.Runtime.mac_at!/4` and
  `current_mac_version!/2`, exposed on vaults as `mac_at!/3` and `mac_key_version!/1`
  (optional callbacks). `mac_at!` recomputes a tag at a stated key version with the
  `verify_mac!` error taxonomy, and never mints a keyring.
- `AshVault.Mac` behaviour (`id/0`, `key_bytes/0`, `mac/3`, `verify/4`), the
  authentication sibling of `AshVault.Cipher`, with two implementations:
  - `AshVault.Macs.HmacSha256`: HMAC-SHA256 in process, constant-time verification.
  - `AshVault.Macs.OpenBaoTransit`: HMAC-SHA256 through `transit/hmac` and
    `transit/verify`, so the key never leaves OpenBao.
- Key purposes. `AshVault.KeyProvider` gains optional `purposes/0`, `current_key/2`,
  `get_key/3` and `rotate/2` callbacks for a per-scope `:mac` keyring, implemented by
  `Memory`, `Local`, `OpenBao`, `OpenBaoTransit` and `Cached`. `:mac` keys are 32
  random bytes, never the data or lookup key and never derived from either.
  `destroy/1` destroys every purpose under one tombstone.
- Vault API: `mac!/2` returns `{key_version, tag}`, `verify_mac!/4` checks one, and
  `rotate!(scope, purpose: :mac)` / `AshVault.rotate_key!(vault, scope, ctx,
  purpose: :mac)` rotate the MAC keyring. A new `mac:` vault option picks the MAC and
  defaults by provider.
- Errors: `AshVault.Errors.InvalidMac` (the tag is wrong) and
  `AshVault.Errors.PurposeUnsupported` (the provider has no `:mac` keyring).
  `KeyDestroyed`, `KeyNotFound` and `ProviderUnavailable` keep their meanings for MACs:
  revoked, invalid and retryable.
- Telemetry: `[:ash_vault, :mac, :sign]` and `[:ash_vault, :mac, :verify]` spans, and
  `:purpose` on `[:ash_vault, :key, :rotate]`.
- Guide: [Key purposes and MACs](documentation/topics/key-purposes-and-macs.md).

### Compatibility

- Existing key providers, vaults and configuration keep working unchanged. The
  arity-1 `current_key/1`, `get_key/2` and `rotate/1` callbacks are the `:data` purpose.
  A third-party provider without `purposes/0` serves `:data` only.
- A provider that already defines a `current_key/2`, `get_key/3` or `rotate/2` helper
  (such as a named-server form) and uses `@impl` elsewhere will now get a missing-`@impl`
  warning for it, because those arities are now optional callbacks. Mark them
  `@impl AshVault.KeyProvider`, or rename them. Unless the provider also defines
  `purposes/0`, AshVault never calls them as purpose callbacks.
