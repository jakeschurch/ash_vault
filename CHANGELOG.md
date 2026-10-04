# Changelog

All notable changes to AshVault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

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
