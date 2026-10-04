# Changelog

All notable changes to AshVault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- `AshVault.Errors.ProviderForbidden`: the key store answered `403`. It carries the
  refused `:operation` (`:encrypt`, `:hmac`, `:create_key`, `:read_key`,
  `:read_tombstone`, ...) and never the transit key name.
  `AshVault.KeyProviders.OpenBao.Transport.operation/3` derives that operation from a
  request path.
- Tests covering a scope's first write under the recommended OpenBao policy, which
  grants `create` on `transit/keys` but not on `transit/encrypt`. They run against a
  stub and against a live server (`:openbao`).

### Changed

- **Breaking:** an OpenBao `403` is now `AshVault.Errors.ProviderForbidden`. It was
  `ProviderUnavailable` with `reason: :forbidden`, which callers and metrics treated as
  a transient outage and retried. A `403` is a policy, credential or addressing fault,
  and retrying cannot fix it. Match the new struct wherever you matched
  `reason: :forbidden`. A `403` on a tombstone read still fails closed. A Kubernetes
  auth login refused with `403` is still `ProviderUnavailable` with reason
  `{:kubernetes_auth, :forbidden}`, because the token holder retries the login itself.

### Documentation

- An HA OpenBao must be addressed through its active node. Standbys serve reads and
  policy checks from a lagging copy of the data. An encrypt sent right after AshVault
  explicitly creates a scope's key can reach a standby that has not seen the key yet.
  The standby treats the encrypt as an implicit create and returns `403`. Verified
  against openbao 2.6.3. The `OpenBaoTransit` policy example now matches what the
  provider needs: `create` on `transit/keys`, and nothing more on the encrypt path.

## 0.1.0 - 2026-10-04

First release, published together with `ash_vault_rustler` 0.1.0.

### Added

- Usage rules for coding agents: `usage-rules.md` and `usage-rules/*.md`, shipped in the
  package for [`usage_rules`](https://hex.pm/packages/usage_rules) to sync into an
  application's agent instructions.
- Released under the MIT license.

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
  - Revocation per record (`revoked_when`, which must be exactly `false`), per scope by
    rotating the `:mac` keyring past `accepted_key_versions` (default `1`: rotation
    revokes every outstanding token), and by crypto-erasure (reported as
    `:bad_signature`, indistinguishable from forgery by design).
  - Errors `AshVault.Errors.InvalidMacaroon` and `AshVault.Errors.MacaroonRevoked`;
    `ProviderUnavailable` passes through and is never reported as an invalid token.
  - `AshVault.Verifiers.VerifyMacaroons`: prefix charset, unique identity, resolvable
    scope, a vault that serves `:mac`, serializable caveat types and compiled checks.
  - Computed options: `default_ttl` may be a function / `AshVault.Macaroon.Ttl` module of
    the mint input, always clamped to the new static `max_ttl` (required for a function;
    a `:ttl` argument above it is refused); `accepted_key_versions` may be an
    `AshVault.Macaroon.KeyWindow` module or MFA of the scope, failing closed to `1`;
    caveat `check:` takes a module or an inline `fn value, context -> ... end`.
  - Every failure before the signature verifies (malformed, unknown version, wrong
    prefix, unknown or crypto-erased scope, bad chain) is reported to the caller as
    `InvalidMacaroon{reason: :bad_signature}`, with equalized in-process work, so forged
    tokens cannot enumerate tenants or detect erasure; the precise reason is on the new
    `[:ash_vault, :macaroon, :rejected]` telemetry event. A request tenant is compared
    only after the signature verifies.
  - The root signature uses the reserved vault field `:"macaroon:<name>"`, so no
    `Vault.mac!/2` call for an attribute can serve as a root-signature oracle.
  - `require_authorize_enforcement?` (DSL) / `require_enforcement?` (preparation) refuse
    tokens carrying authorize-phase caveats unless the caller asserts enforcement, and
    the compiler warns when a macaroon has authorize-phase caveats but the resource's
    own policies never use `MacaroonAllows`.
  - Token scopes are capped at 180 bytes.
- `AshVault.KeyProviders.Local` answers `:not_found` (not `ProviderUnavailable`) for a
  scope whose key path exceeds the filesystem's name limit: no key or tombstone can exist
  there, and a caller-supplied scope must not be able to manufacture an outage.
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
- Kubernetes auth for the OpenBao providers: `auth: {:kubernetes, role: ..., mount:
  ..., jwt_path: ...}` in place of `:token`. A token holder supervised by AshVault
  (`AshVault.KeyProviders.OpenBao.KubernetesAuth`) logs in with the service-account JWT,
  caches the client token, and logs in again, re-reading the rotated JWT, at two thirds
  of the lease. Failures back off exponentially and are `ProviderUnavailable` with
  reason `{:kubernetes_auth, reason}`. Neither the token nor the JWT is logged or put
  in process status.
- TLS options for the OpenBao providers: `:cacertfile` trusts a private CA with peer and
  hostname verification on, and `:connect_options` passes through to Req. A missing CA
  file is `ProviderUnavailable` with reason `{:cacertfile_unreadable, path}`, and
  `verify: :verify_none` is refused.
- Guide: [Running against OpenBao in Kubernetes](documentation/how-to/openbao-in-kubernetes.md).

### Compatibility

- Existing key providers, vaults and configuration keep working unchanged. The
  arity-1 `current_key/1`, `get_key/2` and `rotate/1` callbacks are the `:data` purpose.
  A third-party provider without `purposes/0` serves `:data` only.
- A provider that already defines a `current_key/2`, `get_key/3` or `rotate/2` helper
  (such as a named-server form) and uses `@impl` elsewhere will now get a missing-`@impl`
  warning for it, because those arities are now optional callbacks. Mark them
  `@impl AshVault.KeyProvider`, or rename them. Unless the provider also defines
  `purposes/0`, AshVault never calls them as purpose callbacks.
