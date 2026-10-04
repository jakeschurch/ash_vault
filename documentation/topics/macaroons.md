# Macaroons

A macaroon is a bearer token that its **holder** can narrow. Hand a service a token
that may do anything a user may do; the service can append `actions: ["read"]` and
pass the narrower token on, without calling you and without being able to undo the
restriction. The issuer can still revoke at three levels.

AshVault declares macaroons on a resource, signs them under the scope's `:mac` key (see
[Key purposes and MACs](key-purposes-and-macs.md)), and generates the actions to mint
and verify them.

## Declaring one

```elixir
defmodule MyApp.Accounts.ApiKey do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault
    scope :tenant

    macaroon :api do
      prefix "myapp"
      identity :id
      revoked_when expr(not is_nil(revoked_at))
      default_ttl 30 * 86_400
      accepted_key_versions 1

      caveat :ip, :string, check: MyApp.Caveats.RemoteIp

      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn
    end
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  # ...
end
```

| Option | Meaning |
|---|---|
| `prefix` | 2-32 chars of `[a-z][a-z0-9]*`. Make it distinctive: it is what secret scanners match on. No `_` — it separates prefix from payload. |
| `identity` | How a token names its record: the single primary key attribute, or a one-key identity. Must be a string, ci_string, UUID or integer. |
| `revoked_when` | An expression over the record. The token verifies only while it is exactly `false`; `true`, `nil` and errors all revoke. Mind SQL `nil` semantics: `revoked_at <= now()` is `nil`, not `false`, while `revoked_at` is unset, so it revokes every live key. Write `not is_nil(revoked_at) and revoked_at <= now()`. |
| `default_ttl` | Seconds until the minted token expires, `:infinity`, or a function of the mint input (see below). |
| `max_ttl` | The ceiling on every minted lifetime. Required when `default_ttl` is a function. |
| `accepted_key_versions` | How many recent `:mac` key versions verify (default `1`), `:all`, or a per-scope module / MFA. See *Revocation*. |
| `require_authorize_enforcement?` | Refuse tokens with authorize-phase caveats unless the caller asserts enforcement. |
| `mint_action` / `read_action` | Rename the generated actions. |
| `caveat name, type, check:, phase:` | A restriction a token may carry. |

### Computed options

Three options may be computed rather than fixed; everything else — `prefix`,
`identity`, caveat types and `revoked_when` (an expression only) — is static.

```elixir
macaroon :api do
  # per plan, tenant or actor; evaluated at mint with the action input
  default_ttl fn input -> if input.tenant in MyApp.internal_orgs(), do: 7 * 86_400, else: 3_600 end
  max_ttl 30 * 86_400

  # per scope, evaluated at verify; a module (AshVault.Macaroon.KeyWindow) or an MFA,
  # never an inline fn
  accepted_key_versions {MyApp.Macaroons, :window_for, []}

  caveat :tier, :string,
    check: fn tier, ctx -> if ctx.context[:tier] == tier, do: :ok, else: {:error, :tier} end
end
```

* `default_ttl` as a function (or an `AshVault.Macaroon.Ttl` module) is called with the
  mint `Ash.ActionInput`. Its answer is **clamped to `max_ttl`** — `:infinity` included —
  so it can never mint a near-permanent token; an answer that is not a positive integer
  or `:infinity`, or a raise, refuses the mint. A `:ttl` argument above `max_ttl` is
  refused rather than clamped: the caller asked for more than it may have.
* `accepted_key_versions` as a module or MFA is called with the token's scope. An answer
  that is not a positive integer or `:all`, or a raise, **fails closed to `1`** (only the
  current key version verifies) and logs a warning with the scope fingerprint.
* A caveat `check:` is a module, `{module, opts}`, or an inline
  `fn value, context -> ... end` returning `:ok`/`true` to admit, anything else
  (`{:error, reason}`, `false`) to refuse.

## What is generated

* `:mint_api` — a generic action returning the token string, with arguments for the
  identity (`:id` here), `:caveats` (a map of declared names to values) and `:ttl`.
  It loads the record through the primary read (same actor, tenant and `authorize?`)
  and refuses a missing or revoked one.
* `:api_by_token` — a read action, `get? true`, taking a sensitive `:token`. It verifies
  the token and returns the record it names.
* Code interfaces for both:

```elixir
{:ok, token} = ApiKey.mint_api(key.id, %{caveats: %{ip: "203.0.113.7"}, ttl: 3600},
                               tenant: org.id, actor: admin)

{:ok, key} = ApiKey.api_by_token(token)
key.__metadata__.macaroon        #=> %AshVault.Macaroon.Verified{...}
key.__metadata__.using_macaroon? #=> true
```

No tenant is needed to verify: the token carries its scope, the signature binds it,
and the verifying read sets it as the query's tenant once the signature checks out. A
request that already carries a tenant must agree with the token, or it is refused
(`:scope_mismatch`). The token therefore reveals the tenant id it belongs to.

The verifying read is an ordinary read, so the resource's policies apply to its record
load. A token-authenticated request usually has no actor yet; authorize the action
itself — the token is the credential:

```elixir
policies do
  bypass action([:api_by_token, :sign_in_with_api_key]) do
    authorize_if always()
  end
end
```

## Attenuating

```elixir
{:ok, narrower} = AshVault.Macaroon.attenuate(token, actions: ["read"], ip: "10.0.0.7")
```

`attenuate/2` is pure: no vault, no key, no resource. Anyone holding a token can call
it. The verifier rejects any caveat the macaroon does not declare (`:unknown_caveat`)
and any value whose type disagrees with the declaration (`:caveat_type`).

Every caveat a token carries must admit the request, so adding one can only shrink what
the token allows — **as long as every check only narrows**. A check must decide from its
own value and the request alone; one that grants more because of its value (an
`admin: true` caveat) breaks the guarantee for every token of that macaroon. See
`AshVault.Macaroon.Caveat`.

`expires_at` is the one built-in caveat. `default_ttl` (or `:ttl` on mint) adds it, and
a holder can attenuate with an earlier `expires_at`; a later one cannot extend the
token, because the earlier one still has to hold. Expiry is checked against the
verifier's clock — never one taken from request context.

### Caveat types

| Declared type | Value |
|---|---|
| `:string` | a UTF-8 string |
| `:integer` | a signed 64-bit integer |
| `:boolean` | `true` / `false` |
| `:utc_datetime`, `:utc_datetime_usec` | a `DateTime` (microsecond precision) |
| `{:array, :string}`, `{:array, :integer}` | a non-empty list (up to 32) |

### Verify-phase and authorize-phase checks

A `phase: :verify` check (the default) runs inside the verifying read, after the record
is loaded. Its `AshVault.Macaroon.CheckContext` carries the record and the read's
context — the place a plug puts request facts:

```elixir
ApiKey.api_by_token(token, context: %{remote_ip: "203.0.113.7"})
```

A `phase: :authorize` check runs in `AshVault.Checks.MacaroonAllows`, against the
action being authorized on **any** resource, with the macaroon-authenticated record as
the actor:

```elixir
policies do
  policy always() do
    forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api, when_absent: true}
    authorize_if actor_present()
  end
end
```

`when_absent: true` lets actors that did not sign in with a macaroon through; macaroon
actors are held to every authorize-phase caveat they carry.

> #### Authorize-phase caveats are enforced only by `MacaroonAllows` {: .warning}
>
> A resource whose policies do not use the check does not restrict a macaroon actor by
> authorize-phase caveats. Put it on every resource such an actor can reach, or in a
> shared policy. Nobody holding a token can tell where it is enforced — a third party
> given an attenuated `actions: ["read"]` token is trusting your policy coverage.
>
> Two guards help. The compiler warns when a macaroon declares authorize-phase caveats
> and the declaring resource's own policies never use the check (other resources'
> policies are invisible to it, so silence is not proof). And
> `require_authorize_enforcement? true` makes the verifying read refuse such tokens
> (`:unenforced_caveats`) unless the caller asserts enforcement:
>
> ```elixir
> ApiKey.api_by_token(token, context: %{ash_vault: %{authorize_caveats_enforced?: true}})
> ```

> #### `when_absent: true` drops caveats from reloaded actors {: .warning}
>
> The verified macaroon lives in the actor's `__metadata__`. Re-reading the actor
> (`Ash.reload/2`, `Ash.get/3`, a session that stores the id and reloads per request)
> returns a record without it, which `when_absent: true` then treats as an actor that
> never used a macaroon — every authorize-phase caveat silently stops applying. Use the
> record the verifying read returned as the actor, or keep `when_absent: false` where
> only macaroon actors belong.

## Signing in from a plug

AshAuthentication's API key strategy insists on its own preparation, so it cannot be
pointed at a macaroon. The preparation follows the same convention instead — a read
action with a non-nil string argument, returning `[record]` with metadata, or `[]` —
so a plug in that style works unchanged:

```elixir
read :sign_in_with_api_key do
  argument :api_key, :string, allow_nil?: false, sensitive?: true
  get? true

  prepare {AshVault.Macaroon.Preparations.Verify,
           macaroon: :api, argument: :api_key, mode: :sign_in}
end
```

```elixir
def call(conn, _opts) do
  with ["Bearer " <> token] <- get_req_header(conn, "authorization") do
    ApiKey
    |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: token},
      context: %{remote_ip: conn.remote_ip |> :inet.ntoa() |> to_string()}
    )
    |> Ash.read()
    |> case do
      {:ok, [key]} -> Ash.PlugHelpers.set_actor(conn, key)
      {:ok, []} -> conn |> send_resp(401, "") |> halt()
      {:error, _outage_or_config_fault} -> conn |> send_resp(503, "") |> halt()
    end
  else
    _ -> conn |> send_resp(401, "") |> halt()
  end
end
```

In `mode: :sign_in` an invalid or revoked token reads as no record. An outage is still
an error — never an empty result, which a plug would turn into a 401 and a log line
about a bad credential that never existed.

## Revocation

Three levels, from narrowest to widest:

| Level | How | Error |
|---|---|---|
| One record | make `revoked_when` true (set `revoked_at`) | `MacaroonRevoked`, `:record` |
| Every token of the scope | rotate the scope's `:mac` keyring | `MacaroonRevoked`, `:key_retired` |
| Everything the scope ever issued | `destroy!` the scope (crypto-erasure) | `InvalidMacaroon`, `:bad_signature` |

Tokens of an erased scope are reported exactly like forgeries, on purpose: once the
keys are gone the signature cannot be checked, so the verifier cannot tell a genuine
erased token from a forged one naming that tenant — and answering "revoked" would tell
any forger which tenants were erased. Telemetry carries the distinction (below).

### Rotation semantics

A token records the `:mac` key version it was signed under. It verifies while that
version is one of the `accepted_key_versions` most recent versions:

    token.key_version > current_version - accepted_key_versions

With the default `1`, **rotating the scope's `:mac` keyring revokes every outstanding
token of this macaroon in the scope** — the "log every integration out" button:

```elixir
AshVault.rotate_key!(MyApp.Vault, org_id, nil, purpose: :mac)
```

With `2`, tokens minted under the previous version keep working until the next rotation
retires them, so a scheduled rotation does not cut off live clients. `:all` never
retires (rotation then limits only how long one key version signs new tokens).

Know what is shared:

* The `:mac` keyring is per **scope**, and shared with every other `Vault.mac!` user and
  every other macaroon in that scope. Rotating it moves all of them; each macaroon applies
  its own `accepted_key_versions`. Plain `verify_mac!/4` tags have no window and keep
  verifying.
* Rotating the `:data` key never affects macaroons.
* Verification costs two key-provider calls with a window (`get_key` at the stated
  version, then the current version), one with `:all`. `:mac` keys are not cached by
  `AshVault.KeyProviders.Cached`.

## Errors

| Error | Meaning |
|---|---|
| `AshVault.Errors.InvalidMacaroon` | the token is wrong. Before the signature verifies there is one reason, `:bad_signature`; after it, `:scope_mismatch`, `:unknown_key_version`, `:unknown_caveat`, `:caveat_type`, `:expired`, `{:caveat_failed, name}`, `:unenforced_caveats`, `:not_found` |
| `AshVault.Errors.MacaroonRevoked` | the token was good and is revoked: `:record`, `:key_retired` (or `:scope_destroyed` if erasure races the check) |
| `AshVault.Errors.ProviderUnavailable` | the key provider could not answer. Retry. Never reported as invalid, never as valid |
| `AshVault.Errors.ProviderForbidden` | the key provider refused the request (`403`). A configuration fault; do not retry. Never reported as invalid, never as valid |

Errors never carry the token, its signature or its identity.

### Telemetry

Every refused token emits `[:ash_vault, :macaroon, :rejected]` with `%{count: 1}` and
metadata `:resource`, `:macaroon` and the **precise** `:reason` — including the
pre-signature ones collapsed into `:bad_signature` for the caller: `:malformed`,
`:unsupported_version`, `:wrong_prefix`, `:scope_mismatch`, `:unknown_key_version`,
`:scope_destroyed`, `:bad_signature`. Attach a handler for operator diagnostics; never
return its reason to the token holder.

### Timing

A scope with no key, or an erased one, answers without a MAC being computed. The
verifier runs the same local HMAC and chain replay under a throwaway key on that path,
so the in-process work matches a real verification. The residual differences are the
key provider's own latency for a missing versus a present key, and — under
`OpenBaoTransit` — the `transit/hmac` round trip a real verification makes and this
path does not. Rate-limit token verification if tenant existence is sensitive.

## The format

    token   = prefix "_" base64url(payload)            (no padding)
    payload = 0x01 | len8 scope (<= 180 bytes) | key_version:32 | len8 id
              | count:8 | count × (len16 caveat) | sig:32

The root signature is the vault's MAC at the token's stated key version, under the
reserved context field `:"macaroon:<name>"` (so no ordinary `Vault.mac!/2` call for an
attribute can double as a root-signature oracle), over

    "ashvault:macaroon:root:v1|" <> len64(prefix) <> prefix <> <<1>>
      <> len64(scope) <> scope <> <<key_version::64>> <> len64(id) <> id

bound by the vault's associated data to the scope, resource and macaroon name. Under
`AshVault.KeyProviders.OpenBaoTransit` it is computed inside OpenBao. Each caveat then
extends the chain locally:

    sig_i = HMAC-SHA256(sig_{i-1}, "ashvault:macaroon:caveat:v1|" <> len64(caveat_i) <> caveat_i)

with its own domain prefix, so a chain step never equals any other HMAC in the system.
The final signature is compared in constant time. Decoding is strict — oversized,
truncated, trailing, non-canonical or unknown-version input is refused before any key
provider is asked anything — and a forged scope
cannot make the provider mint a keyring, because only a version-pinned `get_key` runs
before the signature verifies.

Renaming the resource module or the macaroon changes the associated data and so
invalidates every outstanding token, as it does for encrypted fields.

See `AshVault.Macaroon.Envelope`, `AshVault.Macaroon.CaveatCodec` and
`AshVault.Macaroon.Chain` for the frozen details.
