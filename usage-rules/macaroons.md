# Macaroons (attenuable API tokens)

A `macaroon` declares a bearer token that names one record of the resource (an API key,
say). It is signed under the scope's `:mac` keyring. Any holder can narrow it with more
caveats, offline, and cannot widen it again. Use it instead of hand-rolled API-key
hashing or `Vault.mac!/2` token schemes.

```elixir
ash_vault do
  vault MyApp.Vault

  macaroon :api do
    prefix "myapp"                                  # 2-32 chars [a-z][a-z0-9]*, no "_"
    identity :id                                    # PK or one-key identity: string/ci_string/uuid/integer
    revoked_when expr(not is_nil(revoked_at))
    default_ttl 30 * 86_400                         # seconds, :infinity, or fn input -> ... end
    accepted_key_versions 1                         # default; see Revocation

    caveat :ip, :string, check: MyApp.Caveats.RemoteIp
    caveat :actions, {:array, :string},
      phase: :authorize,
      check: AshVault.Macaroon.Caveats.ActionIn
  end
end
```

Generated: a `:mint_api` generic action and an `:api_by_token` read (`get? true`, sensitive
`:token` argument), both with code interfaces. Rename them with `mint_action` / `read_action`.

```elixir
{:ok, token} = ApiKey.mint_api(key.id, %{caveats: %{ip: "203.0.113.7"}, ttl: 3600},
                               tenant: org.id, actor: admin)
{:ok, key} = ApiKey.api_by_token(token, context: %{remote_ip: "203.0.113.7"})
key.__metadata__.macaroon   #=> %AshVault.Macaroon.Verified{}

{:ok, narrower} = AshVault.Macaroon.attenuate(token, actions: ["read"])  # no key needed
```

## Rules

- **`revoked_when` must be exactly `false` for a live token.** `true`, `nil` and errors all
  revoke. `revoked_at <= now()` is `nil` while `revoked_at` is unset, so it revokes every
  key. Write `not is_nil(revoked_at) and revoked_at <= now()`.
- **Verifying needs no tenant.** The token carries its scope. A request that already has a
  tenant must match it, or the read fails with `:scope_mismatch`. A token reveals its
  tenant id.
- **The verifying read obeys policies.** It usually runs with no actor, so add a `bypass`
  for `:api_by_token` (and any sign-in read). The token is the credential.
- **Caveat checks may only narrow.** A check decides from its own value and the request.
  Never write one that grants more for some value, such as an `admin: true` caveat. That
  breaks attenuation for every token of the macaroon.
- **Undeclared caveats or wrong value types are rejected** (`:unknown_caveat`,
  `:caveat_type`). Supported types: `:string`, `:integer`, `:boolean`, `:utc_datetime`,
  `:utc_datetime_usec`, `{:array, :string}`, `{:array, :integer}`.
- **`phase: :authorize` caveats are enforced only by `AshVault.Checks.MacaroonAllows`.**
  Put it on every resource a macaroon actor can reach, or in a shared policy:

  ```elixir
  policy always() do
    forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api, when_absent: true}
    authorize_if actor_present()
  end
  ```

  The compiler only sees the declaring resource's policies. Set
  `require_authorize_enforcement? true` to refuse such tokens unless the caller passes
  `context: %{ash_vault: %{authorize_caveats_enforced?: true}}`.
- **Use the actor the verifying read returned.** The verified macaroon lives in
  `__metadata__`. `Ash.reload/2`, `Ash.get/3` or a per-request reload drops it, and with
  `when_absent: true` every authorize-phase caveat then silently stops applying.
- **Computed options.** Only three options can be computed:
  - `default_ttl` as a function or module must have a finite `max_ttl` (compile error
    otherwise), and its result is clamped to `max_ttl`. A `:ttl` argument above `max_ttl` is
    refused, not clamped.
  - `accepted_key_versions` takes a module or MFA, never an inline fn. If it fails, it
    falls back to `1`.
  - A caveat `check:` may be an inline fn.
- **Renaming the resource module or the macaroon invalidates every outstanding token.**

## Plug sign-in

For a plug, use a read with `prepare {AshVault.Macaroon.Preparations.Verify, macaroon: :api,
argument: :api_key, mode: :sign_in}`. In `:sign_in` mode, an invalid or revoked token returns
`[]` (send 401). Any `{:error, _}` is an outage or config fault (send 503). Never turn an error
into a 401.

## Revocation

| Scope of revocation | How | Error |
|---|---|---|
| One record | make `revoked_when` true | `MacaroonRevoked`, `:record` |
| All tokens in the scope | `AshVault.rotate_key!(MyApp.Vault, scope, nil, purpose: :mac)` | `MacaroonRevoked`, `:key_retired` |
| Everything the scope issued | `AshVault.destroy_keys!/3` (erasure) | `InvalidMacaroon`, `:bad_signature` |

- With `accepted_key_versions 1` (default), **any** `:mac` rotation logs out every token of
  that macaroon in the scope. Use `2` so scheduled rotations do not cut off live clients.
- The `:mac` keyring is shared per scope with every other macaroon and every `Vault.mac!`
  user. Rotating `:data` never affects macaroons.
- Erased-scope tokens report as forgeries on purpose. Do not try to tell them apart for the
  caller. Use telemetry instead.

## Errors

- `AshVault.Errors.InvalidMacaroon`: the token is bad. Reject it.
- `AshVault.Errors.MacaroonRevoked`: the token was valid but is revoked. Reject it.
- `AshVault.Errors.ProviderUnavailable`: retry. **Never** report it as an invalid token.
- `AshVault.Errors.ProviderForbidden`: the key store refused (`403`); a configuration
  fault. Alert, do not retry, and **never** report it as an invalid token.

Never log tokens. Never return the precise rejection reason to the holder. For operators,
attach a handler to `[:ash_vault, :macaroon, :rejected]` telemetry, which carries the
precise `:reason`.
