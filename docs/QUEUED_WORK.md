# Queued work

Sequenced behind the in-flight Rust NIF cache and security-semantics agents, both of which
are editing `lib/ash_vault/errors.ex` and `lib/ash_vault/vault/runtime.ex`.

---

## 1. Rename `AshVault.Errors.AuthenticationFailed` → `AshVault.Errors.CiphertextIntegrityFailed`

**Status: DONE.** The module is `AshVault.Errors.CiphertextIntegrityFailed`, no alias was
left behind, and `message/1` now leads with the integrity failure and states outright that
it is not an authorization error. The scope below is kept as the record of why; the name
`AuthenticationFailed` survives only in this section's own prose.

### Why

The error is the AEAD tag check — the "authenticated" in *authenticated encryption*. It fires
when GCM verification fails: the stored bytes were modified, the AAD did not match (the blob
was moved between tenants, resources or fields), or the key was wrong.

It has nothing to do with actors, policies, or `AshAuthentication`. But AshVault sits directly
beside `AshAuthentication` and `Ash.Policy.Authorizer`, where "authentication failed" means
something completely different — and the project's own author read it that way on first
encounter. That is the evidence: if the person who wrote the error taxonomy misparses the name,
every operator will.

The mis-triage runs in the dangerous direction. `CiphertextIntegrityFailed` means *someone has
write access to your database*. An authorization error means Tuesday. A name that downgrades
the first into the second is a real operational hazard.

Cheap now: nothing is published, and the error is runtime-only — there is no persisted format
to migrate. The envelope on disk is untouched by this change.

### Scope

- `lib/ash_vault/errors.ex` — rename the module; rewrite `message/1` to lead with what happened
  and to state explicitly that it is **not** an authorization error:

      Ciphertext for MyApp.User.email failed its integrity check.

      The stored bytes were modified, were encrypted for a different tenant, resource or
      field, or were encrypted with a different key.

      This is not an authorization error. AshVault performs no authorization; if this
      operation reached the crypto layer, Ash had already authorized it.

- All raise sites and rescues: `lib/ash_vault/vault/runtime.ex`, `lib/ash_vault.ex`, and any
  `rescue error in [...]` lists that enumerate the error modules.
- Tests: `test/ash_vault/vault_test.exs`, `test/integration/`, `test/acceptance/`, and the
  cross-tenant / cross-field substitution assertions that name it.
- Docs: `documentation/topics/{threat-model,operations,crypto-erasure}.md`,
  `documentation/how-to/writing-a-key-provider.md`, `README.md`,
  `docs/{CORE_SPEC,REVIEW_FINDINGS}.md`, and `docs/adr/0002-distinguishable-crypto-errors.md`
  if that ADR has landed by then.
- Add a short note in the docs' error-taxonomy table saying plainly that this error is about
  ciphertext integrity, not access control — the table is where someone will look when
  triaging.

**Do not add a deprecated alias.** Nothing is released; an alias would preserve exactly the
confusing name this change exists to remove.

### Done when

`grep -rn AuthenticationFailed` returns nothing outside this file's history, and
`mix test --include postgres --include openbao` is green at its then-current count.

Met: 323 tests (320 + one asserting the new message's "not an authorization error"
disclaimer, and two for the `runtime.ex` redactions), 425 with postgres and openbao.

---

## 2. Deferred, previously discussed — not queued for action

- **Key cache DSL surface** — resolved: `cache: true` on the vault, desugaring to the
  `Cached` wrapper. In flight.
- **`AshVault.KeyProviders.OpenBaoTransit`** — a provider that never exports the DEK, doing
  encrypt/decrypt inside OpenBao. The genuinely strong answer to "key material in BEAM memory",
  at the cost of a network round trip per value and a `KeyProvider` contract that returns no
  raw key. See `documentation/topics/threat-model.md`.
- **Searchable fields** (`searchable?`, `unique?`) — specified in
  `documentation/topics/searchable-fields.md`, rejected by the transformer today.
- **Example-app API friction**, six items reported by the example build. **DONE**, all six:

    1. A missing OTP app start is reported as `{:not_started, :req}`, with a
       `ProviderUnavailable` message that says it is not an outage, that the server was
       never contacted, and what to add where. Detected positively
       (`AshVault.KeyProviders.OpenBao.transport_status/0`), never by parsing an exception
       message — those interpolate the request, whose headers carry the token.
    2. Optional `child_spec/1` and `setup/0` callbacks on `AshVault.KeyProvider`, with
       `MyApp.Vault.child_specs/0` and `MyApp.Vault.setup/0` as the host-facing one-liners.
       Optional, so third-party providers are unaffected.
    3. Provider config may live under the host's OTP app: `AshVault.KeyProvider.config/1`
       merges `config :my_app, Provider, ...` over `config :ash_vault, Provider, ...`. The
       vault records the application it is compiled into and registers it on load.
    4. `destroy_keys` returns `%AshVault.Erasure{scope:, destroyed_at:}` instead of `:ok`
       wrapped into `{:ok, :ok}`.
    5. Compile-time vault resolution **kept** — it is what makes the key-size check
       possible. The two-vault + `fun/2` resolver pattern is now the documented supported
       answer: `documentation/topics/two-vaults.md`.
    6. The four ex_doc autolink warnings are fixed; `mix docs` is at zero warnings.
- **Four pre-existing ex_doc autolink warnings** in `lib/` doc strings — **DONE**, see
  above.

- **Telemetry's `:scope` metadata** — resolved: the lifecycle events keep the **raw**
  scope, because the compliance record of an erasure has to be able to name the tenant it
  erased and a fingerprint cannot. They also carry `:scope_fingerprint`, which is a
  convenience for handlers forwarding outward and explicitly **not** a mitigation. The
  operations guide warns that a handler forwarding this metadata to an external service is
  forwarding tenant identifiers. Reasoning lives in `AshVault.Telemetry`'s moduledoc and in
  `documentation/topics/operations.md`.
