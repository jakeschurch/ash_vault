# Queued work

Sequenced behind the in-flight Rust NIF cache and security-semantics agents, both of which
are editing `lib/ash_vault/errors.ex` and `lib/ash_vault/vault/runtime.ex`.

---

## 1. Rename `AshVault.Errors.AuthenticationFailed` → `AshVault.Errors.CiphertextIntegrityFailed`

**Status:** queued, agreed.

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
- **Example-app API friction**, six items reported by the example build. The sharpest: a
  missing OTP app start surfaces as `ProviderUnavailable{reason: {:transport, ArgumentError}}`,
  indistinguishable from a genuine outage. Others: provider config living under the
  `:ash_vault` OTP key rather than the host app's; `Local` needing both a supervised child and
  an `init_root!/1` step while `OpenBao` needs `setup/0`, with no `child_spec/1` + `setup/0`
  pair on the behaviour to unify them; the vault being compile-time so there is no runtime
  provider switch; and `destroy_keys` returning `{:ok, :ok}` through `Ash.run_action/1`.
- **Four pre-existing ex_doc autolink warnings** in `lib/` doc strings (`current_key/1` is a
  callback not a function; `UnsupportedCipher.t()` and `Ash.Resource.record()` are undefined
  types; `Ash.Helpers.non_executable_binary_to_term/2` is `@doc false` upstream).
