# ADR 0001 — AshVault does not build on `Cloak.Vault`

Status: accepted
Date: 2026-09-21

## Context

AshVault must encrypt Ash resource attributes with a key selected **per request**, from
runtime facts (Ash tenant, resource, field). The obvious prior art is
[Cloak](https://hex.pm/packages/cloak) (`cloak 1.1.4`) and `ash_cloak`, which wraps it.

We read the Cloak source before deciding.

## What Cloak's architecture actually is

Cloak's vault is **static, module-level configuration cached in ETS**:

- `use Cloak.Vault` generates a GenServer (`deps/cloak/lib/cloak/vault.ex:164-286`).
- Config comes from `Application.get_env(@otp_app, __MODULE__, [])` merged with
  `start_link/1` opts, passed once through a user-overridable `init/1`
  (`vault.ex:178-200`). That `init/1` is the only configuration hook and it runs
  **once, at process boot**.
- The resolved config is written to a named `:protected` ETS table
  `:"#{__MODULE__}.Config"` as a single `{:config, config}` row (`vault.ex:172, 288-295`),
  re-written only on `code_change/3` hot upgrade (`vault.ex:212-217`).
- Every call reads that one row: `read_config/1` → `:ets.lookup(table, :config)`
  (`vault.ex:297-304`).

The public API is correspondingly context-free (`vault.ex:223-275`):

```elixir
encrypt(plaintext)        encrypt!(plaintext)
encrypt(plaintext, label) encrypt!(plaintext, label)
decrypt(ciphertext)       decrypt!(ciphertext)
```

`label` is an atom key into the statically configured `:ciphers` keyword list — a
compile/config-time selector, not a runtime value that can carry a tenant id.

The cipher behaviour has the same shape (`deps/cloak/lib/cloak/cipher.ex:80-92`):

```elixir
@callback encrypt(plaintext, opts) :: {:ok, binary} | :error
@callback decrypt(ciphertext, opts) :: {:ok, binary} | :error
@callback can_decrypt?(ciphertext, opts) :: boolean
```

`opts` is the static keyword list from the `{module, opts}` config tuple — identical on
every call. Decryption key selection is a linear scan calling each configured cipher's
`can_decrypt?/2` with its static opts (`vault.ex:371-375`), matching a TLV key tag baked
into the ciphertext header (`deps/cloak/lib/cloak/tags/encoder.ex`).

## The decision

**There is no supported extension point in `Cloak.Vault` or `Cloak.Cipher` that accepts
per-call runtime context.** Not a context argument, not an extra arity, not a process-dictionary
convention. Threading a tenant id through Cloak requires one of:

1. one vault process + ETS config row **per tenant** — unbounded processes and ETS tables,
   with key material resident in ETS for the life of the node, which directly conflicts with
   AshVault's crypto-erasure requirement (destroyed keys must not survive in a cache); or
2. overriding the generated functions via `defoverridable` (`vault.ex:284`) to close over
   external state — reimplementing the vault while keeping its name.

Both are worse than owning the abstraction. AshVault therefore defines its own
`AshVault.Vault` behaviour whose every operation takes an `AshVault.Context`
(resource, field, Ash runtime context), and its own `AshVault.Cipher` behaviour taking
`(plaintext, key, aad)` explicitly.

## Consequences

- AshVault can bind ciphertext to `scope | resource | field` via AEAD additional
  authenticated data. Cloak's AES.GCM uses a **fixed literal AAD** `"AES256GCM"`
  (`deps/cloak/lib/cloak/ciphers/aes_gcm.ex:12`), so ciphertext is freely relocatable
  between tenants, resources and fields. That relocation is exactly threat #7/#8 of our
  Definition of Done.
- AshVault owns its ciphertext envelope (versioned, carrying cipher id **and key version**)
  rather than Cloak's TLV key tag. Key version is what makes rotation-without-re-encryption
  and per-scope erasure possible.
- Keys are fetched from an `AshVault.KeyProvider` per operation, so the authoritative key
  store lives outside the application and outside the PostgreSQL backup domain. Cloak's keys
  are config, and config is typically deployed alongside — and restorable with — the app.
- AshVault does not depend on `cloak` at runtime. (`cloak` and `ash_cloak` are `:dev/:test`-only
  dependencies used for reference and comparison.)
- We give up Cloak's ecosystem of ciphers and its `Cloak.Ecto` field types. `ash_cloak`
  remains the right choice for a single-key, non-multitenant application that wants the
  smallest possible setup.

## Reusable concepts we did take from `ash_cloak`

- Splitting each encrypted attribute into a persisted `encrypted_*` column plus a
  non-persisted plaintext view.
- Using `Ash.Type.dump_to_embedded/3` / `Ash.Type.cast_from_embedded/3` to preserve Ash
  type information across the crypto boundary instead of serializing raw structs.
- Exposing the decrypted value as an Ash calculation so field policies and loading behave
  normally.

What we did **not** take is its value-only `vault.encrypt!(value)` call shape, which is a
direct consequence of Cloak's API above.
