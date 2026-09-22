# AshVault Ash extension — authoritative spec (v1)

Every API fact below was verified against the vendored source at `deps/` —
ash 3.33.9, spark 2.7.3, ash_cloak 0.4.0. Citations are `file:line` inside `deps/`.

The crypto core (docs/CORE_SPEC.md) is a separate work item and is assumed to exist:
`AshVault.Vault` behaviour with `encrypt!/2`, `decrypt!/2` taking `%AshVault.Context{}`.

---

## 1. Target DSL

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault
    scope :tenant

    encrypt :email
    encrypt :phone
    encrypt :ssn, encrypt_nil?: false

    decrypt_by_default [:email]
  end
end
```

Sugar for the common case (identical meaning, expanded by a transformer):

```elixir
  ash_vault do
    vault MyApp.Vault
    attributes [:email, :phone, :ssn]
  end
```

### Why an entity, not a bare list

ash_cloak's `cloak` section is **schema-only, zero entities**
(`deps/ash_cloak/lib/ash_cloak.ex:12-55`). That cannot grow per-field options
(`searchable?`, `unique?`, `encrypt_nil?`, `backfill_from`), which v1 needs and §21 requires.
So `AshVault` uses a real `%Spark.Dsl.Entity{}` and keeps `attributes [...]` as sugar.

### Section definition

```elixir
@encrypt %Spark.Dsl.Entity{
  name: :encrypt,
  describe: "Encrypt a single attribute of this resource.",
  examples: ["encrypt :email", "encrypt :ssn, encrypt_nil?: false"],
  target: AshVault.Encrypted,
  args: [:name],
  schema: [
    name: [type: :atom, required: true, doc: "The attribute to encrypt."],
    encrypt_nil?: [type: :boolean, doc: "Encrypt nil instead of storing SQL NULL. Defaults to the section-level setting."],
    searchable?: [type: :boolean, default: false, doc: "Also store a keyed HMAC lookup token. Post-v1; rejected by the verifier for now."],
    unique?: [type: :boolean, default: false, doc: "Add a unique identity on the lookup token. Requires searchable?. Post-v1."],
    backfill_from: [type: :atom, doc: "Existing plaintext attribute to read during a migration backfill."]
  ]
}

@ash_vault %Spark.Dsl.Section{
  name: :ash_vault,
  describe: "Configure encrypted attributes for this resource.",
  entities: [@encrypt],
  sections: [@key_lifecycle],
  schema: [
    vault: [type: {:or, [{:behaviour, AshVault.Vault}, :mfa, {:fun, 2}]}, required: true],
    scope: [type: {:or, [{:in, [:tenant, :global]}, {:behaviour, AshVault.Scope}]}, default: :tenant],
    attributes: [type: {:wrap_list, :atom}, default: [], doc: "Shorthand for a list of `encrypt` entities with default options."],
    decrypt_by_default: [type: {:wrap_list, :atom}, default: []],
    encrypt_nil?: [type: :boolean, default: true],
    scope_owner?: [type: :boolean, default: false]
  ]
}

@key_lifecycle %Spark.Dsl.Section{
  name: :key_lifecycle,
  describe: "Generate generic actions for key rotation and cryptographic erasure.",
  schema: [
    rotate: [type: :atom, doc: "Name of a generic action that rotates this scope's key."],
    destroy: [type: :atom, doc: "Name of a generic action that destroys this scope's keys."]
  ]
}

use Spark.Dsl.Extension, sections: [@ash_vault], transformers: @transformers, verifiers: @verifiers
```

`AshVault.Encrypted` is the entity target struct:
`defstruct [:name, :encrypt_nil?, :searchable?, :unique?, :backfill_from]`.

Introspection module:

```elixir
defmodule AshVault.Info do
  use Spark.InfoGenerator, extension: AshVault, sections: [:ash_vault]
end
```

`Spark.InfoGenerator` generates `ash_vault_vault/1`+`!`, `ash_vault_scope/1`+`!`,
`ash_vault_attributes/1`+`!`, `ash_vault_decrypt_by_default/1`+`!`,
`ash_vault_encrypt_nil?/1`, `ash_vault_scope_owner?/1`, `ash_vault_options/1`, and
`ash_vault_encrypt/1` for the entities (`deps/spark/lib/spark/info_generator.ex:53,87,121`).
Note the naming rules: `?`-suffixed options get **only** `name?/1` (no bang);
non-predicate options with a non-nil default never return `:error`.

Add a hand-written helper on top:

```elixir
def encrypted_fields(resource_or_dsl) :: [%AshVault.Encrypted{}]   # entities + expanded `attributes` sugar
def encrypted_field(resource_or_dsl, name) :: %AshVault.Encrypted{} | nil
def scope_module(resource_or_dsl) :: module()   # :tenant -> AshVault.Scopes.AshTenant, :global -> AshVault.Scopes.Global
```

---

## 2. Transformers

Two, in this order:

### `AshVault.Transformers.ExpandAttributes`

`before?(AshVault.Transformers.SetupEncryption), do: true`

Turns each atom in the `attributes` option into an `%AshVault.Encrypted{}` entity via
`Spark.Dsl.Transformer.add_entity(dsl, [:ash_vault], entity)`, skipping names already
present as entities. Then leaves `attributes` alone (harmless).

### `AshVault.Transformers.SetupEncryption`

**Ordering — load-bearing:**

```elixir
def after?(Ash.Resource.Transformers.DefaultAccept), do: true
def after?(_), do: false
```

`Ash.Resource.Transformers.DefaultAccept` expands `:*`/`nil` accept lists into concrete
attribute names (`deps/ash/lib/ash/resource/transformers/default_accept.ex:36-60`). Running
before it means `attr.name in action.accept` is false everywhere and **zero actions get
rewritten** — silent, total failure. There is no `before_compile?` callback in Spark 2.7.3;
the behaviour is exactly `transform/1`, `before?/1`, `after?/1`, `after_compile?/0`
(`deps/spark/lib/spark/dsl/transformer.ex:60-80`).

**Per encrypted field, in this order** (mirrors `deps/ash_cloak/lib/ash_cloak/transformers/set_up_encryption.ex:33-54`):

```elixir
dsl
|> Spark.Dsl.Transformer.remove_entity([:attributes], &(&1.name == attribute.name))
|> Ash.Resource.Builder.add_attribute(:"encrypted_#{name}", :binary,
     allow_nil?: true,                       # SEE NOTE BELOW — differs from ash_cloak
     sensitive?: true,
     public?: false,
     description: "Encrypted #{name}"
   )
|> Ash.Resource.Builder.add_calculation(
     name,
     attribute.type,
     {AshVault.Calculations.Decrypt, [field: :"encrypted_#{name}", plain_field: name]},
     public?: attribute.public?,
     constraints: attribute.constraints,
     allow_nil?: attribute.allow_nil?,
     sensitive?: true,
     filterable?: false,
     sortable?: false,
     description: attribute.description
   )
|> rewrite_actions(attribute, encrypted_config)
```

Removing the attribute entity is **the** non-persistence mechanism — there is no plaintext
column, so no data layer can write one. Do not rely on `private?` or on scrubbing for that.

> **NOTE on `allow_nil?`**: ash_cloak copies `attribute.allow_nil?` onto the backing column.
> That is wrong whenever `encrypt_nil?: false`, because then a nil value legitimately stores
> SQL NULL on a `allow_nil?: false` column and the write fails. AshVault sets the backing
> attribute `allow_nil?: true` always, and enforces the real nullability through the
> **calculation's** `allow_nil?` plus the action argument's `allow_nil?`. Document this
> deviation.

**Rejections (raise `Spark.Error.DslError`, `path: [:ash_vault, :encrypt]`):**
- attribute does not exist
- attribute is part of the primary key
- attribute name already has an `encrypted_` sibling
- `searchable?`/`unique?` set (post-v1; clear "not implemented in v1" message)

**Action rewriting** — same filter as ash_cloak:

```elixir
Ash.Resource.Info.actions()
|> Enum.filter(&(&1.type in [:create, :update, :destroy] && attr.name in &1.accept))
```

For each: build an argument of the original type, build the change, and `replace_entity`:

```elixir
opts =
  case action.type do
    :create -> [allow_nil?: attr.allow_nil?, constraints: attr.constraints, default: attr.default, sensitive?: true]
    _       -> [constraints: attr.constraints, sensitive?: true]
  end

{:ok, argument} = Ash.Resource.Builder.build_action_argument(attr.name, attr.type, opts)
{:ok, change}   = Ash.Resource.Builder.build_action_change({AshVault.Changes.Encrypt, field: attr.name})

Spark.Dsl.Transformer.replace_entity(dsl, [:actions],
  %{action |
    arguments: [argument | Enum.reject(action.arguments, &(&1.name == attr.name))],
    changes: [change | action.changes],
    accept: action.accept -- [attr.name]},
  &(&1.name == action.name))
```

`sensitive?: true` on the argument is required — without it the plaintext appears in
error messages and `inspect` output.

**`decrypt_by_default`** (resource-global, not per action):

```elixir
dsl
|> Ash.Resource.Builder.add_change({Ash.Resource.Change.Load, target: fields})
|> Ash.Resource.Builder.add_preparation({Ash.Resource.Preparation.Build, options: [load: fields]})
```

**`key_lifecycle`** generic actions, when configured and `scope_owner?` is true:

```elixir
Ash.Resource.Builder.add_action(dsl, :action, rotate_name,
  run: {AshVault.Actions.RotateKey, []}, returns: :integer, description: "...")
Ash.Resource.Builder.add_action(dsl, :action, destroy_name,
  run: {AshVault.Actions.DestroyKeys, []}, returns: :atom, description: "...")
```

Both run with ordinary Ash actors and policies — AshVault adds no authorization of its own.
Verifier: `key_lifecycle` without `scope_owner? true` is a DSL error telling the user to put
lifecycle on the resource that owns the scope (the tenant/organization), not on every
resource with encrypted fields.

---

## 3. Verifier — `AshVault.Verifiers.VerifyVault`

`Spark.Dsl.Verifier` runs after compile, so cross-module checks cost no compile-time
dependency (`deps/spark/lib/spark/dsl/verifier.ex:54-71`). Checks:

- the configured `vault` module exports `encrypt!/2`, `decrypt!/2`, `rotate!/1`, `destroy!/1`
  (`Code.ensure_compiled` + `function_exported?`) when it is a plain module
- `decrypt_by_default` names are all encrypted fields
- `backfill_from` names an attribute that still exists
- `scope_owner? false` + `key_lifecycle` configured -> error
- duplicate `encrypt` entries for one attribute -> error

Note `use Spark.Dsl.Extension` auto-prepends `Spark.Dsl.Verifiers.VerifyEntityUniqueness`
and `VerifySectionSingletonEntities` to whatever verifier list you pass.

---

## 4. `AshVault.Context` construction — normalize once, at the boundary

The two Ash context structs are different shapes, and neither is what the crypto core
should have to pattern-match:

```
Ash.Resource.Change.Context      [:actor, :tenant, :authorize?, :tracer, bulk?: false, source_context: %{}]
                                 deps/ash/lib/ash/resource/change/change.ex:289-305
Ash.Resource.Calculation.Context [:actor, :tenant, :authorize?, :tracer, :domain, :resource,
                                  :type, :constraints, :arguments, source_context: %{}]
                                 deps/ash/lib/ash/resource/calculation/calculation.ex:117-147
```

So AshVault normalizes both into one map before building `%AshVault.Context{}`:

```elixir
defmodule AshVault.Context do
  # built by these two, never by hand at a call site
  def from_changeset(changeset, field, ash_change_context)
  def from_calculation(resource, field, ash_calculation_context)
end
```

The normalized `ash_context` is a plain map:

```elixir
%{tenant: tenant, actor: actor, source_context: source_context, phase: :write | :read}
```

**Three traps, all verified:**

1. **`source_context` is stale in a change.** It is snapshotted once during
   `for_create`/`for_update` (`deps/ash/lib/ash/changeset/changeset.ex:3552-3573`); only
   `tenant` is refreshed per change. Anything a caller sets with
   `Ash.Changeset.set_context/2` afterwards never reaches `change/3`. Therefore the encrypt
   change MUST rebuild it inside the hook:
   `%{context | source_context: changeset.context}` (ash_cloak does this at
   `deps/ash_cloak/lib/ash_cloak/changes/encrypt.ex:12-14`).
2. **Prefer `changeset.tenant` on the write path.** It is authoritative and current.
   On the read path use `context.tenant`, falling back to
   `context.source_context[:private][:tenant]` — the calculation builder itself uses that
   fallback (`deps/ash/lib/ash/query/calculation.ex:117-126`).
3. **`Context.tenant` is the RAW tenant, never `Ash.ToTenant`-normalized**
   (`deps/ash/lib/ash/changeset/changeset.ex:5472-5474`). It may be a whole
   `%Organization{}` struct. `AshVault.Scopes.AshTenant.resolve!/1` is responsible for
   normalizing it to a stable binary scope key — and must do so via `Ash.ToTenant.to_tenant/2`
   when the resource is available, falling back to its own rules.

**No default context.** ash_cloak declares `context \\ nil` on `do_encrypt/4` and
`encrypt_and_set/4` (`deps/ash_cloak/lib/ash_cloak.ex:66,93`), so a direct call reaches the
vault with no tenant at all. For AshVault a missing tenant is not a fallback, it is
`AshVault.Errors.MissingScope`. Context is a **required** argument everywhere.

---

## 5. Plaintext serialization format — explicit, versioned

ash_cloak decides its format by comparing `dumped !== value` and smuggles a
`:__ash_cloak__` atom tag into the term (`deps/ash_cloak/lib/ash_cloak.ex:114-148`). That
heuristic exists only for byte-compatibility with its own older data. AshVault is greenfield,
so it uses an explicit header and one code path.

**Binding format (the bytes handed to `vault.encrypt!/2`):**

```
<<"AVP", 1::8, term_to_binary(dumped)::binary>>
```

- `"AVP"` = AshVault Plaintext, `1` = plaintext format version.
- `dumped` is **always** `Ash.Type.dump_to_embedded(type, value, constraints)`, for every
  type — scalars, arrays, embedded resources, unions alike. Ash dispatches `{:array, t}`
  to `dump_to_embedded_array/2` and recurses for nested arrays
  (`deps/ash/lib/ash/type/type.ex:1649-1657`), so no array-specific code is needed.
- Type and constraints come from `Ash.Resource.Info.calculation(resource, plain_field)`,
  **not** `attribute/2` — the attribute no longer exists after the transformer runs.
- A dump failure raises `AshVault.Errors.SerializationFailed` (a new error module; add it
  alongside the CORE_SPEC taxonomy) naming resource, field and type.

**Decode:**

1. Match the `"AVP", 1` header; anything else -> `AshVault.Errors.UnsupportedEnvelope`
   (the plaintext format version, distinct from the ciphertext envelope version — include
   `layer: :plaintext` in the error fields).
2. Reject a compressed ETF payload before decoding: a term beginning `<<131, 80, _::binary>>`
   is refused with `AshVault.Errors.InvalidCiphertext`. We never write compressed terms, and
   `:safe` does **not** stop a decompression bomb. (This mirrors ash_cloak's fix for
   CVE-2026-81319, `deps/ash_cloak/lib/ash_cloak/calculations/decrypt.ex:39-47`.)
3. `Ash.Helpers.non_executable_binary_to_term(binary, [:safe])`
   (`deps/ash/lib/ash/helpers.ex:594-598`) — blocks atom interning and funs/refs/ports.
4. `Ash.Type.cast_from_embedded(type, dumped, constraints)`.

**Storage encoding.** Hand the raw envelope binary to the `:binary` attribute and let Ash
handle encoding. Since Ash 3.26 `Ash.Type.Binary` base64s on its own inside embedded
resources (`deps/ash/lib/ash/type/binary.ex:52-66`), so AshVault does **not** add its own
conditional base64. ash_cloak's `embedded_binary_handles_encoding?/1`
(`deps/ash_cloak/lib/ash_cloak.ex:150-155`) is a version-straddling shim producing two
different on-disk formats for one field; we do not reproduce it. Document that AshVault
requires ash >= 3.26 for encrypted attributes on embedded resources.

**nil handling.** Section-level `encrypt_nil?` (default `true`), overridable per field.
`true` -> nil is encrypted, the column is never NULL. `false` -> store SQL NULL and map
`nil -> nil` on read. Document the tradeoff explicitly: with `encrypt_nil?: true` you cannot
distinguish "unset" from "encrypted nil" without a key; with `false` you leak presence.

---

## 6. Write integration — `AshVault.Changes.Encrypt`

```elixir
def change(changeset, opts, context) do
  Ash.Changeset.before_action(changeset, fn changeset ->
    field = opts[:field]
    ctx = AshVault.Context.from_changeset(changeset, field, %{context | source_context: changeset.context})

    case Ash.Changeset.fetch_argument(changeset, field) do
      {:ok, value} -> AshVault.encrypt_and_set(changeset, field, value, ctx)
      :error -> changeset
    end
  end)
end
```

- Encryption happens in `before_action`, not at `change/3` time.
- The value comes from the **argument** the transformer created, never an attribute.
- `:error` (argument absent) leaves the changeset alone, so a partial update does not clobber
  existing ciphertext.
- `encrypt_and_set/4` then:
  `force_change_attribute(:"encrypted_#{field}", blob)` (the target is `public?: false`, so
  `force_change_attribute` not `change_attribute`), then scrubs the plaintext out of
  `changeset.arguments` and `changeset.params`.
  `String.to_existing_atom("encrypted_#{field}")` is safe only because the transformer minted
  that atom at compile time — keep the naming scheme in exactly one place
  (`AshVault.encrypted_field_name/1`) and use it on both sides.

**`atomic/3`:** implement it, and make it do the *same* scrubbing story as `change/3`.
ash_cloak's atomic path skips scrubbing entirely
(`deps/ash_cloak/lib/ash_cloak/changes/encrypt.ex:22-41`), leaving plaintext in
`changeset.arguments`. Since the crypto runs in the BEAM either way and the ciphertext is
embedded as a literal, prefer returning `{:not_atomic, reason}` when we cannot scrub safely
rather than shipping the weaker path. Decide by test: if `{:atomic, %{...}}` with a scrubbed
changeset is achievable, do that; otherwise `{:not_atomic, "AshVault encrypts in the BEAM"}`.
Whichever you pick, a test must assert plaintext is absent from `changeset.arguments`
and `changeset.params` on **both** paths.

**Errors.** A raise from inside `before_action` becomes an unhelpful 500. Wrap the crypto
call and convert to an Ash error:
`Ash.Changeset.add_error(changeset, error)` for every `AshVault.Errors.*`, so
`MissingScope`, `KeyDestroyed`, and `ProviderUnavailable` surface as ordinary Ash errors on
the changeset.

---

## 7. Read integration — `AshVault.Calculations.Decrypt`

```elixir
def load(_query, opts, _context), do: [opts[:field]]

def calculate([%resource{} | _] = records, opts, context) do
  plain_field = opts[:plain_field]
  %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(resource, plain_field)
  ctx_base = AshVault.Context.from_calculation(resource, plain_field, context)
  vault = AshVault.Info.vault!(resource, context)

  Enum.reduce_while(records, {:ok, []}, fn record, {:ok, acc} ->
    case Map.get(record, opts[:field]) do
      nil -> {:cont, {:ok, [nil | acc]}}
      blob ->
        case AshVault.decrypt_value(vault, blob, ctx_base, type, constraints) do
          {:ok, value} -> {:cont, {:ok, [value | acc]}}
          {:error, error} -> {:halt, {:error, error}}
        end
    end
  end)
  |> case do
    {:ok, acc} -> {:ok, Enum.reverse(acc)}
    {:error, error} -> {:error, error}
  end
end

def calculate([], _, _), do: {:ok, []}
```

- `load/3` returning `[:"encrypted_#{field}"]` is the entire dependency declaration. Ash then
  auto-selects that attribute even though it is `public?: false` — `ensure_selected/2` does
  not consult `public?` (`deps/ash/lib/ash/query/query.ex:1878-1890`, dependency resolution
  at `deps/ash/lib/ash/actions/read/calculations.ex:1410-1421`). Ash also records it in
  `query.context[:private][:depended_on_fields]` and strips it from the returned record, so
  the ciphertext does not leak into results the caller did not ask for.
- **Return `{:error, %AshVault.Errors.*{}}`, never raise.** This is a deliberate departure
  from ash_cloak, which raises throughout its crypto path because Cloak's API is bang-only.
  AshVault's errors are Splode errors with `class: :invalid`, so Ash wraps them correctly.
  A destroyed tenant must produce a clean `KeyDestroyed` error from `Ash.read`, not a 500.
- The calculation is `filterable?: false, sortable?: false` — randomized AEAD ciphertext
  cannot support either. That is a documented limitation, and the reason searchable fields
  need lookup tokens.
- Do **not** re-implement authorization. If a read reaches this calculation, Ash has already
  authorized it. Field policies apply to the calculation like any other field.

---

## 8. Lifecycle actions

```elixir
defmodule AshVault.Actions.RotateKey do
  use Ash.Resource.Actions.Implementation

  def run(input, _opts, context) do
    ctx = AshVault.Context.from_action_input(input, context)
    vault = AshVault.Info.vault!(input.resource, context)
    scope = AshVault.Info.scope_module(input.resource).resolve!(ctx)
    AshVault.rotate_key!(vault, scope)
  end
end
```

`AshVault.Actions.DestroyKeys` is the same shape calling `destroy_keys!/2`. Both return
Ash-idiomatic `{:ok, term}` / `{:error, term}`, and both are ordinary generic actions, so
policies and actors work normally. They are only generated when `scope_owner? true`.

---

## 9. Backfill — `mix ash_vault.backfill`

```
mix ash_vault.backfill MyApp.Accounts.User email --from legacy_email --batch-size 500 --tenant acme
```

Flow per §20 (expand / backfill / cut over / contract):

1. Read a batch ordered by primary key, filtered to rows where the encrypted column is NULL.
2. For each row, read the plaintext from `--from` (or the `backfill_from` DSL option),
   encrypt, and update **only** the encrypted column via a bulk update.
3. Commit per batch. **No giant transaction.**
4. Record progress by primary key so a re-run resumes where it stopped; the NULL filter makes
   it idempotent regardless.
5. `--verify` mode re-reads a sample, decrypts, and compares to the plaintext column.
6. Report progress to stdout: rows done, rows remaining, rate, ETA.
7. `--tenant` is required when the scope is `:tenant`; iterate tenants with `--all-tenants`
   taking a module/function that lists them.

Schema migrations (adding `encrypted_email`) need no keys and stay ordinary Ash/Ecto
migrations. Only the data backfill needs the app runtime and a reachable provider — say so
in the guide, and make the task fail fast with `ProviderUnavailable` rather than writing
half a table.

---

## 10. Post-v1, specified but NOT implemented now

Searchable fields (`searchable?`, `unique?`) generate `<field>_lookup` holding
`HMAC-SHA256(per-scope lookup key, normalized plaintext)`, with the lookup key derived from
the scope key via HKDF with a distinct info string so it is never the encryption key itself.
Deterministic encryption is explicitly **not** the mechanism. The v1 verifier rejects these
options with a clear "not implemented in v1" message rather than silently accepting them.

`AshVault.KeyCache` is also post-v1; see docs/threat-model.md for the constraint that makes
it dangerous (it must be evicted synchronously before `destroy_keys!/2` returns).

---

## 11. Tests for this layer

Resource-level, against a real PostgreSQL via `ash_postgres` (container `foundrybox-postgres-1`
is already running on 5432):

- create with an encrypted attribute; `Ash.read` returns plaintext
- raw SQL (`Postgrex` direct query) shows the column contains neither the plaintext nor any
  substring of it, and starts with the `"AV"` envelope magic
- update one encrypted field leaves the others' ciphertext byte-identical
- partial update (field not in params) does not clobber ciphertext
- nil with `encrypt_nil?: true` -> non-NULL column; with `false` -> SQL NULL, reads back nil
- embedded resource attribute round-trips
- array-of-scalar and array-of-embedded attributes round-trip
- field policy denying the decrypted field blocks it while leaving other fields readable
- tenant flows: two tenants, each reads its own value
- cross-tenant ciphertext substitution (UPDATE the row's blob to the other tenant's) ->
  `CiphertextIntegrityFailed`
- cross-field substitution (copy `encrypted_ssn` into `encrypted_email`) -> `CiphertextIntegrityFailed`
- plaintext absent from `changeset.arguments` and `changeset.params` after the change runs,
  on both the `change/3` and atomic paths
- destroyed scope -> `Ash.read` returns `KeyDestroyed`, not a raised exception and not a 500
- `mix ash_vault.backfill` on a table with existing plaintext: ciphertext appears, values
  round-trip, second run is a no-op

---

## 12. Addendum — verified API corrections (these supersede anything above)

Sourced from ash 3.33.9 / spark 2.7.3 in `deps/`.

1. **`Spark.Dsl.Transformer.add_entity/4` PREPENDS by default.** Every Ash builder passes
   `type: :append`. `AshVault.Transformers.ExpandAttributes` must pass
   `type: :append` too, or the `attributes [...]` sugar silently reverses field order
   relative to explicit `encrypt` entities (`deps/spark/lib/spark/dsl/transformer.ex:273`).

2. **`replace_entity/4` uses `Map.replace_lazy`** — it is a silent no-op when the section
   path key is not already present in the DSL state (`transformer.ex:372`). After rewriting
   actions, assert in a test that the change actually landed on the action; do not assume.

3. **Field policies apply to the generated calculation, and a forbidden field becomes
   `%Ash.ForbiddenField{}`, not nil and not an error**
   (`deps/ash/lib/ash/policy/authorizer/authorizer.ex:384-411, 1548-1556`). Two consequences:
   - The decrypt calculation must handle `Map.get(record, :"encrypted_#{field}")` returning
     `%Ash.ForbiddenField{}` and pass it straight through rather than trying to decrypt it.
   - Field policies must use filter or simple checks only; anything else raises
     `Ash.Error.Forbidden` ("Field policies must currently use only filter checks or simple
     checks"). Say this in the policies guide.
   - Calculations are first-class field-policy targets; relationships are not.

4. **`Ash.Resource.Calculation.Context` already carries `:type` and `:constraints`** — the
   calculation's own declared type/constraints. Prefer re-introspecting via
   `Ash.Resource.Info.calculation/2` anyway (version-robust, and it is what the write path
   must do since it has no such context), but a test should assert the two agree.

5. **Calculations have a `multitenancy:` option** (`:enforce` default, `:allow_global`,
   `:bypass`, `:bypass_all`) — `deps/ash/lib/ash/resource/calculation/calculation.ex:105-114`.
   Leave it at `:enforce` for the decrypt calculation; note it in the docs as the escape
   hatch for a resource that intentionally decrypts across tenants.

6. **Generic actions:** `run:` takes
   `{:spark_function_behaviour, Ash.Resource.Actions.Implementation, {Ash.Resource.Action.ImplementationFunction, 2}}`
   — a module, `{module, opts}`, or a **2-arity** fun in the DSL literal form, while the
   module callback is **`run/3`** (`input, opts, context`). The implementation context is
   `Ash.Resource.Actions.Implementation.Context`:
   `[:actor, :tenant, :authorize?, :domain, :tracer, source_context: %{}]` — note it has
   `:domain` but no `:resource`, so take the resource from `input.resource`.
   `allow_nil?` on a generic action defaults to **false** (unlike attributes) — set
   `allow_nil?: true` or `returns:` appropriately on the lifecycle actions.

7. **All Ash callback `Context` structs implement `Ash.Scope.ToOpts`**
   (`deps/ash/lib/ash/scope.ex:164-187`), so `scope: context` can be forwarded to nested Ash
   calls. But `Ash.Scope`'s own moduledoc says extensions should not accept a `scope:` option
   in their DSL — consume the `Context` instead. AshVault's DSL has no `scope:` opt in that
   sense; its `scope` option names a scope *module*, which is a different thing. Make sure the
   docs do not confuse the two — consider documenting it as "key scope".

8. **`Ash.Context.to_opts/2` is deprecated** in favour of `Ash.Scope.to_opts/2`. Do not use
   the deprecated one.

9. **There is no `Ash.Changeset.get_tenant/1`.** Use the struct fields: `changeset.tenant`
   (raw) and `changeset.to_tenant` (normalized through the `Ash.ToTenant` protocol,
   `deps/ash/lib/ash/to_tenant.ex:5-31`). `AshVault.Scopes.AshTenant` should call
   `Ash.ToTenant.to_tenant(tenant, resource)` and then stringify, so a tenant struct and its
   id produce the same scope key. There is likewise no `Ash.Changeset.get_actor/1`; take the
   actor from the callback `Context` struct, never from `changeset.context[:private]`.

10. **`Ash.Resource.Info.attribute/2` and `calculation/2` accept raw `dsl_state`**, so they
    work inside transformers and verifiers (`deps/ash/lib/ash/resource/info.ex:857`).

11. **`use Ash.Resource.Change` raises at compile time** unless at least one of `change/3`,
    `batch_change/3`, `atomic/3` is defined. `atomic/3`'s `{:not_atomic, String.t()}` return
    is legitimate and is the safe answer when scrubbing cannot be guaranteed.

12. **`Ash.Resource.Calculation.calculate/3` may return** `{:ok, list}`, a bare `list`,
    `{:error, term}`, or `:unknown`; anything else raises
    `Ash.Error.Framework.InvalidReturnType` (`calculation.ex:261-275`). Return `{:error, _}`
    for crypto failures — never `:unknown`, which means "fall back to the data layer".

13. **Backing attribute options** available on `add_attribute/4` include `select_by_default?`
    and `always_select?` (`deps/ash/lib/ash/resource/attribute.ex:63-175`). Leave both at
    their defaults — the calculation's `load/3` dependency is what pulls the column in, and
    Ash strips it from results afterwards via `depended_on_fields`.
