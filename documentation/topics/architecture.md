# Architecture

AshVault is five layers. Each one has a behaviour, a default implementation, and exactly
one job.

```
Ash resource
  └─ AshVault (Spark extension)          transformers rewrite the resource
       ├─ AshVault.Changes.Encrypt       write path  (before_action / atomic)
       └─ AshVault.Calculations.Decrypt  read path   (calculation)
            │
            ▼
       AshVault.Vault                    bundles the five components below
            ├─ AshVault.Scope            operation → scope key  (a binary)
            ├─ AshVault.KeyProvider      scope → key material, rotation, erasure
            ├─ AshVault.Cipher           (plaintext, key, aad) → (ciphertext, nonce, tag)
            ├─ AshVault.Envelope         payload → the bytes stored in the column
            └─ AshVault.RotationPolicy   should this write rotate first?
```

Everything below `AshVault.Vault` is plain Elixir with no Ash dependency at runtime. You
can use a vault directly — `MyApp.Vault.encrypt!/2` — without Ash in the picture at all.

## The extension layer

`use Ash.Resource, extensions: [AshVault]` plus an `ash_vault` section replaces every
encrypted attribute at compile time. For `encrypt :email`,
`AshVault.Transformers.SetupEncryption`:

1. **removes** the `:email` attribute entity from the resource,
2. adds an `encrypted_email` `:binary` attribute — `sensitive?: true`, `public?: false`,
   `allow_nil?: true`,
3. adds an `:email` calculation of the original type, running
   `AshVault.Calculations.Decrypt`, `filterable?: false, sortable?: false`,
4. rewrites every `:create`/`:update`/`:destroy` action that accepted `:email` so it takes
   an `:email` *argument* of the original type (`sensitive?: true`) plus an
   `AshVault.Changes.Encrypt` change, and drops `:email` from `accept`.

Removing the attribute entity is *the* non-persistence mechanism. There is no plaintext
column, so no data layer can write one — this does not rely on `private?`, on scrubbing,
or on anyone remembering to omit a field.

> #### The backing column is always nullable {: .info}
>
> The `encrypted_<field>` attribute is `allow_nil?: true` regardless of the original
> attribute's nullability. With `encrypt_nil?: false` a `nil` value legitimately stores SQL
> NULL, and an `allow_nil?: false` column would reject it. Real nullability is enforced by
> the calculation's `allow_nil?` and the action argument's `allow_nil?` instead.

### Write path

`AshVault.Changes.Encrypt` runs in a `before_action` hook, not at `change/3` time, and
reads the **argument** (there is no attribute to read). If the argument is absent the
changeset is untouched, so a partial update never clobbers existing ciphertext.

`AshVault.encrypt_and_set/4` then force-changes the backing attribute and scrubs the
plaintext out of `changeset.arguments` and `changeset.params` — without that, plaintext
survives in `inspect` output, telemetry and error reports long after encryption.

`atomic/3` is implemented too, returning the three-element
`{:atomic, changeset, %{encrypted_email => blob}}` form so the scrubbed changeset comes
back as well. Both paths scrub.

Crypto failures are converted to `Ash.Changeset.add_error/2`, so `MissingScope`,
`KeyDestroyed` and `ProviderUnavailable` surface as ordinary Ash errors rather than a
raise from inside a hook.

### Read path

The `load/3` callback of `AshVault.Calculations.Decrypt` returns `[:encrypted_email]`,
and that single line is the whole dependency declaration. Ash selects the backing attribute even though it is
`public?: false`, records it in `query.context[:private][:depended_on_fields]`, and strips
it from the returned record — ciphertext does not leak into results nobody asked for.

The calculation returns `{:error, %AshVault.Errors.KeyDestroyed{}}` rather than raising, so
a crypto-erased tenant comes out of `Ash.read/2` as a clean error and not a 500. It never
returns `:unknown`, which to Ash means "fall back to the data layer" — for an encrypted
field that would silently yield ciphertext or nil.

A field policy denying the field makes the backing value `%Ash.ForbiddenField{}`, which is
passed through untouched. AshVault performs no authorization of its own: if a read reached
the calculation, Ash already authorized it.

## The plaintext format (AVP)

Before anything is encrypted, the value is serialized by `AshVault.Serializer`:

```
<<"AVP", 1::8, :erlang.term_to_binary(dumped)::binary>>
```

`dumped` is always `Ash.Type.dump_to_embedded/3` of the value — for scalars, arrays,
arrays of embedded resources, embedded resources and unions alike. One code path, one
on-disk shape. Type and constraints are read from
`Ash.Resource.Info.calculation(resource, field)`, *not* `attribute/2`, because the
attribute no longer exists after the transformer runs.

Decoding is paranoid on purpose: the magic and version must match, a compressed external
term (`<<131, 80, ...>>`) is refused outright (`:safe` does not stop a decompression bomb),
and decoding goes through Ash's `non_executable_binary_to_term/2` helper with `:safe`,
which blocks atom interning and funs/refs/ports.

## The envelope, and why it carries the key version

`AshVault.Envelope.V1` is the wire format written to the column:

```
<<"AV",                              # magic
  1          :: 8,                   # envelope version
  cid_len    :: 8,
  cipher_id  :: binary-size(cid_len),  # e.g. "aes_256_gcm_v1"
  key_version:: 32-unsigned-big,
  nonce_len  :: 8,
  nonce      :: binary-size(nonce_len),
  tag_len    :: 8,
  tag        :: binary-size(tag_len),
  ciphertext :: binary>>
```

Three fields in that header each buy something specific:

* **cipher id** — decryption looks the cipher back up through `AshVault.Cipher.fetch/1`,
  so a value is always decrypted with the cipher that wrote it, even after the vault's
  default cipher changes. The registry is keyed by the *binary* id, exactly what the
  envelope stores, so the encode and decode directions cannot drift.
* **envelope version** — `AshVault.Envelope.decode/1` peeks the version byte and
  dispatches, so values written by older builds keep decoding.
* **key version** — this is what makes rotation without re-encryption possible. Rotating a
  scope's key mints version *n+1* and leaves every existing row alone; each row says which
  version opens it. It is also what makes per-scope erasure legible: destroying the scope
  destroys every version at once, and the error names the version that was needed.

`decode/1` is total. Any binary — truncated, foreign, empty — produces
`{:error, %AshVault.Errors.InvalidCiphertext{}}` or
`{:error, %AshVault.Errors.UnsupportedEnvelope{}}`, never an exception.

## The AAD, and what it binds

```elixir
"ashvault:v1|" <> scope <> "|" <> inspect(resource) <> "|" <> to_string(field)
```

This format is frozen. It is a stable, human-inspectable binary rather than
`:erlang.term_to_binary/1`, because term encoding is not guaranteed stable across OTP
releases and ciphertext has to outlive OTP upgrades.

Binding scope, resource and field into the authentication tag means a ciphertext cannot be
relocated: pasting tenant A's `encrypted_email` into tenant B's row, or `encrypted_ssn`
into `encrypted_email`, or a `users` blob into `contacts`, fails authentication with
`AshVault.Errors.CiphertextIntegrityFailed` rather than silently decrypting into the wrong
place.

The `inspect(resource)` in there is a deliberate tradeoff: renaming a resource module
invalidates its existing ciphertext. If you rename, re-encrypt first.

## `AshVault.Context` — what it is and is not

```elixir
%AshVault.Context{resource: module(), field: atom(), ash_context: map() | struct() | nil}
```

It **is** the non-secret identity of one encrypt-or-decrypt operation: which resource,
which field, and an opaque bag of Ash-supplied information from which the scope is
resolved.

It **is not**:

* a carrier of key material, plaintext or ciphertext — it never holds any of the three;
* `Ash.Scope`. The `scope` option in the `ash_vault` DSL names an `AshVault.Scope`
  *module* — the **key** scope. That is a different thing from `Ash.Scope`/`Ash.Scope.ToOpts`,
  which is Ash's mechanism for forwarding actor/tenant to nested calls. They share a word
  and nothing else.
* something you build by hand. `AshVault.Context.Builder` is the only place contexts are
  constructed — `from_changeset/3` on the write path, `from_calculation/3` on the read
  path, `from_action_input/2` for the `key_lifecycle` generic actions. Each normalizes its
  Ash callback struct into one plain map:

```elixir
%{tenant: tenant, actor: actor, source_context: source_context, phase: :write | :read}
```

That normalization exists because the two Ash callback structs are different shapes, and
because of three traps:

1. `source_context` is **stale** inside a change — it is snapshotted during
   `for_create`/`for_update`, so anything a caller sets with `Ash.Changeset.set_context/2`
   afterwards never reaches `change/3`. The encrypt change rebuilds it from
   `changeset.context` inside the hook.
2. On the write path `changeset.tenant` wins (authoritative and current); on the read path
   the calculation context's `:tenant` wins, falling back to
   `source_context[:private][:tenant]`.
3. The tenant here is the **raw** tenant, never `Ash.ToTenant`-normalized — it may be a
   whole `%Organization{}` struct. Normalizing it to a stable binary is
   `AshVault.Scopes.AshTenant`'s job. See
   [Tenant-scoped encryption](tenant-scoped-encryption.md).

There is no `context \\ nil` default anywhere in AshVault. A missing tenant is not a
fallback to a global key; it is `AshVault.Errors.MissingScope`.

## Where errors come from

| Layer | Errors it can produce |
|---|---|
| Serializer | `SerializationFailed`, `UnsupportedEnvelope` (`layer: :plaintext`), `InvalidCiphertext` |
| Scope | `MissingScope`, `InvalidScope` |
| Key provider | `KeyDestroyed`, `KeyNotFound`, `ProviderUnavailable` |
| Cipher | `CiphertextIntegrityFailed`, `KeySizeMismatch` |
| Envelope | `InvalidCiphertext`, `UnsupportedEnvelope`, `UnsupportedCipher` |

`AshVault.Vault.Runtime` is the single place raw provider error terms are mapped onto those
structs, which is how `:destroyed`, `:not_found` and a transport failure stay three
distinguishable things. See [Operations](operations.md) for what to do about each.

## Related

* [Tenant-scoped encryption](tenant-scoped-encryption.md)
* [Rotation](rotation.md)
* [Crypto-erasure](crypto-erasure.md)
* [Threat model](threat-model.md)
