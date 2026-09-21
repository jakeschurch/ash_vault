# AshVault crypto core — authoritative spec (v1)

Binding decisions. Implementations MUST match exactly; tests assert on these bytes.

## Module list (crypto core, no Ash dependency at runtime)

    lib/ash_vault/errors.ex
    lib/ash_vault/context.ex
    lib/ash_vault/cipher.ex
    lib/ash_vault/ciphers/aes_gcm.ex
    lib/ash_vault/envelope.ex
    lib/ash_vault/key_provider.ex
    lib/ash_vault/key_providers/memory.ex
    lib/ash_vault/scope.ex
    lib/ash_vault/rotation_policy.ex
    lib/ash_vault/vault.ex

## 1. Errors (`AshVault.Errors`)

Each error is its own module, built with Splode (splode is already a dependency via ash).
Pattern for every error module:

```elixir
defmodule AshVault.Errors.KeyDestroyed do
  use Splode.Error, fields: [:scope, :key_version, :resource, :field], class: :invalid

  def message(%{scope: scope, key_version: v}) do
    """
    Encryption key for scope #{inspect(scope)} (version #{inspect(v)}) has been destroyed.

    This data was cryptographically erased and cannot be recovered.
    """
  end
end
```

Modules (all under `AshVault.Errors.`), with fields:

| Module | fields | class | meaning |
|---|---|---|---|
| `MissingScope` | `:resource, :field, :scope_module, :reason` | `:invalid` | scope could not be resolved (e.g. no tenant) |
| `KeyNotFound` | `:scope, :key_version` | `:invalid` | provider has no such key, and no tombstone |
| `KeyDestroyed` | `:scope, :key_version` | `:invalid` | key deliberately destroyed (crypto-erasure) |
| `ProviderUnavailable` | `:provider, :reason` | `:invalid` | transport/backend failure — retryable |
| `AuthenticationFailed` | `:resource, :field, :key_version` | `:invalid` | AEAD tag mismatch: tampering, wrong AAD, wrong key |
| `UnsupportedEnvelope` | `:version` | `:invalid` | envelope version this build cannot parse |
| `UnsupportedCipher` | `:cipher_id` | `:invalid` | cipher id not in registry |
| `InvalidCiphertext` | `:reason` | `:invalid` | malformed/truncated/not-an-envelope bytes |

`MissingScope.message/1` must produce the operator-facing text:

```
Cannot encrypt <Resource>.<field> because no Ash tenant was present.

This resource uses tenant-scoped encryption.
Pass a tenant when executing the Ash action or configure another AshVault scope.
```

Rule: **never** let `{:error, :destroyed}` surface as `AuthenticationFailed`. Destroyed is checked before decrypt.

## 2. `AshVault.Context`

```elixir
defmodule AshVault.Context do
  @enforce_keys [:resource, :field]
  defstruct [:resource, :field, :ash_context]
  @type t :: %__MODULE__{resource: module(), field: atom(), ash_context: map() | struct() | nil}
end
```

No crypto data in it, ever.

`ash_context` holds the **raw Ash context struct** — `Ash.Resource.Change.Context` or
`Ash.Resource.Calculation.Context`. Verified field lists in ash 3.33.9:

    Ash.Resource.Change.Context:      [:actor, :tenant, :authorize?, :tracer, bulk?: false, source_context: %{}]
    Ash.Resource.Calculation.Context: [:actor, :tenant, :authorize?, :tracer, :domain, :resource, :type, :constraints, :arguments, source_context: %{}]

So `tenant` is a **top-level struct field**, not a key inside a nested map. The crypto core
must assume no more than "it is a map, a struct, or nil" and must never require a specific
struct module (a plain map works in tests).

## 3. `AshVault.Cipher`

```elixir
@type payload :: %{ciphertext: binary(), nonce: binary(), tag: binary()}
@callback id() :: atom()   # atom for ergonomics; the registry is keyed by Atom.to_string(id())
@callback key_bytes() :: pos_integer()
@callback encrypt(plaintext :: binary(), key :: binary(), aad :: binary()) :: {:ok, payload} | {:error, term}
@callback decrypt(payload, key :: binary(), aad :: binary()) :: {:ok, binary()} | {:error, term}
```

Also in `AshVault.Cipher`: a registry for envelope decoding.

```elixir
@builtin %{aes_256_gcm_v1: AshVault.Ciphers.AES.GCM}
def fetch(id_atom_or_binary) :: {:ok, module} | {:error, %AshVault.Errors.UnsupportedCipher{}}
```

**The registry MUST be keyed by the BINARY id, not the atom** — the envelope decodes
`cipher` as a binary, and encode writes `to_string(cipher.id())`. Keying by binary makes it
impossible for the two directions to drift:

```elixir
@builtin %{"aes_256_gcm_v1" => AshVault.Ciphers.AES.GCM}
def fetch(id) when is_binary(id)   # map lookup
def fetch(id) when is_atom(id), do: fetch(Atom.to_string(id))
```

Extra ciphers merge in from `Application.get_env(:ash_vault, :ciphers, %{})` (also
binary-keyed). Unknown id -> `{:error, %AshVault.Errors.UnsupportedCipher{cipher_id: id}}`.
`String.to_atom/1` MUST NOT be called on decoded input anywhere.

### `AshVault.Ciphers.AES.GCM`

- `id()` -> `:aes_256_gcm_v1`
- `key_bytes()` -> `32`
- nonce: 12 bytes from `:crypto.strong_rand_bytes/1`, fresh per encryption.
- tag: 16 bytes.
- `:crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, true)` -> `{ct, tag}`
- decrypt: same with `false`; `:error` return maps to `{:error, :auth_failed}`.
- Reject a key whose byte_size /= 32 with `{:error, {:invalid_key_size, n}}`.
- No nonce/tag-size options exposed.

## 4. `AshVault.Envelope`

Behaviour:

```elixir
@callback version() :: pos_integer()
@callback encode(map()) :: binary()
@callback decode(binary()) :: {:ok, map()} | {:error, Exception.t()}
```

`AshVault.Envelope` is also the dispatcher: `decode/1` peeks the version byte and
routes to the right module; unknown version -> `AshVault.Errors.UnsupportedEnvelope`.

### V1 wire format (`AshVault.Envelope.V1`) — BINDING

```
<<"AV",                          # 2-byte magic
  1        :: 8,                 # envelope version
  cid_len  :: 8,                 # cipher id length
  cipher_id:: binary-size(cid_len),   # e.g. "aes_256_gcm_v1"
  key_ver  :: 32-unsigned-big,
  nonce_len:: 8,
  nonce    :: binary-size(nonce_len),
  tag_len  :: 8,
  tag      :: binary-size(tag_len),
  ciphertext :: binary>>          # remainder
```

Decoded map: `%{version: 1, cipher: <binary id>, key_version: integer, nonce: bin, tag: bin, ciphertext: bin}`.

Decode rules:
- wrong magic, trailing-length mismatch, truncation, or empty input -> `AshVault.Errors.InvalidCiphertext`
- good magic but unknown version byte -> `AshVault.Errors.UnsupportedEnvelope`
- `decode/1` must be total: never raise on arbitrary binaries, always return a tagged tuple.
- `encode/1` accepts the cipher id as an atom OR binary and stores it as a binary.

## 5. `AshVault.KeyProvider`

```elixir
@type scope :: term()
@type version :: non_neg_integer()
@type key_info :: %{version: version, key: binary(), created_at: DateTime.t()}

@callback current_key(scope) :: {:ok, key_info} | {:error, term}
@callback get_key(scope, version) :: {:ok, binary} | {:error, :not_found} | {:error, :destroyed} | {:error, term}
@callback rotate(scope) :: {:ok, version} | {:error, term}
@callback destroy(scope) :: :ok | {:error, term}
```

Optional callback `@callback key_bytes() :: pos_integer()` (default 32) — declare `@optional_callbacks`.

`current_key/1` creates the scope's key material on first use (version 1) — callers never
"create a tenant key" explicitly.

### `AshVault.KeyProviders.Memory`

- GenServer named `AshVault.KeyProviders.Memory` (startable under a supervisor; `start_link/1` takes `name:`).
- State: `%{keys: %{scope => %{version => %{key: bin, created_at: dt}}}, current: %{scope => version}, destroyed: MapSet.t()}`
- **Tombstones are mandatory**: `destroy(scope)` wipes all key material for the scope AND records the scope in `destroyed`. After destroy, `current_key/1` and `get_key/2` BOTH return `{:error, :destroyed}` — never `:not_found`, and never silently mint a fresh key. Destroy is irreversible for the life of the process.
- `rotate/1` mints a new random key at version+1, keeps history.
- Config: `Application.get_env(:ash_vault, AshVault.KeyProviders.Memory)` may set `:key_bytes` (default 32).
- Intended for dev/test only — document that loudly in @moduledoc.

## 6. `AshVault.Scope`

```elixir
@callback resolve!(AshVault.Context.t()) :: term()
```

`AshVault.Scopes.AshTenant` resolves the tenant from `context.ash_context` in this order:

1. `Map.get(ash_context, :tenant)` — the top-level struct field on both Ash context structs
2. `get_in(ash_context, [Access.key(:source_context, %{}), :tenant])` — fallback for contexts
   whose tenant only reached `source_context`

First non-nil wins. If tenant is nil/absent -> raise `AshVault.Errors.MissingScope`
with the operator text above. Normalizes the tenant to a stable binary via
`to_scope_key/1`: binary -> itself; atom/integer -> `to_string`; struct with `:id` -> the id
stringified; otherwise raise MissingScope with `reason: :unsupported_tenant_shape`.
Scope keys MUST be stable across processes and releases (no term_to_binary of structs).

Also provide `AshVault.Scopes.Global` (constant scope `"global"`) for non-multitenant apps.

## 7. `AshVault.RotationPolicy`

```elixir
defmodule AshVault.RotationPolicy do
  defstruct strategy: :manual, max_age: nil, rotate_on_write?: false
  @type strategy :: :manual | :age | :provider
  @callback policy(scope :: term(), AshVault.Context.t()) :: t()
end
```

Helper in the same module:
`due?(%__MODULE__{}, key_info, now \\ DateTime.utc_now())` ->
- `:manual` / `:provider` -> false
- `:age` with `max_age` (an `Elixir.Duration`) -> true when `key_info.created_at` is older than now - max_age. Use `DateTime.shift/2` (Elixir 1.17+) and `DateTime.compare/2`.

Default policy module `AshVault.RotationPolicies.Manual` returns `%RotationPolicy{strategy: :manual}`.

## 8. `AshVault.Vault`

`use AshVault.Vault, key_provider: M, cipher: M, envelope: M, scope: M, rotation_policy: M`

Defaults: cipher `AshVault.Ciphers.AES.GCM`, envelope `AshVault.Envelope.V1`,
scope `AshVault.Scopes.AshTenant`, rotation_policy `AshVault.RotationPolicies.Manual`.
`key_provider` is REQUIRED — raise at compile time with a clear message if absent.

Generated module implements `@behaviour AshVault.Vault`:

```elixir
@callback encrypt!(binary(), AshVault.Context.t()) :: binary()
@callback decrypt!(binary(), AshVault.Context.t()) :: binary()
@callback rotate!(scope :: term()) :: {:ok, non_neg_integer()}   # {:ok, new_version}; raises on failure
@callback destroy!(scope :: term()) :: :ok
# introspection, used by the Ash layer and tests:
@callback __ash_vault__(:key_provider | :cipher | :envelope | :scope | :rotation_policy) :: module()
```

The `use` macro delegates all logic to `AshVault.Vault.Runtime` functions taking an
opts map — keep generated code to one-line delegations (easier to debug, less bloat).

### encrypt! algorithm (Runtime)

1. `scope = scope_mod.resolve!(ctx)`
2. `{:ok, key_info} = provider.current_key(scope)` (map provider errors via `map_provider_error/3`)
3. rotation check: `policy = rotation_mod.policy(scope, ctx)`; if `policy.rotate_on_write?` and `RotationPolicy.due?(policy, key_info)` then `provider.rotate(scope)` and re-fetch `current_key`. Rotation failure must NOT fail the write — log a warning and use the existing key. (Never block a write on rotation.)
4. `aad = AshVault.Vault.Runtime.build_aad(scope, ctx)`
5. `cipher.encrypt(plaintext, key_info.key, aad)`
6. `envelope.encode(%{version: envelope.version(), cipher: cipher.id(), key_version: key_info.version, nonce: ..., tag: ..., ciphertext: ...})`

### decrypt! algorithm

1. `{:ok, env} = envelope_dispatcher.decode(blob)` (raise the returned error)
2. `{:ok, cipher_mod} = AshVault.Cipher.fetch(env.cipher)`
3. `scope = scope_mod.resolve!(ctx)`
4. `provider.get_key(scope, env.key_version)`; `{:error, :destroyed}` -> raise `KeyDestroyed`; `{:error, :not_found}` -> raise `KeyNotFound`; other -> `ProviderUnavailable`
5. `aad = build_aad(scope, ctx)`
6. `cipher_mod.decrypt(payload, key, aad)`; error -> raise `AuthenticationFailed` with resource/field/key_version

### AAD — BINDING

```elixir
def build_aad(scope, %AshVault.Context{resource: resource, field: field}) do
  "ashvault:v1|" <> to_string(scope) <> "|" <> inspect(resource) <> "|" <> to_string(field)
end
```

Deliberately a stable, human-inspectable binary rather than `:erlang.term_to_binary/1`
(term encoding is not guaranteed stable across OTP releases; ciphertext must outlive OTP upgrades).
Scope is already normalized to a binary by the Scope module.

### destroy! / rotate!

- `rotate!(scope)` -> `provider.rotate(scope)`, raise on error.
- `destroy!(scope)` -> evict cache (no cache in v1 — leave a documented hook `AshVault.KeyCache.evict_scope/1` call site commented/behind a config check), then `provider.destroy(scope)`. MUST return only after the provider confirms.

## 9. Top-level `AshVault` module (crypto-core part only)

```elixir
def rotate_key!(vault, scope), do: vault.rotate!(scope)
def destroy_keys!(vault, scope), do: vault.destroy!(scope)
```

## 10. Tests required for this layer (ExUnit, `test/ash_vault/...`)

- cipher: roundtrip; AAD mismatch fails; flipped ciphertext byte fails; flipped tag byte fails; wrong key fails; 1000 encryptions produce 1000 distinct nonces; bad key size rejected; empty plaintext roundtrips.
- envelope: roundtrip incl. empty ciphertext and large (1MB) ciphertext; decode rejects `""`, `"AV"`, truncated-at-every-prefix-length (property-ish loop) without raising; unknown version byte -> UnsupportedEnvelope; non-AV magic -> InvalidCiphertext; key_version 0 and 2^32-1 roundtrip.
- provider (Memory): first `current_key` mints v1; rotate -> v2 and v1 still fetchable; get_key unknown version -> :not_found; destroy -> current_key and get_key both :destroyed; destroy twice is idempotent; destroyed scope never re-mints.
- vault: roundtrip through a test vault; cross-scope decrypt raises AuthenticationFailed; cross-field decrypt raises AuthenticationFailed; cross-resource decrypt raises AuthenticationFailed; decrypt after destroy raises KeyDestroyed (NOT AuthenticationFailed); rotation — encrypt with v1, rotate, old blob still decrypts, new blob carries key_version 2 (assert by decoding the envelope); missing tenant raises MissingScope with the documented message.

Use `async: true` everywhere except tests sharing the named Memory provider; for those,
start a uniquely-named Memory provider per test with `start_supervised!`.


## 11. Addendum — corrections that supersede anything above

1. `AshVault.Context.ash_context` is the raw Ash context **struct** (or a plain map, or nil).
   `tenant` is a top-level field on it. See §2.
2. The cipher registry is keyed by **binary** ids. See §3.
3. `rotate!/1` returns `{:ok, new_version}` and raises on provider failure. `destroy!/1`
   returns `:ok` and raises on provider failure. The `KeyProvider` callbacks stay
   tuple-returning (`rotate/1 :: {:ok, version} | {:error, term}`, `destroy/1 :: :ok | {:error, term}`);
   only the Vault-level bang functions raise.
4. A third provider, `AshVault.KeyProviders.Local` (filesystem-backed), is specified in
   docs/LOCAL_PROVIDER_SPEC.md. It is NOT part of the crypto-core work item.
