defmodule AshVault.Lookup do
  @moduledoc """
  Deterministic lookup tokens for searchable encrypted fields.

  AES-GCM draws a fresh nonce for every write, so the same plaintext encrypts to
  different bytes every time: `WHERE encrypted_email = $1` matches nothing and a unique
  index on the ciphertext column is meaningless. A searchable field therefore carries a
  *second*, deterministic column beside the ciphertext:

      plaintext
        ├── AES-GCM → encrypted_email   (randomized, unsearchable)
        └── HMAC    → email_lookup      (deterministic, indexable)

  ## The key is not the DEK, and is not derived from it

  The token key comes from `c:AshVault.KeyProvider.lookup_key/1` — a **separate,
  non-rotating, per-scope** secret. `AshVault.rotate_key!/2` must not change it.

  If the token were derived from the rotating data encryption key, rotation would change
  every future token while every stored token still reflected the old key. Lookups for
  existing rows would silently stop matching, `unique?` would stop preventing duplicates
  and users could not log in — with nothing raised anywhere. That failure passes any test
  that writes a row and immediately reads it back, which is why
  `test/ash_vault/lookup_rotation_test.exs` asserts the provider hands back the *same*
  key binary across a rotation rather than inferring it from token equality.

  Erasure still erases: `c:AshVault.KeyProvider.destroy/1` destroys the lookup key along
  with every data key, and the same tombstone gates it afterwards.

  ## Per-field separation comes from HKDF

      lookup_key_for_field =
        HKDF-SHA256(ikm:  provider_lookup_key(scope),
                    info: "ash_vault:lookup:v1|" <> inspect(resource) <> "|" <> field)

      token = HMAC-SHA256(lookup_key_for_field, normalized_plaintext)

  Binding the resource and the field means the same plaintext in two columns, or in two
  resources, produces two unrelated tokens — so a token cannot be replayed across
  columns any more than a ciphertext can be replayed across its AAD. Binding the scope
  is what the per-scope provider key already does, and it is what keeps the equality
  leak inside one tenant.

  HKDF is not in OTP, so `hkdf/4` implements RFC 5869 extract-and-expand directly on
  `:crypto.mac/4`. It is tested against the RFC's own vectors.

  ## Rotating a lookup key is a backfill, not a rotation

  There is deliberately no `rotate_lookup_key` anywhere. Changing the lookup key — like
  changing `normalize:` — invalidates every stored token, so it is a data migration:
  destroy nothing, re-derive, and rewrite the column with `mix ash_vault.backfill
  --lookup`.
  """

  alias AshVault.Context
  alias AshVault.Errors.MissingScope

  @info_prefix "ash_vault:lookup:v1|"

  @typedoc "A normalization strategy for a searchable field."
  @type normalize :: :none | :downcase | :downcase_trim | mfa() | (term() -> term())

  # ── RFC 5869 ───────────────────────────────────────────────────────────────────

  @doc """
  HKDF-SHA256 (RFC 5869): extract-then-expand, in one call.

  `salt` may be `""`, which RFC 5869 §2.2 defines as a string of `HashLen` zeros.

  RFC 5869 Appendix A.1 (SHA-256, with salt and info) round-trips through here; the
  RFC's three SHA-256 vectors are asserted in `test/ash_vault/lookup_test.exs`.
  """
  @spec hkdf(binary(), binary(), binary(), pos_integer()) :: binary()
  def hkdf(ikm, salt, info, length)
      when is_binary(ikm) and is_binary(salt) and is_binary(info) and is_integer(length) and
             length > 0 do
    ikm |> hkdf_extract(salt) |> hkdf_expand(info, length)
  end

  @doc """
  HKDF-Extract (RFC 5869 §2.2): `HMAC-SHA256(salt, ikm)`, returning a 32-byte PRK.

  An empty `salt` is replaced by `HashLen` zero bytes, as the RFC specifies.
  """
  @spec hkdf_extract(binary(), binary()) :: binary()
  def hkdf_extract(ikm, salt \\ "") when is_binary(ikm) and is_binary(salt) do
    salt = if salt == "", do: <<0::256>>, else: salt
    :crypto.mac(:hmac, :sha256, salt, ikm)
  end

  @doc """
  HKDF-Expand (RFC 5869 §2.3).

  Raises `ArgumentError` for a `length` above `255 * HashLen`, which the RFC forbids.
  """
  @spec hkdf_expand(binary(), binary(), pos_integer()) :: binary()
  def hkdf_expand(prk, info, length)
      when is_binary(prk) and is_binary(info) and is_integer(length) and length > 0 do
    if length > 255 * 32 do
      raise ArgumentError,
            "HKDF-Expand cannot produce more than #{255 * 32} bytes of SHA-256 output, " <>
              "asked for #{length}"
    end

    n = div(length - 1, 32) + 1

    1..n
    |> Enum.reduce({<<>>, <<>>}, fn i, {previous, acc} ->
      block = :crypto.mac(:hmac, :sha256, prk, previous <> info <> <<i>>)
      {block, acc <> block}
    end)
    |> elem(1)
    |> binary_part(0, length)
  end

  # ── derivation ─────────────────────────────────────────────────────────────────

  @doc """
  The HKDF `info` string binding a token key to one resource and field.

  Frozen, human-inspectable, and built by stringification rather than
  `:erlang.term_to_binary/1` — for exactly the reason
  `AshVault.Vault.Runtime.build_aad/2` is: the external term format is not guaranteed
  stable across OTP releases, and stored tokens have to outlive OTP upgrades.

      iex> AshVault.Lookup.info(MyApp.User, :email)
      "ash_vault:lookup:v1|MyApp.User|email"
  """
  @spec info(module(), atom()) :: binary()
  def info(resource, field) when is_atom(resource) and is_atom(field) do
    @info_prefix <> inspect(resource) <> "|" <> to_string(field)
  end

  @doc """
  Derive the 32-byte token key for one resource/field from a provider lookup key.
  """
  @spec derive_field_key(binary(), module(), atom()) :: binary()
  def derive_field_key(lookup_key, resource, field) when is_binary(lookup_key) do
    hkdf(lookup_key, "", info(resource, field), 32)
  end

  @doc """
  `HMAC-SHA256(field_key, normalized_plaintext)` — the stored token.
  """
  @spec token(binary(), binary()) :: binary()
  def token(field_key, normalized) when is_binary(field_key) and is_binary(normalized) do
    :crypto.mac(:hmac, :sha256, field_key, normalized)
  end

  # ── normalization ──────────────────────────────────────────────────────────────

  @doc """
  Apply a field's `normalize:` strategy to a plaintext value.

  Returns `{:ok, normalized}`, or `{:error, reason}` when the strategy produced
  something that is not a binary — which is a bug in a custom normalizer, not a user
  error, and must not be papered over with `to_string/1`.

  `nil` passes through as `{:ok, nil}`: a nil plaintext produces no token.
  """
  @spec normalize(term(), normalize()) :: {:ok, binary() | nil} | {:error, term()}
  def normalize(nil, _strategy), do: {:ok, nil}

  def normalize(value, :none), do: as_binary(value, :none)

  def normalize(value, :downcase) do
    with {:ok, binary} <- as_binary(value, :downcase), do: {:ok, String.downcase(binary)}
  end

  def normalize(value, :downcase_trim) do
    with {:ok, binary} <- as_binary(value, :downcase_trim) do
      {:ok, binary |> String.trim() |> String.downcase()}
    end
  end

  def normalize(value, {module, function, args})
      when is_atom(module) and is_atom(function) and is_list(args) do
    module |> apply(function, [value | args]) |> as_binary({module, function, args})
  end

  def normalize(value, fun) when is_function(fun, 1) do
    value |> fun.() |> as_binary(fun)
  end

  # `Ash.CiString` is allowed as a searchable type, and its runtime representation is a
  # struct, not a binary. Unwrapping it here rather than at the type gate keeps the two
  # in agreement: everything the verifier permits, this function can normalize.
  defp as_binary(%Ash.CiString{} = value, strategy),
    do: value |> Ash.CiString.value() |> as_binary(strategy)

  defp as_binary(value, _strategy) when is_binary(value), do: {:ok, value}

  defp as_binary(nil, _strategy), do: {:ok, nil}

  defp as_binary(value, strategy) do
    {:error, {:not_a_binary, strategy, AshVault.Scope.describe(value)}}
  end

  # ── the full path ──────────────────────────────────────────────────────────────

  @doc """
  Compute the lookup token for a value, resolving the vault, scope and provider exactly
  as a write does.

  Returns `{:ok, nil}` for a `nil` plaintext. Returns `{:error, exception}` for a
  missing scope, a destroyed scope, an unreachable provider, a provider with no
  `c:AshVault.KeyProvider.lookup_key/1`, or a normalizer that did not return a binary.

  Never raises: like `AshVault.decrypt_value/5`, crypto failures are values here so the
  write path can add them to a changeset and the read path to a query.
  """
  @spec token_for(module(), atom(), term(), Context.t()) ::
          {:ok, binary() | nil} | {:error, Exception.t()}
  def token_for(resource, field, value, %Context{} = context) do
    with {:ok, normalized} <- normalize_for(resource, field, value) do
      token_for_normalized(resource, field, normalized, context)
    end
  end

  @doc """
  Like `token_for/4`, for a value that has **already** been normalized.

  The write path normalizes once and encrypts the result, so it must not normalize a
  second time here: a custom `normalize:` MFA is not required to be idempotent, and the
  token has to be the hash of exactly the bytes that were encrypted.
  """
  @spec token_for_normalized(module(), atom(), binary() | nil, Context.t()) ::
          {:ok, binary() | nil} | {:error, Exception.t()}
  def token_for_normalized(_resource, _field, nil, %Context{}), do: {:ok, nil}

  def token_for_normalized(resource, field, normalized, %Context{} = context)
      when is_binary(normalized) do
    with {:ok, key} <- field_key(resource, field, context) do
      {:ok, token(key, normalized)}
    end
  end

  @doc """
  Like `token_for/4`, but raises the error instead of returning it.

  This is the form `AshVault.Query.filter_by/4` uses: a plain function has no changeset
  or query to attach an error to, and a lookup that quietly returned no filter would
  read as "no such user".
  """
  @spec token_for!(module(), atom(), term(), Context.t()) :: binary() | nil
  def token_for!(resource, field, value, %Context{} = context) do
    case token_for(resource, field, value, context) do
      {:ok, token} -> token
      {:error, error} -> raise error
    end
  end

  @doc """
  Normalize a value with the `normalize:` strategy configured for a field.
  """
  @spec normalize_for(module() | Spark.Dsl.t(), atom(), term()) ::
          {:ok, binary() | nil} | {:error, Exception.t()}
  def normalize_for(resource, field, value) do
    case normalize(value, AshVault.Info.normalize(resource, field)) do
      {:ok, normalized} ->
        {:ok, normalized}

      {:error, {:not_a_binary, strategy, description}} ->
        {:error, normalizer_error(resource, field, strategy, description)}
    end
  end

  @doc """
  The derived per-field token key for an operation, or an error.

  Exposed so a test can assert the key is stable across a rotation, which is the one
  property the whole mechanism rests on.
  """
  @spec field_key(module(), atom(), Context.t()) :: {:ok, binary()} | {:error, Exception.t()}
  def field_key(resource, field, %Context{} = context) do
    vault = AshVault.Info.vault!(resource, context.ash_context)

    # Through `Runtime.resolve_scope!/3`, not `scope.resolve!/1` directly. Calling the
    # scope module here skipped the one place that enforces "a scope is a binary", so a
    # custom `AshVault.Scope` returning a non-binary escaped as a bare `ArgumentError`
    # from whichever provider's `validate_scope!/1` happened to see it first — a wrong
    # -shaped error leaving a non-bang `Ash.read/2`, where every other path in the
    # library raises `AshVault.Errors.InvalidScope`.
    scope =
      AshVault.Vault.Runtime.resolve_scope!(context, vault.__ash_vault__(:scope), :lookup)

    provider = vault.__ash_vault__(:key_provider)

    case AshVault.KeyProvider.lookup_key(provider, scope) do
      {:ok, key} ->
        {:ok, derive_field_key(key, resource, field)}

      # The runtime backstop behind `AshVault.Verifiers.VerifyVault`, which catches this
      # at compile time whenever it can see the provider module. It cannot for a provider
      # resolved through a `fun/2` or MFA vault, or one not yet compiled when the resource
      # was — and `ProviderUnavailable` would be the wrong answer for both: this is a
      # permanent configuration fault, not something to retry.
      {:error, :lookup_unsupported} ->
        {:error,
         AshVault.Errors.LookupUnsupported.exception(
           provider: provider,
           resource: resource,
           field: field
         )}

      {:error, reason} ->
        {:error,
         AshVault.Vault.Runtime.map_provider_error(reason, scope, context)
         |> with_provider(provider)}
    end
  rescue
    error in [MissingScope, AshVault.Errors.InvalidScope, AshVault.Errors.LookupUnsupported] ->
      {:error, error}
  end

  defp with_provider(%AshVault.Errors.ProviderUnavailable{provider: nil} = error, provider),
    do: %{error | provider: provider}

  defp with_provider(error, _provider), do: error

  defp normalizer_error(resource, field, strategy, description) do
    AshVault.Errors.LookupNormalizationFailed.exception(
      resource: resource,
      field: field,
      strategy: describe_strategy(strategy),
      value: description
    )
  end

  defp describe_strategy(strategy) when is_atom(strategy), do: inspect(strategy)
  defp describe_strategy({m, f, a}), do: "#{inspect(m)}.#{f}/#{length(a) + 1}"
  defp describe_strategy(fun) when is_function(fun), do: inspect(fun)
  defp describe_strategy(other), do: inspect(other)
end
