defmodule AshVault do
  @moduledoc """
  Encrypted attributes for Ash resources.

      defmodule MyApp.Accounts.User do
        use Ash.Resource, extensions: [AshVault]

        ash_vault do
          vault MyApp.Vault
          scope :tenant

          encrypt :email
          encrypt :ssn, encrypt_nil?: false

          decrypt_by_default [:email]
        end
      end

  Each encrypted attribute is *replaced*: the plaintext attribute entity is removed, a
  private `encrypted_<name>` `:binary` attribute takes its place in the data layer, and a
  calculation of the original name and type decrypts on read. There is no plaintext
  column, so no data layer can write one.

  Writes go through an argument of the original name and type plus an
  `AshVault.Changes.Encrypt` change that encrypts in a `before_action` hook and scrubs the
  plaintext from `changeset.arguments` and `changeset.params`.

  See `AshVault.Dsl` for the DSL, `AshVault.Info` for introspection, and
  `AshVault.Serializer` for the plaintext wire format.

  ## Limitations

    * The decrypt calculation is `filterable?: false, sortable?: false` — randomized AEAD
      ciphertext supports neither. Searchable fields (lookup tokens) are post-v1.
    * Encrypted attributes on *embedded* resources require ash >= 3.26, which is when
      `Ash.Type.Binary` started handling its own base64 encoding.
  """

  @transformers [
    AshVault.Transformers.ExpandAttributes,
    AshVault.Transformers.SetupEncryption
  ]

  @verifiers [
    AshVault.Verifiers.VerifyVault
  ]

  use Spark.Dsl.Extension,
    sections: AshVault.Dsl.sections(),
    transformers: @transformers,
    verifiers: @verifiers

  alias AshVault.Errors.SerializationFailed

  @doc """
  Rotate the key for `scope` in `vault`, minting a new key version.

  Existing values keep decrypting with their original key version; new writes use the
  new one.
  """
  @spec rotate_key!(module(), term(), AshVault.Context.t() | nil) :: {:ok, non_neg_integer()}
  def rotate_key!(vault, scope, context \\ nil) do
    metadata =
      context
      |> AshVault.Telemetry.context_metadata()
      |> Map.merge(%{vault: vault, scope: scope, key_version: nil})

    :telemetry.span([:ash_vault, :key, :rotate], metadata, fn ->
      result = vault.rotate!(scope)

      {result,
       metadata
       |> Map.merge(AshVault.Telemetry.result_metadata(result))
       |> Map.put(:key_version, key_version(result))}
    end)
  end

  defp key_version({:ok, version}) when is_integer(version), do: version
  defp key_version(_other), do: nil

  @doc """
  Crypto-erase `scope` in `vault`: destroy every key version and tombstone the scope.

  This is irreversible. Every value encrypted under `scope` becomes permanently
  unrecoverable, and later reads raise `AshVault.Errors.KeyDestroyed`.
  """
  @spec destroy_keys!(module(), term(), AshVault.Context.t() | nil) :: :ok
  def destroy_keys!(vault, scope, context \\ nil) do
    metadata =
      context
      |> AshVault.Telemetry.context_metadata()
      |> Map.merge(%{vault: vault, scope: scope})

    :telemetry.span([:ash_vault, :key, :destroy], metadata, fn ->
      result = vault.destroy!(scope)
      {result, Map.merge(metadata, AshVault.Telemetry.result_metadata(result))}
    end)
  end

  @doc """
  The name of the backing ciphertext attribute for an encrypted field.

  This is the single place the naming scheme lives; the transformer mints the atom at
  compile time and every runtime lookup goes through here.
  """
  @spec encrypted_field_name(atom()) :: atom()
  def encrypted_field_name(field) when is_atom(field), do: :"encrypted_#{field}"

  @doc """
  Encrypt `value` and write it to the backing attribute of `field`, scrubbing the
  plaintext from the changeset.

  Returns the changeset with the error added when encryption fails, so `MissingScope`,
  `KeyDestroyed` and `ProviderUnavailable` surface as ordinary Ash errors rather than a
  raise inside a `before_action` hook.
  """
  @spec encrypt_and_set(Ash.Changeset.t(), atom(), term(), AshVault.Context.t()) ::
          Ash.Changeset.t()
  def encrypt_and_set(changeset, field, value, %AshVault.Context{} = context) do
    case encrypt_value(changeset.resource, field, value, context) do
      {:ok, blob} ->
        changeset
        |> Ash.Changeset.force_change_attribute(encrypted_field_name(field), blob)
        |> scrub_plaintext(field)

      {:error, error} ->
        changeset
        |> scrub_plaintext(field)
        |> Ash.Changeset.add_error(error)
    end
  end

  @doc """
  Encrypt one value for a field of a resource, returning the bytes to store.

  Returns `{:ok, nil}` for a `nil` value on a field configured `encrypt_nil?: false` —
  that is the "store SQL NULL" case.
  """
  @spec encrypt_value(module(), atom(), term(), AshVault.Context.t()) ::
          {:ok, binary() | nil} | {:error, Exception.t()}
  def encrypt_value(resource, field, value, %AshVault.Context{} = context) do
    metadata =
      context
      |> AshVault.Telemetry.context_metadata()
      |> Map.merge(%{resource: resource, field: field})

    :telemetry.span([:ash_vault, :encrypt], metadata, fn ->
      result = do_encrypt_value(resource, field, value, context)
      {result, Map.merge(metadata, AshVault.Telemetry.result_metadata(result))}
    end)
  end

  defp do_encrypt_value(resource, field, value, context) do
    if is_nil(value) and not AshVault.Info.encrypt_nil?(resource, field) do
      {:ok, nil}
    else
      %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(resource, field)
      vault = AshVault.Info.vault!(resource, context.ash_context)

      plaintext = AshVault.Serializer.serialize!(value, type, constraints, resource, field)
      {:ok, vault.encrypt!(plaintext, context)}
    end
  rescue
    error in [
      AshVault.Errors.MissingScope,
      AshVault.Errors.KeyNotFound,
      AshVault.Errors.KeyDestroyed,
      AshVault.Errors.ProviderUnavailable,
      AshVault.Errors.CiphertextIntegrityFailed,
      AshVault.Errors.UnsupportedEnvelope,
      AshVault.Errors.UnsupportedCipher,
      AshVault.Errors.InvalidCiphertext,
      SerializationFailed
    ] ->
      {:error, error}
  end

  @doc """
  Decrypt one stored value, returning `{:ok, value}` or `{:error, %AshVault.Errors.*{}}`.

  Never raises: crypto failures are values here, so the decrypt calculation can return
  them to Ash and a destroyed tenant comes out of `Ash.read/2` as a clean
  `AshVault.Errors.KeyDestroyed`.
  """
  @spec decrypt_value(module(), binary(), AshVault.Context.t(), Ash.Type.t(), keyword()) ::
          {:ok, term()} | {:error, Exception.t()}
  def decrypt_value(vault, blob, %AshVault.Context{} = context, type, constraints) do
    metadata =
      context
      |> AshVault.Telemetry.context_metadata()
      |> Map.put(:vault, vault)

    :telemetry.span([:ash_vault, :decrypt], metadata, fn ->
      result = do_decrypt_value(vault, blob, context, type, constraints)
      {result, Map.merge(metadata, AshVault.Telemetry.result_metadata(result))}
    end)
  end

  defp do_decrypt_value(vault, blob, context, type, constraints) do
    plaintext = vault.decrypt!(blob, context)

    AshVault.Serializer.deserialize(
      plaintext,
      type,
      constraints,
      context.resource,
      context.field
    )
  rescue
    error in [
      AshVault.Errors.MissingScope,
      AshVault.Errors.KeyNotFound,
      AshVault.Errors.KeyDestroyed,
      AshVault.Errors.ProviderUnavailable,
      AshVault.Errors.CiphertextIntegrityFailed,
      AshVault.Errors.UnsupportedEnvelope,
      AshVault.Errors.UnsupportedCipher,
      AshVault.Errors.InvalidCiphertext,
      SerializationFailed
    ] ->
      {:error, error}
  end

  @doc """
  Remove a field's plaintext from `changeset.arguments` and `changeset.params`.

  Without this the plaintext survives in the changeset — and therefore in `inspect` output,
  telemetry and error reports — long after it has been encrypted.
  """
  @spec scrub_plaintext(Ash.Changeset.t(), atom()) :: Ash.Changeset.t()
  def scrub_plaintext(changeset, field) do
    changeset
    |> Map.update!(:arguments, &Map.delete(&1, field))
    |> Map.update!(:params, &Map.drop(&1, [field, to_string(field)]))
  end
end
