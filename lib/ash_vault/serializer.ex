defmodule AshVault.Serializer do
  @moduledoc """
  The AshVault Plaintext ("AVP") format: the bytes handed to `c:AshVault.Vault.encrypt!/2`.

      <<"AVP", 1::8, :erlang.term_to_binary(dumped)::binary>>

  `dumped` is **always** `Ash.Type.dump_to_embedded/3` of the value, for every type —
  scalars, arrays, arrays of embedded resources, embedded resources and unions alike.
  Ash dispatches `{:array, t}` to its array implementation and recurses, so no
  array-specific code is needed here. One code path, one on-disk shape.

  Decoding is deliberately paranoid:

    * the `"AVP"` magic and version byte must match, or you get
      `AshVault.Errors.UnsupportedEnvelope` with `layer: :plaintext` in `vars` — the
      *plaintext* format version, which is distinct from the ciphertext envelope version
    * a compressed external term (`<<131, 80, ...>>`) is refused outright with
      `AshVault.Errors.InvalidCiphertext`. AshVault never writes one, and `:safe` does
      not stop a decompression bomb
    * decoding goes through Ash's `non_executable_binary_to_term` helper with `:safe`,
      which blocks atom interning and funs/refs/ports
    * the decoded term is then cast with `Ash.Type.cast_from_embedded/3`

  ## Storage encoding

  The encrypted envelope is handed to the backing `:binary` attribute raw. Since ash
  3.26 `Ash.Type.Binary` base64-encodes itself inside embedded resources, so AshVault
  adds no conditional base64 of its own — which means **ash >= 3.26 is required for
  encrypted attributes on embedded resources**.
  """

  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.SerializationFailed
  alias AshVault.Errors.UnsupportedEnvelope

  @magic "AVP"
  @version 1

  @doc "The plaintext format magic, `\"AVP\"`."
  @spec magic() :: binary()
  def magic, do: @magic

  @doc "The plaintext format version, `1`."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc """
  Serialize a value to the AVP plaintext format.

  Raises `AshVault.Errors.SerializationFailed` when the type cannot dump the value.
  """
  @spec serialize!(term(), Ash.Type.t(), keyword(), module(), atom()) :: binary()
  def serialize!(value, type, constraints, resource, field) do
    case Ash.Type.dump_to_embedded(type, value, constraints) do
      {:ok, dumped} ->
        <<@magic, @version::8, :erlang.term_to_binary(dumped)::binary>>

      other ->
        raise SerializationFailed.exception(
                resource: resource,
                field: field,
                type: type,
                reason: {:dump_to_embedded, other}
              )
    end
  end

  @doc """
  Deserialize an AVP plaintext binary back into a value.

  Returns `{:error, %AshVault.Errors.UnsupportedEnvelope{}}`,
  `{:error, %AshVault.Errors.InvalidCiphertext{}}` or
  `{:error, %AshVault.Errors.SerializationFailed{}}` rather than raising, so the decrypt
  calculation can hand the error straight to Ash.
  """
  @spec deserialize(binary(), Ash.Type.t(), keyword(), module(), atom()) ::
          {:ok, term()} | {:error, Exception.t()}
  def deserialize(binary, type, constraints, resource, field)

  def deserialize(<<@magic, @version::8, payload::binary>>, type, constraints, resource, field) do
    with {:ok, dumped} <- decode_term(payload) do
      case Ash.Type.cast_from_embedded(type, dumped, constraints) do
        {:ok, value} ->
          {:ok, value}

        other ->
          {:error,
           SerializationFailed.exception(
             resource: resource,
             field: field,
             type: type,
             reason: {:cast_from_embedded, other}
           )}
      end
    end
  end

  def deserialize(<<@magic, version::8, _rest::binary>>, _type, _constraints, _resource, _field) do
    {:error, UnsupportedEnvelope.exception(version: version, vars: [layer: :plaintext])}
  end

  def deserialize(binary, _type, _constraints, _resource, _field) when is_binary(binary) do
    {:error, InvalidCiphertext.exception(reason: :not_an_ash_vault_plaintext)}
  end

  # Refuse the compressed external term format before decoding: AshVault never writes
  # `:compressed` terms, and `:safe` inflates them regardless of size.
  defp decode_term(<<131, 80, _rest::binary>>) do
    {:error, InvalidCiphertext.exception(reason: :compressed_term_refused)}
  end

  defp decode_term(payload) do
    {:ok, Ash.Helpers.non_executable_binary_to_term(payload, [:safe])}
  rescue
    error -> {:error, InvalidCiphertext.exception(reason: {:binary_to_term, classify(error)})}
  end

  # The rescued exception is NOT safe to store. `Ash.Helpers.non_executable_binary_to_term/2`
  # raises `ArgumentError` whose message interpolates `inspect(other)` for a fun, pid,
  # port or reference (`deps/ash/lib/ash/helpers.ex:625`), and that `inspect(other)` is a
  # term reconstructed from bytes AshVault just decrypted. `InvalidCiphertext.message/1`
  # runs `inspect(reason)`, so keeping the struct would print it. Classify instead: the
  # two outcomes are the only diagnostic an operator can act on.
  defp classify(%ArgumentError{message: message}) do
    if is_binary(message) and String.contains?(message, "not safe for deserialization") do
      :unsafe_term
    else
      :malformed_term
    end
  end

  defp classify(error), do: {:raised, error.__struct__}
end
