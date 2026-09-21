defmodule AshVault.Envelope do
  @moduledoc """
  Behaviour for envelope formats, and the dispatcher used to decode stored values.

  An envelope is the self-describing wrapper written to the database. It carries
  everything needed to decrypt a value except the key itself: the format version, the
  cipher id, the key version, the nonce, the authentication tag and the ciphertext.

  `AshVault.Envelope` is both the behaviour and the dispatcher. `decode/1` peeks at the
  version byte and routes to the matching implementation, so values written by older
  builds keep decoding after the default envelope version changes.

  See `AshVault.Envelope.V1` for the current wire format.
  """

  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.UnsupportedEnvelope

  @type decoded :: %{
          version: pos_integer(),
          cipher: binary(),
          key_version: non_neg_integer(),
          nonce: binary(),
          tag: binary(),
          ciphertext: binary()
        }

  @doc "The version byte this implementation writes."
  @callback version() :: pos_integer()

  @doc "Serialize a decoded envelope map to its wire representation."
  @callback encode(map()) :: binary()

  @doc "Parse a binary into a decoded envelope map. Must never raise."
  @callback decode(binary()) :: {:ok, map()} | {:error, Exception.t()}

  @magic "AV"

  @versions %{1 => AshVault.Envelope.V1}

  @doc """
  The magic prefix every AshVault envelope starts with.
  """
  @spec magic() :: binary()
  def magic, do: @magic

  @doc """
  Decode a stored value by dispatching on its envelope version byte.

  This function is total: any binary (or indeed any term) produces a tagged tuple, never
  an exception.

  Returns `{:error, %AshVault.Errors.UnsupportedEnvelope{}}` for a well-formed magic with
  an unknown version, and `{:error, %AshVault.Errors.InvalidCiphertext{}}` for anything
  that is not an AshVault envelope at all.
  """
  @spec decode(binary()) :: {:ok, decoded()} | {:error, Exception.t()}
  def decode(<<>>), do: {:error, InvalidCiphertext.exception(reason: :empty)}

  def decode(<<@magic, version::8, _rest::binary>> = blob) do
    case Map.fetch(@versions, version) do
      {:ok, module} -> module.decode(blob)
      :error -> {:error, UnsupportedEnvelope.exception(version: version)}
    end
  end

  def decode(binary) when is_binary(binary) do
    {:error, InvalidCiphertext.exception(reason: :bad_magic)}
  end

  def decode(_other) do
    {:error, InvalidCiphertext.exception(reason: :not_a_binary)}
  end

  @doc """
  The envelope implementation for a version byte, if this build knows it.
  """
  @spec module_for_version(integer()) :: {:ok, module()} | :error
  def module_for_version(version), do: Map.fetch(@versions, version)
end
