defmodule AshVault.Cipher do
  @moduledoc """
  Behaviour for AEAD ciphers, plus the registry used to resolve a cipher id
  read out of a stored envelope.

  A cipher is identified by a stable atom id (for example `:aes_256_gcm_v1`) which is
  written into every envelope as a binary. Decryption looks the cipher back up through
  `fetch/1`, so the cipher a value was encrypted with is always the cipher used to
  decrypt it — even if the vault has since been configured with a different default.

  Additional ciphers can be registered:

      config :ash_vault, :ciphers, %{my_cipher_v1: MyApp.Ciphers.Custom}
  """

  alias AshVault.Errors.UnsupportedCipher

  @type payload :: %{ciphertext: binary(), nonce: binary(), tag: binary()}

  @doc "The stable identifier written into envelopes."
  @callback id() :: atom()

  @doc "The exact key size, in bytes, this cipher requires."
  @callback key_bytes() :: pos_integer()

  @doc "Encrypt `plaintext` under `key`, binding `aad` into the authentication tag."
  @callback encrypt(plaintext :: binary(), key :: binary(), aad :: binary()) ::
              {:ok, payload()} | {:error, term()}

  @doc "Decrypt a payload under `key`, verifying it against `aad`."
  @callback decrypt(payload(), key :: binary(), aad :: binary()) ::
              {:ok, binary()} | {:error, term()}

  @builtin %{aes_256_gcm_v1: AshVault.Ciphers.AES.GCM}

  @doc """
  Look up a cipher module by id.

  Accepts either an atom id or the binary id stored in an envelope. Binary ids are
  matched against the known ids by string comparison — untrusted input is never turned
  into an atom.

  ## Examples

      iex> AshVault.Cipher.fetch(:aes_256_gcm_v1)
      {:ok, AshVault.Ciphers.AES.GCM}

      iex> AshVault.Cipher.fetch("aes_256_gcm_v1")
      {:ok, AshVault.Ciphers.AES.GCM}

      iex> {:error, %AshVault.Errors.UnsupportedCipher{}} = AshVault.Cipher.fetch("nope")

  """
  @spec fetch(atom() | binary()) :: {:ok, module()} | {:error, UnsupportedCipher.t()}
  def fetch(id) when is_atom(id) and not is_nil(id) do
    fetch(Atom.to_string(id))
  end

  def fetch(id) when is_binary(id) do
    case Enum.find(registry(), fn {key, _module} -> key == id end) do
      {_key, module} -> {:ok, module}
      nil -> {:error, UnsupportedCipher.exception(cipher_id: id)}
    end
  end

  def fetch(id) do
    {:error, UnsupportedCipher.exception(cipher_id: id)}
  end

  @doc """
  The full binary-keyed cipher registry: built-in ciphers merged with configured ones.
  """
  @spec registry() :: %{optional(binary()) => module()}
  def registry do
    @builtin
    |> Map.merge(configured())
    |> Map.new(fn {key, module} -> {to_binary_id(key), module} end)
  end

  defp configured do
    case Application.get_env(:ash_vault, :ciphers, %{}) do
      map when is_map(map) -> map
      list when is_list(list) -> Map.new(list)
      _other -> %{}
    end
  end

  defp to_binary_id(key) when is_atom(key), do: Atom.to_string(key)
  defp to_binary_id(key) when is_binary(key), do: key
end
