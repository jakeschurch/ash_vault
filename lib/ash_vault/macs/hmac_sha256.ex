defmodule AshVault.Macs.HmacSha256 do
  @moduledoc """
  HMAC-SHA256 computed in process, over a raw 32-byte `:mac` key.

  The default `AshVault.Mac` for every vault whose cipher is not
  `AshVault.Ciphers.OpenBaoTransit`.

  The tag is `HMAC-SHA256(key, AshVault.Mac.frame(data, aad))`: 32 raw bytes. `hmac/2`
  is the bare primitive, exposed so it can be checked against the RFC 4231 vectors
  directly.

  `verify/4` recomputes the tag and compares it with `:crypto.hash_equals/2`, which is
  constant-time in the contents. A tag of the wrong length is refused before the
  comparison — `:crypto.hash_equals/2` raises on unequal lengths, and the length of a
  valid tag is public anyway.

  An opaque `AshVault.Key` handle is refused with `{:error, :opaque_key_unsupported}`:
  there are no bytes here to HMAC with, and no fallback is ever taken.
  """

  @behaviour AshVault.Mac

  @key_bytes 32
  @tag_bytes 32

  @doc "The stable id, `:hmac_sha256_v1`."
  @impl AshVault.Mac
  @spec id() :: :hmac_sha256_v1
  def id, do: :hmac_sha256_v1

  @doc "The key size in bytes, `32`."
  @impl AshVault.Mac
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: @key_bytes

  @doc """
  The bare HMAC-SHA256 primitive, with no framing.

  ## Examples

      iex> AshVault.Macs.HmacSha256.hmac("key", "The quick brown fox jumps over the lazy dog")
      ...> |> Base.encode16(case: :lower)
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

  """
  @spec hmac(binary(), binary()) :: binary()
  def hmac(key, message) when is_binary(key) and is_binary(message) do
    :crypto.mac(:hmac, :sha256, key, message)
  end

  @doc """
  The 32-byte tag over `AshVault.Mac.frame(data, aad)` under `key`.
  """
  @impl AshVault.Mac
  @spec mac(binary(), AshVault.Key.t(), binary()) :: {:ok, binary()} | {:error, term()}
  def mac(data, key, aad) when is_binary(data) and is_binary(aad) do
    with :ok <- check_key(key) do
      {:ok, hmac(key, AshVault.Mac.frame(data, aad))}
    end
  end

  @doc """
  Verify a tag in constant time. `{:error, :invalid_tag}` for anything that does not
  verify, including a tag of the wrong length or type.
  """
  @impl AshVault.Mac
  @spec verify(binary(), binary(), AshVault.Key.t(), binary()) ::
          :ok | {:error, :invalid_tag} | {:error, term()}
  def verify(data, tag, key, aad) when is_binary(data) and is_binary(aad) do
    with :ok <- check_key(key) do
      if is_binary(tag) and byte_size(tag) == @tag_bytes and
           :crypto.hash_equals(hmac(key, AshVault.Mac.frame(data, aad)), tag) do
        :ok
      else
        {:error, :invalid_tag}
      end
    end
  end

  defp check_key(key) when is_binary(key) and byte_size(key) == @key_bytes, do: :ok
  defp check_key(key) when is_binary(key), do: {:error, {:invalid_key_size, byte_size(key)}}
  defp check_key(_key), do: {:error, :opaque_key_unsupported}
end
