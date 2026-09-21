defmodule AshVault.Envelope.V1 do
  @moduledoc """
  Version 1 of the AshVault envelope wire format.

  This layout is frozen. Stored ciphertext must remain decodable forever, so the bytes
  below are a compatibility guarantee, not an implementation detail:

      <<"AV",                              # 2-byte magic
        1          :: 8,                   # envelope version
        cid_len    :: 8,                   # cipher id length
        cipher_id  :: binary-size(cid_len),
        key_ver    :: 32-unsigned-big,
        nonce_len  :: 8,
        nonce      :: binary-size(nonce_len),
        tag_len    :: 8,
        tag        :: binary-size(tag_len),
        ciphertext :: binary>>

  The ciphertext is the remainder of the binary, so truncation *within* the ciphertext
  cannot be detected structurally — the AEAD tag catches it at decryption time instead.
  Truncation anywhere in the header is detected and reported as
  `AshVault.Errors.InvalidCiphertext`.
  """

  @behaviour AshVault.Envelope

  alias AshVault.Errors.InvalidCiphertext

  @magic "AV"
  @version 1

  @doc """
  The version byte written by this implementation, `1`.
  """
  @impl AshVault.Envelope
  @spec version() :: pos_integer()
  def version, do: @version

  @doc """
  Encode an envelope map to its wire representation.

  The `:cipher` key may be given as an atom or a binary; it is always stored as a binary.
  """
  @impl AshVault.Envelope
  @spec encode(map()) :: binary()
  def encode(%{
        cipher: cipher,
        key_version: key_version,
        nonce: nonce,
        tag: tag,
        ciphertext: ciphertext
      })
      when is_integer(key_version) and key_version >= 0 and key_version <= 0xFFFFFFFF and
             is_binary(nonce) and byte_size(nonce) <= 255 and
             is_binary(tag) and byte_size(tag) <= 255 and is_binary(ciphertext) do
    cipher_id = to_cipher_id(cipher)

    if byte_size(cipher_id) > 255 do
      raise ArgumentError, "cipher id is too long: #{inspect(cipher_id)}"
    end

    <<@magic, @version::8, byte_size(cipher_id)::8, cipher_id::binary,
      key_version::32-unsigned-big, byte_size(nonce)::8, nonce::binary, byte_size(tag)::8,
      tag::binary, ciphertext::binary>>
  end

  @doc """
  Parse a v1 envelope.

  Total: never raises, and returns `{:error, %AshVault.Errors.InvalidCiphertext{}}` for
  any binary that is not a structurally valid v1 envelope.
  """
  @impl AshVault.Envelope
  @spec decode(binary()) :: {:ok, AshVault.Envelope.decoded()} | {:error, Exception.t()}
  def decode(
        <<@magic, @version::8, cid_len::8, cipher_id::binary-size(cid_len),
          key_version::32-unsigned-big, nonce_len::8, nonce::binary-size(nonce_len), tag_len::8,
          tag::binary-size(tag_len), ciphertext::binary>>
      ) do
    {:ok,
     %{
       version: @version,
       cipher: cipher_id,
       key_version: key_version,
       nonce: nonce,
       tag: tag,
       ciphertext: ciphertext
     }}
  end

  def decode(<<@magic, @version::8, _rest::binary>>) do
    {:error, InvalidCiphertext.exception(reason: :truncated)}
  end

  def decode(binary) when is_binary(binary) do
    {:error, InvalidCiphertext.exception(reason: :bad_magic)}
  end

  def decode(_other) do
    {:error, InvalidCiphertext.exception(reason: :not_a_binary)}
  end

  defp to_cipher_id(cipher) when is_atom(cipher) and not is_nil(cipher),
    do: Atom.to_string(cipher)

  defp to_cipher_id(cipher) when is_binary(cipher), do: cipher
end
