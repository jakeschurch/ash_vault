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

  Every field that does not fit the wire format raises `ArgumentError` naming the field
  and the limit. The header encodes the cipher id, nonce and tag lengths in one byte
  each and the key version in 32 bits, so the ceilings are 255 bytes and 4294967295
  respectively. These used to be guard clauses, which meant an over-long nonce, an
  over-long tag or a key version past 2^32-1 raised an opaque `FunctionClauseError`
  while an over-long cipher id got a clean message — the same class of mistake
  reported two different ways.
  """
  @impl AshVault.Envelope
  @spec encode(map()) :: binary()
  def encode(%{
        cipher: cipher,
        key_version: key_version,
        nonce: nonce,
        tag: tag,
        ciphertext: ciphertext
      }) do
    cipher_id = to_cipher_id(cipher)

    validate_length!(:cipher_id, cipher_id)
    validate_length!(:nonce, nonce)
    validate_length!(:tag, tag)
    validate_key_version!(key_version)
    validate_binary!(:ciphertext, ciphertext)

    <<@magic, @version::8, byte_size(cipher_id)::8, cipher_id::binary,
      key_version::32-unsigned-big, byte_size(nonce)::8, nonce::binary, byte_size(tag)::8,
      tag::binary, ciphertext::binary>>
  end

  def encode(other) do
    raise ArgumentError,
          "not an encodable AshVault envelope: expected a map with :cipher, :key_version, " <>
            ":nonce, :tag and :ciphertext, got: #{inspect(other)}"
  end

  defp validate_length!(_field, value) when is_binary(value) and byte_size(value) <= 255, do: :ok

  defp validate_length!(field, value) when is_binary(value) do
    raise ArgumentError,
          "#{field} is too long: the v1 envelope stores its length in one byte, so it must " <>
            "be at most 255 bytes, got #{byte_size(value)}"
  end

  defp validate_length!(field, value), do: validate_binary!(field, value)

  defp validate_binary!(_field, value) when is_binary(value), do: :ok

  defp validate_binary!(field, value) do
    raise ArgumentError, "#{field} must be a binary, got: #{inspect(value)}"
  end

  defp validate_key_version!(version)
       when is_integer(version) and version >= 0 and version <= 0xFFFFFFFF,
       do: :ok

  defp validate_key_version!(version) when is_integer(version) do
    raise ArgumentError,
          "key_version is out of range: the v1 envelope stores it as a 32-bit unsigned " <>
            "integer, so it must be between 0 and 4294967295, got #{version}"
  end

  defp validate_key_version!(version) do
    raise ArgumentError, "key_version must be an integer, got: #{inspect(version)}"
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

  defp to_cipher_id(cipher) do
    raise ArgumentError, "cipher must be an atom or a binary, got: #{inspect(cipher)}"
  end
end
