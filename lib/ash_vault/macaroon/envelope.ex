defmodule AshVault.Macaroon.Envelope do
  @moduledoc """
  The frozen wire format of a macaroon token.

      token   := prefix "_" base64url(payload)        (no padding)
      payload := version::8 = 1
                 scope_len::8        scope            1..180 bytes, UTF-8, no control chars
                 key_version::32                      >= 1
                 id_len::8           id               1..255 bytes
                 caveat_count::8                      0..#{32}
                 caveat_count × (caveat_len::16  caveat)   1..256 bytes each
                 sig::binary-32

  `prefix` is 2–32 characters of `[a-z][a-z0-9]*` — deliberately no `_`, so the first
  `_` always separates it from the payload (the base64url alphabet itself contains `_`).
  A distinctive prefix is what lets secret scanners recognise a leaked token.

  The prefix is not inside the payload, but it is bound by the root signature (see
  `AshVault.Macaroon.Chain.root_data/1`), so swapping it breaks the token.

  ## Strictness

  `decode/1` fails closed on anything that is not the one canonical encoding: a token
  longer than `max_token_bytes/0` (checked before any decoding), non-canonical base64,
  an unknown version, a field that runs past the end, trailing bytes, a zero key
  version, an oversized caveat list, or a scope with control characters. It returns
  `{:error, :malformed}` or `{:error, :unsupported_version}` and nothing more specific:
  the details of why a forged token failed to parse are not something to hand back.
  """

  @version 1
  @sig_bytes 32
  @max_field 255
  @max_caveats 32
  @max_caveat_bytes AshVault.Macaroon.CaveatCodec.max_caveat_bytes()
  @max_prefix 32
  @max_scope 180

  @max_payload 1 + 1 + @max_field + 4 + 1 + @max_field + 1 +
                 @max_caveats * (2 + @max_caveat_bytes) + @sig_bytes
  @max_token @max_prefix + 1 + div(@max_payload * 4 + 2, 3)

  defstruct [:prefix, :scope, :key_version, :id, caveats: [], sig: nil, version: @version]

  @type t :: %__MODULE__{
          prefix: binary(),
          version: pos_integer(),
          scope: binary(),
          key_version: pos_integer(),
          id: binary(),
          caveats: [binary()],
          sig: binary()
        }

  @doc "The envelope version this build writes, `#{@version}`."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc "The maximum number of caveats a token may carry, `#{@max_caveats}`."
  @spec max_caveats() :: pos_integer()
  def max_caveats, do: @max_caveats

  @doc "The longest token string `decode/1` will look at, in bytes."
  @spec max_token_bytes() :: pos_integer()
  def max_token_bytes, do: @max_token

  @doc "Whether `prefix` is a valid macaroon prefix."
  @spec valid_prefix?(term()) :: boolean()
  def valid_prefix?(prefix) when is_binary(prefix) do
    byte_size(prefix) in 2..@max_prefix and prefix =~ ~r/\A[a-z][a-z0-9]*\z/
  end

  def valid_prefix?(_prefix), do: false

  @doc """
  Whether `scope` can be carried in a token: 1–#{@max_scope} bytes of UTF-8 without
  control characters. Checked on mint and on decode, before any key provider sees it.

  #{@max_scope} rather than the field's 255 because a scope becomes a file or key name in
  a provider: `AshVault.KeyProviders.Local` names a scope directory with its base64url
  encoding plus `.tombstone`, which for 180 bytes is 250 characters — inside every common
  filesystem's 255-byte name limit.
  """
  @spec valid_scope?(term()) :: boolean()
  def valid_scope?(scope) when is_binary(scope) do
    byte_size(scope) in 1..@max_scope and String.valid?(scope) and
      not String.match?(scope, ~r/[[:cntrl:]]/u)
  end

  def valid_scope?(_scope), do: false

  @doc "Encode a token struct. `{:error, :malformed}` for a struct outside the format."
  @spec encode(t()) :: {:ok, binary()} | {:error, :malformed}
  def encode(%__MODULE__{version: @version} = token) do
    if well_formed?(token) do
      caveats = for caveat <- token.caveats, do: <<byte_size(caveat)::16, caveat::binary>>

      payload =
        IO.iodata_to_binary([
          <<@version::8, byte_size(token.scope)::8>>,
          token.scope,
          <<token.key_version::32, byte_size(token.id)::8>>,
          token.id,
          <<length(token.caveats)::8>>,
          caveats,
          token.sig
        ])

      {:ok, token.prefix <> "_" <> Base.url_encode64(payload, padding: false)}
    else
      {:error, :malformed}
    end
  end

  def encode(_token), do: {:error, :malformed}

  defp well_formed?(token) do
    valid_prefix?(token.prefix) and valid_scope?(token.scope) and
      is_integer(token.key_version) and token.key_version in 1..0xFFFFFFFF and
      is_binary(token.id) and byte_size(token.id) in 1..@max_field and
      is_list(token.caveats) and length(token.caveats) <= @max_caveats and
      Enum.all?(token.caveats, &(is_binary(&1) and byte_size(&1) in 1..@max_caveat_bytes)) and
      is_binary(token.sig) and byte_size(token.sig) == @sig_bytes
  end

  @doc "Decode a token string, strictly. See the moduledoc."
  @spec decode(term()) :: {:ok, t()} | {:error, :malformed | :unsupported_version}
  def decode(token) when is_binary(token) and byte_size(token) <= @max_token do
    with [prefix, encoded] <- :binary.split(token, "_"),
         true <- valid_prefix?(prefix),
         {:ok, payload} <- Base.url_decode64(encoded, padding: false),
         true <- Base.url_encode64(payload, padding: false) == encoded do
      decode_payload(prefix, payload)
    else
      _ -> {:error, :malformed}
    end
  end

  def decode(_token), do: {:error, :malformed}

  defp decode_payload(
         prefix,
         <<@version::8, scope_len::8, scope::binary-size(scope_len), key_version::32, id_len::8,
           id::binary-size(id_len), count::8, rest::binary>>
       )
       when count <= @max_caveats and key_version >= 1 and id_len >= 1 do
    with true <- valid_scope?(scope),
         {:ok, caveats, sig} <- decode_caveats(count, rest, []) do
      {:ok,
       %__MODULE__{
         prefix: prefix,
         scope: scope,
         key_version: key_version,
         id: id,
         caveats: caveats,
         sig: sig
       }}
    else
      _ -> {:error, :malformed}
    end
  end

  defp decode_payload(_prefix, <<version::8, _rest::binary>>) when version != @version,
    do: {:error, :unsupported_version}

  defp decode_payload(_prefix, _payload), do: {:error, :malformed}

  defp decode_caveats(0, <<sig::binary-size(@sig_bytes)>>, acc),
    do: {:ok, Enum.reverse(acc), sig}

  defp decode_caveats(count, <<len::16, caveat::binary-size(len), rest::binary>>, acc)
       when count > 0 and len in 1..@max_caveat_bytes,
       do: decode_caveats(count - 1, rest, [caveat | acc])

  defp decode_caveats(_count, _rest, _acc), do: :error
end
