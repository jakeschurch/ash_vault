defmodule AshVault.Macs.OpenBaoTransit do
  @moduledoc """
  The MAC half of `AshVault.KeyProviders.OpenBaoTransit`: HMAC-SHA256 computed inside
  OpenBao, so the `:mac` key never enters the BEAM.

  `mac/3` is one `transit/hmac/<name>/sha2-256` call and `verify/4` one
  `transit/verify/<name>/sha2-256` call, both pinned to the handle's key version. The
  algorithm is in the path rather than left to the server's default, so a default that
  changed under an upgrade could not silently change every tag.

  ## Same frame, same tag as `AshVault.Macs.HmacSha256`

  Transit has no associated-data parameter, so the input sent is
  `AshVault.Mac.frame(data, aad)` — exactly what `AshVault.Macs.HmacSha256` HMACs. Transit
  answers `vault:v<N>:<base64>`; `mac/3` checks that `N` is the version it asked for and
  returns the decoded 32 raw bytes. So for the same key bytes the two modules produce the
  same tag, which `test/ash_vault/macs/open_bao_transit_test.exs` checks against a live
  server by exporting an `hmac` key and comparing.

  `verify/4` rebuilds `vault:v<N>:<base64(tag)>` from the handle's version. Rebuilding the
  prefix is safe here in a way it is not for ciphertext: the tag is a fixed 32-byte HMAC
  whose wire form transit has never varied, and the version comes from the handle the
  provider validated, not from the stored bytes.

  ## Handles only

  It accepts only a `:mac` handle from `AshVault.KeyProviders.OpenBaoTransit`
  (`{:mac, name, version}`). A data key handle is `{:error, :opaque_key_unsupported}`,
  and raw bytes are `{:error, :requires_open_bao_transit_key_provider}` — there is no
  transit key name to invent for them.

  ## Outage versus forgery

  `{:error, :invalid_tag}` is returned only when transit answers `200` with
  `valid: false`, or when the tag is not 32 bytes (refused before any round trip). Every
  other failure — a deleted key, a `403`, an unreachable server, a malformed response —
  is `AshVault.Errors.ProviderUnavailable`.
  """

  @behaviour AshVault.Mac

  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider

  @tag_bytes 32
  @algorithm "sha2-256"

  @doc "The stable id, `:openbao_transit_hmac_sha256_v1`."
  @impl AshVault.Mac
  @spec id() :: :openbao_transit_hmac_sha256_v1
  def id, do: :openbao_transit_hmac_sha256_v1

  @doc """
  The key size in bytes, `32`. Nominal: this module never sees key bytes.
  """
  @impl AshVault.Mac
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: 32

  @doc """
  HMAC `AshVault.Mac.frame(data, aad)` through `transit/hmac`, returning 32 raw bytes.
  """
  @impl AshVault.Mac
  @spec mac(binary(), AshVault.Key.t(), binary()) :: {:ok, binary()} | {:error, term()}
  def mac(data, key, aad) when is_binary(data) and is_binary(aad) do
    with {:ok, {name, version}} <- unwrap(key) do
      body = %{input: Base.encode64(AshVault.Mac.frame(data, aad)), key_version: version}

      case Transport.post(Provider, path("/hmac/#{name}/#{@algorithm}"), body) do
        {:ok, %{status: 200, body: response}} ->
          response |> Transport.data() |> Map.get("hmac") |> decode_tag(version)

        {:ok, response} ->
          Transport.unavailable!(Provider, response)

        {:error, error} ->
          {:error, error}
      end
    end
  end

  @doc """
  Verify a tag through `transit/verify`. `{:error, :invalid_tag}` only for a tag transit
  positively rejected, or one that is not 32 bytes.
  """
  @impl AshVault.Mac
  @spec verify(binary(), binary(), AshVault.Key.t(), binary()) ::
          :ok | {:error, :invalid_tag} | {:error, term()}
  def verify(data, tag, key, aad) when is_binary(data) and is_binary(aad) do
    with {:ok, {name, version}} <- unwrap(key),
         :ok <- check_tag(tag) do
      body = %{
        input: Base.encode64(AshVault.Mac.frame(data, aad)),
        hmac: "vault:v#{version}:" <> Base.encode64(tag)
      }

      case Transport.post(Provider, path("/verify/#{name}/#{@algorithm}"), body) do
        {:ok, %{status: 200, body: response}} ->
          case response |> Transport.data() |> Map.get("valid") do
            true -> :ok
            false -> {:error, :invalid_tag}
            _other -> {:error, Transport.unavailable(Provider, :malformed_transit_response)}
          end

        {:ok, response} ->
          Transport.unavailable!(Provider, response)

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp check_tag(tag) when is_binary(tag) and byte_size(tag) == @tag_bytes, do: :ok
  defp check_tag(_tag), do: {:error, :invalid_tag}

  @doc """
  Decode transit's `vault:v<N>:<base64>` HMAC into raw bytes, requiring `N == version`.

  Public so the parse can be tested without a server.

  ## Examples

      iex> AshVault.Macs.OpenBaoTransit.decode_tag("vault:v2:" <> Base.encode64(<<0::256>>), 2)
      {:ok, <<0::256>>}

  """
  @spec decode_tag(term(), pos_integer()) :: {:ok, binary()} | {:error, Exception.t()}
  def decode_tag("vault:v" <> rest, version) do
    with [digits, encoded] <- :binary.split(rest, ":"),
         {^version, ""} <- Integer.parse(digits),
         {:ok, tag} when byte_size(tag) == @tag_bytes <- Base.decode64(encoded) do
      {:ok, tag}
    else
      _other -> {:error, Transport.unavailable(Provider, :malformed_transit_response)}
    end
  end

  def decode_tag(_other, _version),
    do: {:error, Transport.unavailable(Provider, :malformed_transit_response)}

  defp unwrap(%AshVault.Key{} = key) do
    case Provider.unwrap_mac(key) do
      {:ok, pair} -> {:ok, pair}
      :error -> {:error, :opaque_key_unsupported}
    end
  end

  defp unwrap(_key), do: {:error, :requires_open_bao_transit_key_provider}

  defp path(suffix), do: Transport.transit_path(Provider, suffix)
end
