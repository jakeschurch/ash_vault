defmodule AshVault.Ciphers.OpenBaoTransit do
  @moduledoc """
  The AEAD half of `AshVault.KeyProviders.OpenBaoTransit`: encryption and decryption
  happen inside OpenBao, so no key material ever enters the BEAM.

  Every other `AshVault.Cipher` is a local `:crypto` call over a key the provider handed
  it. This one has no key. It receives an `AshVault.Key` handle naming a transit key and
  a version, and turns each `encrypt/3` and `decrypt/3` into one HTTP call to
  `transit/encrypt` / `transit/decrypt`.

  > #### One network round trip per value, *here* {: .warning}
  >
  > This module contributes one call per `encrypt/3` and one per `decrypt/3`. The value
  > costs **three** end to end: `AshVault.KeyProviders.OpenBaoTransit` reads the scope's
  > tombstone and the transit key's metadata before handing over the handle this module
  > uses. Measured, not estimated — see the `[:finch, :request, :stop]` counter in
  > `test/ash_vault/ciphers/open_bao_transit_test.exs`, and
  > `AshVault.KeyProviders.OpenBaoTransit` for when that trade is worth making.

  ## AAD is real here, verified against the live server

  `transit/encrypt` accepts `associated_data`, and OpenBao binds it into the GCM tag.
  Verified against openbao 2.6.2: decrypting with different associated data, or with
  none, returns `400 "cipher: message authentication failed"`. A control probe sending a
  genuinely unrecognised parameter comes back with
  `warnings: ["Endpoint ignored these unrecognized parameters: [bogus_param]"]`, and
  `associated_data` produces no such warning — so it is being consumed, not dropped.

  The AAD is `AshVault.Vault.Runtime.build_aad/2` verbatim, base64-encoded for the JSON
  body. Cross-tenant, cross-resource and cross-field ciphertext substitution therefore
  fail exactly as they do under `AshVault.Ciphers.AES.GCM`. This guarantee is **not**
  weakened by moving the AEAD into OpenBao.

  `context` (transit's key-derivation input) is deliberately not used: it only applies to
  `derived: true` keys and would change what a key *is*, rather than binding data to a
  ciphertext.

  ## What goes in the envelope

  The transit ciphertext is a self-describing string, `vault:v<N>:<base64>`. It is stored
  **verbatim** in the envelope's `ciphertext` slot, with empty `nonce` and `tag`:

    * The nonce and tag are inside transit's own base64 blob. There is nothing to put in
      those slots, and the frozen v1 envelope layout permits zero-length values for both.
    * Re-synthesising the `vault:v<N>:` prefix from the envelope's `key_version` on the
      way out would mean assuming the prefix format forever. OpenBao already emits other
      shapes for other key classes; storing the server's own string means a future shape
      keeps working with no envelope change.
    * The version is therefore recorded twice — in the envelope header and inside the
      transit string. `decrypt/3` requires them to agree, which costs nothing and turns a
      spliced ciphertext body into a clean refusal before the round trip.

  Envelope `cipher` id is `:openbao_transit_v1`, so a value encrypted this way decrypts
  through this module forever, even if the vault's default cipher changes later.

  ## Pairing

  This cipher only works with `AshVault.KeyProviders.OpenBaoTransit`. Given raw key bytes
  from any other provider it returns `{:error, :requires_open_bao_transit_key_provider}` rather than
  inventing a transit key name — there is no correct name to invent. Conversely, every
  other cipher declines this provider's handle with `{:error, :opaque_key_unsupported}`.
  """

  @behaviour AshVault.Cipher

  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider

  @doc """
  The stable cipher id, `:openbao_transit_v1`.
  """
  @impl AshVault.Cipher
  @spec id() :: :openbao_transit_v1
  def id, do: :openbao_transit_v1

  @doc """
  The key size in bytes, `32`, matching `aes256-gcm96`.

  Nominal only: this cipher never sees key bytes. It exists because
  `c:AshVault.Cipher.key_bytes/0` is a required callback and
  `AshVault.Vault.verify_key_sizes!/2` reads it. `AshVault.KeyProviders.OpenBaoTransit`
  deliberately does not export `key_bytes/0`, so that compile-time comparison does not
  fire for the supported pairing.
  """
  @impl AshVault.Cipher
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: 32

  @doc """
  Encrypt through `transit/encrypt`, binding `aad` as `associated_data`.

  The encrypt is pinned to the handle's `key_version`, so a rotation racing this call
  cannot silently produce a ciphertext under a version the envelope does not name.
  """
  @impl AshVault.Cipher
  @spec encrypt(binary(), AshVault.Key.t(), binary()) ::
          {:ok, AshVault.Cipher.payload()} | {:error, term()}
  def encrypt(plaintext, key, aad) when is_binary(plaintext) and is_binary(aad) do
    with {:ok, {name, version}} <- unwrap(key) do
      body = %{
        plaintext: Base.encode64(plaintext),
        associated_data: Base.encode64(aad),
        key_version: version
      }

      case Transport.post(Provider, path("/encrypt/#{name}"), body) do
        {:ok, %{status: 200, body: response}} ->
          response |> Transport.data() |> Map.get("ciphertext") |> to_payload()

        {:ok, response} ->
          Transport.unavailable!(Provider, response)

        {:error, error} ->
          {:error, error}
      end
    end
  end

  def encrypt(_plaintext, _key, _aad), do: {:error, :requires_open_bao_transit_key_provider}

  defp to_payload(ciphertext) when is_binary(ciphertext) do
    {:ok, %{ciphertext: ciphertext, nonce: "", tag: ""}}
  end

  defp to_payload(_other) do
    {:error, Transport.unavailable(Provider, :malformed_transit_response)}
  end

  @doc """
  Decrypt through `transit/decrypt`, verifying `aad` as `associated_data`.

  Returns `{:error, :auth_failed}` — which `AshVault.Vault.Runtime` reports as
  `AshVault.Errors.CiphertextIntegrityFailed` — only for a genuine authentication
  failure. Every other failure (a deleted key, a `403`, an unreachable server) is
  returned as `AshVault.Errors.ProviderUnavailable`, so an outage is never reported to an
  operator as "your data was tampered with".
  """
  @impl AshVault.Cipher
  @spec decrypt(AshVault.Cipher.payload(), AshVault.Key.t(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt(%{ciphertext: ciphertext}, key, aad)
      when is_binary(ciphertext) and is_binary(aad) do
    with {:ok, {name, version}} <- unwrap(key),
         :ok <- check_version(ciphertext, version) do
      body = %{ciphertext: ciphertext, associated_data: Base.encode64(aad)}

      case Transport.post(Provider, path("/decrypt/#{name}"), body) do
        {:ok, %{status: 200, body: response}} ->
          response |> Transport.data() |> Map.get("plaintext") |> decode_plaintext()

        # The one status that can be authentication rather than infrastructure. Only a
        # positively identified MAC failure is reported as tampering; "encryption key
        # not found" arrives as the same 400 and is an outage, not a forgery.
        {:ok, %{status: 400} = response} ->
          if auth_failed?(response) do
            {:error, :auth_failed}
          else
            Transport.unavailable!(Provider, response)
          end

        {:ok, response} ->
          Transport.unavailable!(Provider, response)

        {:error, error} ->
          {:error, error}
      end
    end
  end

  # A payload whose ciphertext slot is not a binary is not a transit ciphertext.
  def decrypt(_payload, _key, _aad), do: {:error, :auth_failed}

  # Which 400s are about the stored bytes, and which are about the server.
  #
  # Verified against openbao 2.6.2, decrypting deliberately broken input:
  #
  #   * a flipped byte, or the wrong `associated_data` → "cipher: message authentication
  #     failed" — a forgery or a substitution, exactly what the AEAD is for
  #   * a body that is not base64 → "invalid ciphertext: could not decode base64"
  #   * an empty or short body → "invalid ciphertext length"
  #   * a deleted key → "encryption key not found" — infrastructure, NOT the bytes
  #
  # The first three are all "the value in your database is not the value we wrote", which
  # is `AshVault.Errors.CiphertextIntegrityFailed`. Classifying corrupted bytes as an
  # outage would tell an operator to retry damage that will never heal; classifying a
  # missing key as tampering would send them hunting an attacker who does not exist.
  defp auth_failed?(response) do
    message = Transport.error_message(response)

    message =~ "message authentication failed" or message =~ "invalid ciphertext"
  end

  defp decode_plaintext(encoded) when is_binary(encoded) do
    case Base.decode64(encoded) do
      {:ok, plaintext} -> {:ok, plaintext}
      :error -> {:error, Transport.unavailable(Provider, :malformed_transit_response)}
    end
  end

  defp decode_plaintext(_other) do
    {:error, Transport.unavailable(Provider, :malformed_transit_response)}
  end

  # The envelope's key_version and the version transit embedded in its own ciphertext
  # must agree. They are written from the same handle, so disagreement means the stored
  # bytes were spliced — refuse before spending a round trip on it.
  defp check_version(ciphertext, version) do
    case parse_version(ciphertext) do
      {:ok, ^version} -> :ok
      {:ok, _other} -> {:error, :auth_failed}
      # Not a `vault:vN:` string at all. Foreign bytes in the ciphertext slot.
      :error -> {:error, :auth_failed}
    end
  end

  @doc """
  The key version embedded in a transit ciphertext string.

  Public so the envelope-versus-transit agreement check can be tested directly.

  ## Examples

      iex> AshVault.Ciphers.OpenBaoTransit.parse_version("vault:v3:abcdef")
      {:ok, 3}

      iex> AshVault.Ciphers.OpenBaoTransit.parse_version("not a transit ciphertext")
      :error

  """
  @spec parse_version(binary()) :: {:ok, pos_integer()} | :error
  def parse_version("vault:v" <> rest) do
    case :binary.split(rest, ":") do
      [digits, _body] -> parse_digits(digits)
      _other -> :error
    end
  end

  def parse_version(_other), do: :error

  defp parse_digits(digits) do
    case Integer.parse(digits) do
      {version, ""} when version > 0 -> {:ok, version}
      _other -> :error
    end
  end

  # An `%AshVault.Key{}` from some *other* opaque provider is not usable here, and must
  # not be mistaken for a raw-key pairing mistake.
  defp unwrap(%AshVault.Key{} = key) do
    case Provider.unwrap(key) do
      {:ok, pair} -> {:ok, pair}
      :error -> {:error, :opaque_key_unsupported}
    end
  end

  defp unwrap(_key), do: {:error, :requires_open_bao_transit_key_provider}

  # Address, token, mounts and timeouts come from the PROVIDER's configuration block,
  # never from the handle: a handle that carried a token would put the token into every
  # key_info map, every cache entry and every stack trace.
  defp path(suffix), do: Transport.transit_path(Provider, suffix)
end
