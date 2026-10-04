defmodule AshVault.Mac do
  @moduledoc """
  Behaviour for message authentication codes: the sibling of `AshVault.Cipher` for data
  that must be *authenticated* rather than *hidden*.

  A MAC is computed under a scope's **`:mac` key** — a keyring of its own, minted,
  rotated and destroyed by the vault's key provider alongside the `:data` keyring the
  cipher uses, but never the same key and never derived from it. See
  [Key purposes and MACs](key-purposes-and-macs.md).

  Two implementations ship:

    * `AshVault.Macs.HmacSha256` — HMAC-SHA256 in process, over a raw 32-byte key.
    * `AshVault.Macs.OpenBaoTransit` — HMAC-SHA256 computed inside OpenBao through
      `transit/hmac`, so the key never enters the BEAM.

  ## The frame

  Both compute HMAC-SHA256 over the same frozen byte string, built by `frame/2`:

      "ashvault:mac:v1|" <> <<byte_size(aad)::unsigned-big-64>> <> aad <> data

  The associated data is length-prefixed, so no `(aad, data)` pair can be re-split into
  another pair with the same bytes, and the domain prefix keeps a MAC computed here from
  ever equalling an HMAC some other part of an application computed under the same key.
  OpenBao's `transit/hmac` has no associated-data parameter, which is why the binding is
  done in the frame and not left to the backend: framing it identically in both
  implementations is what makes a tag from one verifiable by the other for the same key.

  ## Tags are raw bytes

  `c:mac/3` returns the raw 32-byte HMAC output, never a hex or `vault:v1:` string. A tag
  is something later layers build on — a macaroon's signature chain HMACs each caveat
  under the previous signature — so it must be usable as key material itself.

  A tag is also a **bearer credential**. Implementations must not put it, the data, or
  the key into an error, a log line or telemetry.

  ## Error conventions

  The same as `AshVault.Cipher`, so `AshVault.Vault.Runtime` classifies both alike:

    * `{:error, {:invalid_key_size, actual}}` — a configuration fault, reported as
      `AshVault.Errors.KeySizeMismatch`
    * `{:error, :opaque_key_unsupported}` — this MAC cannot use the provider's
      `AshVault.Key` handle, reported as `AshVault.Errors.OpaqueKeyUnsupported`
    * `{:error, %AshVault.Errors.ProviderUnavailable{}}` — a backend outage, retryable

  `c:verify/4` additionally returns `{:error, :invalid_tag}` — and **only** for a tag that
  positively failed verification. That is the one answer reported as
  `AshVault.Errors.InvalidMac`; an outage must never be reported as a forgery, nor a
  forgery as an outage.
  """

  @frame_prefix "ashvault:mac:v1|"

  @doc "The stable identifier of this MAC construction."
  @callback id() :: atom()

  @doc "The exact key size, in bytes, this MAC requires."
  @callback key_bytes() :: pos_integer()

  @doc """
  Compute a tag over `data`, bound to `aad`, under `key`.

  `key` is an `AshVault.Key.t()`: raw bytes, or an opaque handle for a MAC that runs
  where the key lives.
  """
  @callback mac(data :: binary(), key :: AshVault.Key.t(), aad :: binary()) ::
              {:ok, binary()} | {:error, term()}

  @doc """
  Verify `tag` over `data` and `aad` under `key`.

  Returns `{:error, :invalid_tag}` only for a tag that does not verify. Implementations
  must compare in constant time.
  """
  @callback verify(data :: binary(), tag :: binary(), key :: AshVault.Key.t(), aad :: binary()) ::
              :ok | {:error, :invalid_tag} | {:error, term()}

  @doc """
  The frozen byte string every shipped MAC authenticates.

  ## Examples

      iex> AshVault.Mac.frame("payload", "aad")
      "ashvault:mac:v1|" <> <<3::64>> <> "aad" <> "payload"

      iex> AshVault.Mac.frame("ab", "c") == AshVault.Mac.frame("b", "ca")
      false

  """
  @spec frame(binary(), binary()) :: binary()
  def frame(data, aad) when is_binary(data) and is_binary(aad) do
    @frame_prefix <> <<byte_size(aad)::unsigned-big-64>> <> aad <> data
  end
end
