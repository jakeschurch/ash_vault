defmodule AshVault.Macaroon.Chain do
  @moduledoc """
  The macaroon signature chain.

      sig_0 = Vault.mac_at!(root_data(token), token.key_version, ctx)
      sig_i = HMAC-SHA256(sig_{i-1}, "ashvault:macaroon:caveat:v1|" <> len64(caveat_i) <> caveat_i)
      token.sig = sig_n

  `sig_0` is computed by the vault under the scope's `:mac` key — inside OpenBao for
  `AshVault.Macs.OpenBaoTransit` — and is itself bound to the scope, resource and
  macaroon name through the vault's associated data. Every later link is computed
  locally with `AshVault.Macs.HmacSha256.hmac/2`, keyed by the previous signature: a
  holder can append a caveat (extend the chain) but cannot remove one, because that
  would need the earlier signature, which the token does not carry.

  Each link carries its own domain prefix and a 64-bit length frame, so a chain step can
  never collide with the vault's `ashvault:mac:v1|` frame or with any other HMAC an
  application computes, and a caveat boundary can never be re-split.

  Comparison of the final signature is constant-time (`:crypto.hash_equals/2`).
  """

  alias AshVault.Macaroon.Envelope
  alias AshVault.Macs.HmacSha256

  @root_prefix "ashvault:macaroon:root:v1|"
  @caveat_prefix "ashvault:macaroon:caveat:v1|"

  @doc """
  The bytes the root signature covers: the prefix, envelope version, scope, key version
  and identity, each length-framed.
  """
  @spec root_data(Envelope.t()) :: binary()
  def root_data(%Envelope{} = token) do
    IO.iodata_to_binary([
      @root_prefix,
      frame(token.prefix),
      <<token.version::8>>,
      frame(token.scope),
      <<token.key_version::unsigned-big-64>>,
      frame(token.id)
    ])
  end

  @doc "One link of the chain: the signature after appending `caveat` to `sig`."
  @spec step(binary(), binary()) :: binary()
  def step(sig, caveat) when byte_size(sig) == 32 and is_binary(caveat) do
    HmacSha256.hmac(sig, @caveat_prefix <> frame(caveat))
  end

  @doc "Fold `caveats` onto `sig`, in order."
  @spec extend(binary(), [binary()]) :: binary()
  def extend(sig, caveats), do: Enum.reduce(caveats, sig, &step(&2, &1))

  @doc "Constant-time comparison of two signatures. `false` for anything not 32 bytes."
  @spec equal?(term(), term()) :: boolean()
  def equal?(a, b)
      when is_binary(a) and is_binary(b) and byte_size(a) == 32 and byte_size(b) == 32,
      do: :crypto.hash_equals(a, b)

  def equal?(_a, _b), do: false

  defp frame(bytes), do: <<byte_size(bytes)::unsigned-big-64, bytes::binary>>
end
