defmodule AshVault.Macaroon do
  @moduledoc """
  Macaroons for Ash resources: bearer tokens that any holder can **attenuate** — add
  caveats that narrow what the token allows — without contacting the issuer, and that
  the issuer can revoke at three levels.

      ash_vault do
        vault MyApp.Vault

        macaroon :api do
          prefix "myapp"
          identity :id
          revoked_when expr(not is_nil(revoked_at))
          default_ttl 86_400

          caveat :ip, :string, check: MyApp.Caveats.Ip
          caveat :actions, {:array, :string},
            phase: :authorize,
            check: AshVault.Macaroon.Caveats.ActionIn
        end
      end

  generates a `:mint_api` generic action and a `:api_by_token` read action, each with
  a code interface. See [Macaroons](macaroons.md) for the full guide, and
  `AshVault.Macaroon.Envelope` and `AshVault.Macaroon.Chain` for the frozen format.

  This module holds the one operation that needs no key and no resource:
  `attenuate/2`.
  """

  alias AshVault.Macaroon.CaveatCodec
  alias AshVault.Macaroon.Chain
  alias AshVault.Macaroon.Envelope

  @doc """
  Append caveats to a token, returning a token that allows at most what the original
  allowed.

  Pure: no vault, no key, no resource. Anyone holding a token can call it, which is the
  point — a service can hand a narrower token to a less trusted one. The new caveats
  extend the signature chain from the token's own signature, so they cannot be removed
  again; the verifier rejects any caveat its macaroon does not declare, or whose value
  type disagrees with the declaration.

  `caveats` is a keyword list or a list of `{name, value}`; a name may repeat (every
  occurrence must hold). Values are strings, integers, booleans, `DateTime`s, or
  non-empty lists of strings or of integers.

      {:ok, narrower} = AshVault.Macaroon.attenuate(token, actions: ["read"], ip: "10.0.0.7")

  `{:error, :malformed}` for something that is not a token, and
  `{:error, :invalid_caveat}` for a name or value outside the format or a result that
  would exceed the caveat limits. Attenuating never produces a token the verifier would
  reject for its shape.

  Attenuating does not check the signature — it cannot. Attenuating a forged token gives
  another forged token.
  """
  @spec attenuate(binary(), keyword() | [{atom() | binary(), term()}]) ::
          {:ok, binary()} | {:error, :malformed | :invalid_caveat}
  def attenuate(token, caveats) when is_list(caveats) do
    with {:ok, env} <- decode(token),
         {:ok, encoded} <- encode_all(caveats),
         true <- length(env.caveats) + length(encoded) <= Envelope.max_caveats() || :too_many do
      Envelope.encode(%{
        env
        | caveats: env.caveats ++ encoded,
          sig: Chain.extend(env.sig, encoded)
      })
    else
      :too_many -> {:error, :invalid_caveat}
      {:error, :malformed} -> {:error, :malformed}
      {:error, _reason} -> {:error, :invalid_caveat}
    end
  end

  defp decode(token) do
    case Envelope.decode(token) do
      {:ok, env} -> {:ok, env}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  defp encode_all(caveats) do
    caveats
    |> Enum.reduce_while({:ok, []}, fn
      {name, value}, {:ok, acc} when (is_atom(name) and not is_nil(name)) or is_binary(name) ->
        with {:ok, tag} <- CaveatCodec.infer_tag(value),
             {:ok, bytes} <- CaveatCodec.encode(to_string(name), tag, value) do
          {:cont, {:ok, [bytes | acc]}}
        else
          _ -> {:halt, {:error, :invalid_caveat}}
        end

      _other, _acc ->
        {:halt, {:error, :invalid_caveat}}
    end)
    |> case do
      {:ok, encoded} -> {:ok, Enum.reverse(encoded)}
      error -> error
    end
  end
end
