defmodule AshVault.Macaroon.OpenBaoTransitTest do
  @moduledoc """
  Macaroons over `AshVault.KeyProviders.OpenBaoTransit`, against a live OpenBao: the
  root signature is an OpenBao `transit/hmac` at the token's stated key version, the
  caveat chain is local. Tagged `:openbao` and skipped when the server is unreachable.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.InvalidMacaroon
  alias AshVault.Errors.MacaroonRevoked
  alias AshVault.KeyProviders.OpenBao
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider
  alias AshVault.Test.Support.TransitVault
  alias AshVault.Test.TransitApiClient

  ExUnit.configure(exclude: Enum.uniq([:openbao | ExUnit.configuration()[:exclude] || []]))

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @token System.get_env("BAO_TOKEN") || "ashvault-root"
  @kv_mount "ashvault"
  @transit_mount "transit"

  @scope_prefix "mcm"
  @name_prefixes [
    "ashvault_nx_" <> Base.url_encode64(@scope_prefix, padding: false),
    "ashvault_" <> Base.url_encode64(@scope_prefix, padding: false)
  ]

  @server_up (case URI.parse(@address) do
                %URI{host: host, port: port} when is_binary(host) and is_integer(port) ->
                  case :gen_tcp.connect(String.to_charlist(host), port, [:binary], 1_000) do
                    {:ok, socket} ->
                      :gen_tcp.close(socket)
                      true

                    _ ->
                      false
                  end

                _ ->
                  false
              end)

  @moduletag :openbao

  if not @server_up do
    @moduletag skip: "OpenBao is not reachable at #{@address}"
  end

  setup_all do
    put_config()
    :ok = Provider.setup()
    on_exit(&clean_up/0)
    :ok
  end

  setup do
    put_config()
    tenant = @scope_prefix <> "_#{System.unique_integer([:positive])}"
    client = Ash.create!(TransitApiClient, %{org_id: tenant}, tenant: tenant)
    {:ok, token} = TransitApiClient.mint_transit(client.id, %{}, tenant: tenant)
    %{tenant: tenant, client: client, token: token}
  end

  defp reason({:error, %Ash.Error.Invalid{errors: [%{reason: reason} = error]}}),
    do: {error.__struct__, reason}

  test "a token minted through transit verifies, and attenuation chains locally", ctx do
    assert {:ok, record} = TransitApiClient.transit_by_token(ctx.token)
    assert record.id == ctx.client.id

    {:ok, narrower} = AshVault.Macaroon.attenuate(ctx.token, ip: "10.0.0.1")

    assert {:ok, _} =
             TransitApiClient.transit_by_token(narrower, context: %{remote_ip: "10.0.0.1"})

    assert reason(TransitApiClient.transit_by_token(narrower, context: %{remote_ip: "10.0.0.2"})) ==
             {InvalidMacaroon, {:caveat_failed, :ip}}
  end

  test "a tampered token is invalid, not an outage", ctx do
    {:ok, env} = AshVault.Macaroon.Envelope.decode(ctx.token)
    {:ok, forged} = AshVault.Macaroon.Envelope.encode(%{env | id: Ash.UUID.generate()})

    assert reason(TransitApiClient.transit_by_token(forged)) == {InvalidMacaroon, :bad_signature}
  end

  test "rotating the transit :mac key retires the old version", ctx do
    {:ok, 2} = TransitVault.rotate!(ctx.tenant, purpose: :mac)
    assert reason(TransitApiClient.transit_by_token(ctx.token)) == {MacaroonRevoked, :key_retired}

    {:ok, fresh} = TransitApiClient.mint_transit(ctx.client.id, %{}, tenant: ctx.tenant)
    assert {:ok, _} = TransitApiClient.transit_by_token(fresh)
  end

  test "destroying the scope revokes the token", ctx do
    :ok = TransitVault.destroy!(ctx.tenant)

    assert reason(TransitApiClient.transit_by_token(ctx.token)) ==
             {InvalidMacaroon, :bad_signature}
  end

  defp put_config do
    config = [address: @address, token: @token, kv_mount: @kv_mount]

    for provider <- [Provider, OpenBao] do
      previous = Application.get_env(:ash_vault, provider)
      Application.put_env(:ash_vault, provider, config)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_vault, provider, previous),
          else: Application.delete_env(:ash_vault, provider)
      end)
    end

    :ok
  end

  defp raw(method, path, body \\ nil) do
    options = [
      method: method,
      base_url: @address,
      url: path,
      headers: [{"x-vault-token", @token}],
      receive_timeout: 5_000,
      retry: false
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options

    case options |> Req.new() |> Req.request() do
      {:ok, response} -> response
      {:error, exception} -> exception
    end
  end

  defp clean_up do
    for name <- list("/v1/#{@transit_mount}/keys"),
        Enum.any?(@name_prefixes, &String.starts_with?(name, &1)) do
      raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{deletion_allowed: true})
      raw(:delete, "/v1/#{@transit_mount}/keys/#{name}")
    end

    for name <- list("/v1/#{@kv_mount}/metadata/tombstones"),
        Enum.any?(@name_prefixes, &String.starts_with?(name, &1)) do
      raw(:delete, "/v1/#{@kv_mount}/metadata/tombstones/#{name}")
    end

    :ok
  end

  defp list(path) do
    case raw(:get, path <> "?list=true") do
      %Req.Response{status: 200, body: %{"data" => %{"keys" => keys}}} when is_list(keys) -> keys
      _ -> []
    end
  end
end
