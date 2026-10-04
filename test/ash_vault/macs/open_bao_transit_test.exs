defmodule AshVault.Macs.OpenBaoTransitTest do
  @moduledoc """
  `AshVault.Macs.OpenBaoTransit` against a live OpenBao, through a vault.

  Tagged `:openbao`, excluded by default, and skipped entirely when the server is
  unreachable:

      mix test --include openbao test/ash_vault/macs/open_bao_transit_test.exs
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.InvalidMac
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.KeyProviders.OpenBao
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider
  alias AshVault.Macs.HmacSha256
  alias AshVault.Macs.OpenBaoTransit, as: Mac
  alias AshVault.Test.Support.Helpers
  alias AshVault.Test.Support.TransitVault

  ExUnit.configure(exclude: Enum.uniq([:openbao | ExUnit.configuration()[:exclude] || []]))

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @token System.get_env("BAO_TOKEN") || "ashvault-root"
  @kv_mount "ashvault"
  @transit_mount "transit"

  @scope_prefix "mcx"
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
    %{tenant: @scope_prefix <> "_#{System.unique_integer([:positive])}"}
  end

  describe "through a vault" do
    test "mac! then verify_mac!", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)

      assert {1, tag} = TransitVault.mac!("payload", ctx)
      assert byte_size(tag) == 32
      assert :ok = TransitVault.verify_mac!("payload", 1, tag, ctx)
    end

    test "tampering, another tenant, or an unknown version all fail distinctly",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      other = Helpers.context_for(tenant <> "_other")
      {1, tag} = TransitVault.mac!("payload", ctx)
      {1, _} = TransitVault.mac!("payload", other)
      <<first, rest::binary>> = tag

      assert_raise InvalidMac, fn -> TransitVault.verify_mac!("Payload", 1, tag, ctx) end

      assert_raise InvalidMac, fn ->
        TransitVault.verify_mac!("payload", 1, <<Bitwise.bxor(first, 1), rest::binary>>, ctx)
      end

      assert_raise InvalidMac, fn -> TransitVault.verify_mac!("payload", 1, tag, other) end
      assert_raise KeyNotFound, fn -> TransitVault.verify_mac!("payload", 2, tag, ctx) end
    end

    test "rotating :mac keeps old tags verifiable and leaves the data key alone",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)
      {1, old} = TransitVault.mac!("payload", ctx)

      assert {:ok, 2} = TransitVault.rotate!(tenant, purpose: :mac)
      assert {2, new} = TransitVault.mac!("payload", ctx)
      refute old == new

      assert :ok = TransitVault.verify_mac!("payload", 1, old, ctx)
      assert :ok = TransitVault.verify_mac!("payload", 2, new, ctx)
      assert {:ok, %{"latest_version" => 1}} = read_key(Provider.key_name(tenant))
      assert TransitVault.decrypt!(blob, ctx) == "secret"
    end

    test "destroy! revokes every tag and deletes the hmac transit key", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      {1, tag} = TransitVault.mac!("payload", ctx)

      :ok = TransitVault.destroy!(tenant)

      assert_raise KeyDestroyed, fn -> TransitVault.verify_mac!("payload", 1, tag, ctx) end
      assert_raise KeyDestroyed, fn -> TransitVault.mac!("payload", ctx) end
      assert :missing = read_key(Provider.mac_key_name(tenant))
    end

    test "the :mac transit key is never exportable, and is not the data key",
         %{tenant: tenant} do
      {1, _} = TransitVault.mac!("payload", Helpers.context_for(tenant))
      name = Provider.mac_key_name(tenant)

      assert {:ok, %{"exportable" => false, "keys" => %{"1" => _}}} = read_key(name)
      refute name == Provider.key_name(tenant)

      assert %Req.Response{status: status} =
               raw(:get, "/v1/#{@transit_mount}/export/hmac-key/#{name}/1")

      assert status in 400..499
    end

    test "a :mac transit key created exportable elsewhere is refused, not used",
         %{tenant: tenant} do
      name = Provider.mac_key_name(tenant)

      assert %Req.Response{status: 200} =
               raw(:post, "/v1/#{@transit_mount}/keys/#{name}", %{
                 type: "aes256-gcm96",
                 exportable: true
               })

      assert_raise AshVault.Errors.ProviderUnavailable, ~r/exportable_key/, fn ->
        TransitVault.mac!("payload", Helpers.context_for(tenant))
      end
    end
  end

  # The framing argument made concrete: for the same key bytes, transit's HMAC over the
  # frame is the in-process HMAC over the frame. Uses the exporting provider's `:mac`
  # key, whose bytes can be fetched, and drives transit/hmac on that same key by name.
  describe "agreement with AshVault.Macs.HmacSha256" do
    test "the same key gives the same tag in both", %{tenant: tenant} do
      assert {:ok, %{version: 1, key: bytes}} = OpenBao.current_key(tenant, :mac)
      handle = Provider.mac_handle(OpenBao.mac_key_name(tenant), 1)
      aad = AshVault.Vault.Runtime.build_aad(tenant, Helpers.context_for(tenant))

      assert {:ok, local} = HmacSha256.mac("payload", bytes, aad)
      assert {:ok, ^local} = Mac.mac("payload", handle, aad)

      assert :ok = Mac.verify("payload", local, handle, aad)
      assert {:error, :invalid_tag} = Mac.verify("payload", local, handle, aad <> "x")
      assert :ok = HmacSha256.verify("payload", local, bytes, aad)
    end
  end

  defp read_key(name) do
    case raw(:get, "/v1/#{@transit_mount}/keys/#{name}") do
      %Req.Response{status: 200, body: %{"data" => data}} -> {:ok, data}
      %Req.Response{status: 404} -> :missing
      other -> {:error, other}
    end
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
