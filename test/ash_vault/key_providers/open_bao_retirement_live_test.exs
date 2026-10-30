for {module, provider} <- [
      {AshVault.KeyProviders.OpenBaoRetirementLiveTest, AshVault.KeyProviders.OpenBao},
      {AshVault.KeyProviders.OpenBaoTransitRetirementLiveTest,
       AshVault.KeyProviders.OpenBaoTransit}
    ] do
  defmodule module do
    use ExUnit.Case, async: false
    alias AshVault.KeyProviders.OpenBao.Transport
    @provider provider
    @mount "ashvault-transit"
    @address System.get_env("BAO_ADDR", "http://127.0.0.1:8200")
    @token System.get_env("BAO_TOKEN", "ashvault-root")
    @moduletag :openbao_plugin

    use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.configure_provider/1

    def configure_provider(_context) do
      previous = Application.get_env(:ash_vault, @provider)

      Application.put_env(:ash_vault, @provider,
        address: @address,
        token: @token,
        transit_mount: @mount,
        server_retirement: true
      )

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_vault, @provider, previous),
          else: Application.delete_env(:ash_vault, @provider)
      end)

      assert :ok = @provider.setup()

      %{
        provider: @provider,
        scope: fn -> "plugin-" <> Ash.UUID.generate() end,
        opaque_keys?: @provider == AshVault.KeyProviders.OpenBaoTransit,
        key_bytes: 32
      }
    end

    test "all purposes stay absent and raw creation stays forbidden after retirement", %{
      scope: scope
    } do
      scope = scope.()
      assert {:ok, _} = @provider.current_key(scope)
      assert {:ok, _} = @provider.current_key(scope, :mac)

      if @provider == AshVault.KeyProviders.OpenBao,
        do: assert({:ok, _} = apply(@provider, :lookup_key, [scope]))

      assert {:ok, 2} = @provider.rotate(scope)
      assert :ok = @provider.destroy(scope)
      name = @provider.key_name(scope)

      for suffix <- ["", ".mac", "_lookup"] do
        assert {:ok, %{status: 404}} =
                 Transport.get(
                   @provider,
                   Transport.transit_path(@provider, "/keys/#{name}#{suffix}")
                 )

        assert {:error, :destroyed} =
                 Transport.post(
                   @provider,
                   Transport.transit_path(@provider, "/keys/#{name}#{suffix}"),
                   %{exportable: true}
                 )
      end

      assert :ok = @provider.destroy(scope)
    end

    test "operator initialization imports legacy erasures before allowing key operations", %{
      scope: scope
    } do
      scope = scope.()
      mount = "migration-" <> Ash.UUID.generate()
      kv = "migration-kv-" <> Ash.UUID.generate()
      headers = [{"x-vault-token", @token}]

      assert %{status: 204} =
               Req.post!(@address <> "/v1/sys/mounts/#{mount}",
                 headers: headers,
                 json: %{type: "ashvault-transit", plugin_version: "v0.1.0"}
               )

      on_exit(fn ->
        Req.delete!(@address <> "/v1/sys/mounts/#{mount}", headers: headers)
        Req.delete!(@address <> "/v1/sys/mounts/#{kv}", headers: headers)
      end)

      config = Application.get_env(:ash_vault, @provider)

      Application.put_env(
        :ash_vault,
        @provider,
        Keyword.merge(config, transit_mount: mount, kv_mount: kv)
      )

      assert :ok = Transport.ensure_kv_mount(@provider)
      name = @provider.key_name(scope)
      await_kv_ready(name, 50)
      assert :ok = Transport.write_tombstone(@provider, name)
      assert {:error, %AshVault.Errors.ProviderUnavailable{}} = @provider.setup()
      assert :ok = Transport.initialize_retirement(@provider)
      assert :ok = @provider.setup()
      # Prove the server marker, independently of the old KV decision.
      for suffix <- ["", ".mac", "_lookup"] do
        assert {:error, :destroyed} =
                 Transport.post(
                   @provider,
                   Transport.transit_path(@provider, "/keys/#{name}#{suffix}"),
                   %{exportable: true}
                 )
      end

      assert {:ok, _} = @provider.current_key(scope <> "-live")
      assert :ok = Transport.initialize_retirement(@provider)
    end

    # KV-v2 performs an asynchronous storage upgrade after mounting. A successful
    # mount response alone does not mean that its data routes are ready yet.
    defp await_kv_ready(name, attempts) do
      case Transport.check_legacy_tombstone(@provider, name) do
        :absent ->
          :ok

        _ when attempts > 0 ->
          Process.sleep(100)
          await_kv_ready(name, attempts - 1)

        other ->
          flunk("fresh test KV did not become ready: #{inspect(other)}")
      end
    end

    if @provider == AshVault.KeyProviders.OpenBaoTransit do
      alias AshVault.Test.Support.{Helpers, TransitVault}
      alias AshVault.Errors.KeyDestroyed

      for operation <- [:encrypt, :decrypt, :mac, :verify] do
        @tag operation: operation
        test "retirement between handle acquisition and #{operation} remains KeyDestroyed",
             %{scope: scope} = context do
          scope = scope.()
          ctx = Helpers.context_for(scope)
          blob = TransitVault.encrypt!("secret", ctx)
          {version, tag} = TransitVault.mac!("payload", ctx)
          operation = context.operation

          path =
            case operation do
              :encrypt -> "/encrypt/"
              :decrypt -> "/decrypt/"
              :mac -> "/hmac/"
              :verify -> "/verify/"
            end

          Req.Test.set_req_test_to_shared(context)
          original = Application.get_env(:ash_vault, @provider)

          Application.put_env(
            :ash_vault,
            @provider,
            Keyword.put(original, :req_options, plug: {Req.Test, __MODULE__})
          )

          Req.Test.stub(__MODULE__, fn conn ->
            if conn.request_path =~ path do
              # Retire through a separate HTTP connection, after the provider has
              # already returned the handle used by this request.
              response =
                Req.post!(
                  @address <> "/v1/#{@mount}/ashvault/retire/#{@provider.key_name(scope)}",
                  headers: [{"x-vault-token", @token}],
                  json: %{},
                  retry: false
                )

              assert response.status == 200
            end

            {:ok, body, conn} = Plug.Conn.read_body(conn)

            response =
              Req.request!(
                url: @address <> conn.request_path,
                method: conn.method |> String.downcase() |> String.to_existing_atom(),
                headers: [{"x-vault-token", @token}],
                body: body,
                retry: false
              )

            Req.Test.json(Plug.Conn.put_status(conn, response.status), response.body)
          end)

          assert_raise KeyDestroyed, fn ->
            case operation do
              :encrypt -> TransitVault.encrypt!("secret", ctx)
              :decrypt -> TransitVault.decrypt!(blob, ctx)
              :mac -> TransitVault.mac!("payload", ctx)
              :verify -> TransitVault.verify_mac!("payload", version, tag, ctx)
            end
          end
        end
      end
    end
  end
end
