defmodule AshVault.KeyProviders.OpenBaoTransitTest do
  @moduledoc """
  Contract and behaviour suite for `AshVault.KeyProviders.OpenBaoTransit`, run against a
  live OpenBao server.

  The suite is tagged `:openbao` and excluded by default, so `mix test` stays green
  without Docker. Run it with:

      mix test --include openbao test/ash_vault/key_providers/open_bao_transit_test.exs

  If the server is unreachable when the suite loads, the whole module is additionally
  skipped, so even `--include openbao` degrades to "skipped", never "failed".
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao
  alias AshVault.KeyProviders.OpenBaoTransit, as: Transit

  ExUnit.configure(exclude: Enum.uniq([:openbao | ExUnit.configuration()[:exclude] || []]))

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @token System.get_env("BAO_TOKEN") || "ashvault-root"
  @kv_mount "ashvault"
  @transit_mount "transit"

  # A 3-byte prefix (a multiple of three) survives base64 as a stable transit-key-name
  # prefix, which is what cleanup matches on.
  @scope_prefix "nxt"
  @name_prefix "ashvault_nx_" <> Base.url_encode64(@scope_prefix, padding: false)

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

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.configure_provider/1

  setup_all do
    Application.put_env(:ash_vault, Transit,
      address: @address,
      token: @token,
      kv_mount: @kv_mount
    )

    :ok = Transit.setup()

    on_exit(&clean_up/0)
    :ok
  end

  @doc false
  def configure_provider(_context) do
    put_config(token: @token)

    %{
      provider: Transit,
      scope: fn -> @scope_prefix <> "_#{System.unique_integer([:positive])}" end,
      opaque_keys?: true
    }
  end

  describe "the key never leaves OpenBao" do
    test "current_key serves an opaque handle carrying no key material", %{scope: scope} do
      scope = scope.()

      assert {:ok, %{version: 1, key: key}} = Transit.current_key(scope)
      assert %AshVault.Key{owner: Transit} = key
      assert AshVault.Key.opaque?(key)
      refute is_binary(key)

      # The handle is a name and an integer. Not bytes, and not a pointer to bytes.
      assert {:ok, {name, 1}} = Transit.unwrap(key)
      assert name == Transit.key_name(scope)

      # Inspect is redacted to the owner, because the name is base64 of the tenant id.
      refute inspect(key) =~ name
      refute inspect(key) =~ Base.url_encode64(scope, padding: false)
    end

    test "handles are deterministic, so the contract's equality cases hold",
         %{scope: scope} do
      scope = scope.()

      assert {:ok, %{key: first}} = Transit.current_key(scope)
      assert {:ok, %{key: second}} = Transit.current_key(scope)
      assert first == second
      assert {:ok, ^first} = Transit.get_key(scope, 1)
    end

    test "the transit key is created non-exportable and export is refused by the server",
         %{scope: scope} do
      scope = scope.()
      assert {:ok, _} = Transit.current_key(scope)

      name = Transit.key_name(scope)
      assert %{status: 200, body: body} = raw(:get, "/v1/#{@transit_mount}/keys/#{name}")
      assert body["data"]["exportable"] == false

      # The guarantee, asserted against the server rather than against our own flag.
      assert %{status: 400, body: export} =
               raw(:get, "/v1/#{@transit_mount}/export/encryption-key/#{name}/1")

      assert Enum.join(export["errors"], " ") =~ "not exportable"
    end

    # Creating a transit key that already exists is a silent no-op on openbao 2.6.2: the
    # server returns the existing metadata and ignores the `exportable` flag we sent. So
    # posting `exportable: false` proves nothing; the flag has to be read back.
    test "an already-exportable transit key is refused, never silently used",
         %{scope: scope} do
      scope = scope.()
      name = Transit.key_name(scope)

      assert %{status: 200} =
               raw(:post, "/v1/#{@transit_mount}/keys/#{name}", %{
                 type: "aes256-gcm96",
                 exportable: true
               })

      assert {:error, %ProviderUnavailable{reason: {:exportable_key, ^name}}} =
               Transit.current_key(scope)

      assert {:error, %ProviderUnavailable{reason: {:exportable_key, ^name}}} =
               Transit.get_key(scope, 1)

      assert {:error, %ProviderUnavailable{reason: {:exportable_key, ^name}}} =
               Transit.rotate(scope)
    end
  end

  describe "key_name/1" do
    test "is derived, deterministic, injective, and a different namespace from OpenBao" do
      assert Transit.key_name("tenant_42") == "ashvault_nx_dGVuYW50XzQy"
      assert Transit.key_name("tenant_42") == Transit.key_name("tenant_42")
      refute Transit.key_name("ab>") == Transit.key_name("ab?")
      assert Transit.key_name("a/b c") =~ ~r/\A[a-zA-Z0-9_.\-]+\z/

      # Sharing a name with the exporting provider would mean whichever provider touched
      # a scope first decides whether its key material is exportable.
      refute Transit.key_name("tenant_42") == OpenBao.key_name("tenant_42")
    end
  end

  describe "searchable fields" do
    test "lookup_key/1 is deliberately not implemented, and that is visible" do
      refute function_exported?(Transit, :lookup_key, 1)
      refute AshVault.KeyProvider.supports_lookup?(Transit)

      assert {:error, :lookup_unsupported} =
               AshVault.KeyProvider.lookup_key(Transit, "tenant_42")
    end

    test "a vault using this provider rejects searchable? at compile time" do
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.SearchableUnderTransit do
          use Ash.Resource,
            domain: AshVault.Test.Domain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshVault]

          ash_vault do
            vault AshVault.Test.Support.TransitVault
            encrypt :email, searchable?: true
          end

          attributes do
            uuid_primary_key :id
            attribute :email, :string, public?: true
          end

          actions do
            default_accept :*
            defaults [:read, :destroy, create: :*, update: :*]
          end
        end
        """)
      end)

      assert {:error, %Spark.Error.DslError{} = error} =
               AshVault.Verifiers.VerifyVault.verify(
                 AshVault.Test.SearchableUnderTransit.spark_dsl_config()
               )

      message = Exception.message(error)
      assert message =~ "does not implement `AshVault.KeyProvider.lookup_key/1`"
      assert message =~ "AshVault.KeyProviders.OpenBaoTransit"
    end
  end

  describe "versions" do
    test "a version above latest is :not_found, without a wasted transit call",
         %{scope: scope} do
      scope = scope.()

      assert {:ok, %{version: 1}} = Transit.current_key(scope)
      assert {:error, :not_found} = Transit.get_key(scope, 2)
      assert {:error, :not_found} = Transit.get_key(scope, 99)
    end

    test "a version below min_decryption_version is :not_found", %{scope: scope} do
      scope = scope.()
      name = Transit.key_name(scope)

      assert {:ok, %{version: 1}} = Transit.current_key(scope)
      assert {:ok, 2} = Transit.rotate(scope)
      assert {:ok, _} = Transit.get_key(scope, 1)

      assert %{status: 200} =
               raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{
                 min_decryption_version: 2
               })

      assert {:error, :not_found} = Transit.get_key(scope, 1)
      assert {:ok, _} = Transit.get_key(scope, 2)
    end

    test "rotate on a scope with no key mints version 1", %{scope: scope} do
      scope = scope.()

      assert {:ok, 1} = Transit.rotate(scope)
      assert {:ok, %{version: 1}} = Transit.current_key(scope)
      assert {:ok, 2} = Transit.rotate(scope)
    end
  end

  describe "destruction" do
    test "destroy then current_key is :destroyed, not a fresh v1", %{scope: scope} do
      scope = scope.()
      name = Transit.key_name(scope)

      assert {:ok, %{version: 1}} = Transit.current_key(scope)
      assert :ok = Transit.destroy(scope)

      assert %{status: 404} = raw(:get, "/v1/#{@transit_mount}/keys/#{name}")

      assert {:error, :destroyed} = Transit.current_key(scope)
      assert {:error, :destroyed} = Transit.get_key(scope, 1)
      assert {:error, :destroyed} = Transit.rotate(scope)

      assert %{status: 404} = raw(:get, "/v1/#{@transit_mount}/keys/#{name}")
    end

    test "retries cleanup behind an existing tombstone", %{scope: scope} do
      scope = scope.()
      name = Transit.key_name(scope)

      assert {:ok, _} = Transit.current_key(scope)

      # An interrupted destroy: tombstone written, transit key not yet deleted.
      assert %{status: status} =
               raw(:post, "/v1/#{@kv_mount}/data/tombstones/#{name}", %{
                 data: %{destroyed_at: DateTime.to_iso8601(DateTime.utc_now())}
               })

      assert status in 200..299

      assert :ok = Transit.destroy(scope)
      assert %{status: 404} = raw(:get, "/v1/#{@transit_mount}/keys/#{name}")
    end

    test "a transit key that cannot be deleted is an error, not a silent :ok",
         %{scope: scope} do
      scope = scope.()
      name = Transit.key_name(scope)

      assert {:ok, %{version: 1}} = Transit.current_key(scope)

      put_config(
        token: @token,
        transit_mount: "transit_absent_#{System.unique_integer([:positive])}"
      )

      assert {:error, %ProviderUnavailable{}} = Transit.destroy(scope)

      put_config(token: @token)

      # Intact but fail-closed: the tombstone landed first, so a fresh v1 can never join
      # ciphertext whose original key is still out there.
      assert %{status: 200} = raw(:get, "/v1/#{@transit_mount}/keys/#{name}")
      assert {:error, :destroyed} = Transit.current_key(scope)
    end
  end

  describe "a missing KV mount" do
    test "is ProviderUnavailable on every read path, and the mount is not created",
         %{scope: scope} do
      scope = scope.()
      missing = "ashvault_missing_#{System.unique_integer([:positive])}"
      put_config(token: @token, kv_mount: missing)

      on_exit(fn -> raw(:delete, "/v1/sys/mounts/#{missing}") end)

      for result <- [
            Transit.current_key(scope),
            Transit.get_key(scope, 1),
            Transit.rotate(scope),
            Transit.destroy(scope)
          ] do
        assert {:error, %ProviderUnavailable{reason: :kv_mount_unavailable}} = result
      end

      assert %{status: status} = raw(:get, "/v1/sys/mounts/#{missing}")
      assert status in [400, 404], "the read path created the KV mount (status #{status})"
    end

    test "setup/0 mounts the KV engine and is idempotent" do
      mount = "ashvault_setup_nx_#{System.unique_integer([:positive])}"
      put_config(token: @token, kv_mount: mount)
      on_exit(fn -> raw(:delete, "/v1/sys/mounts/#{mount}") end)

      assert :ok = Transit.setup()
      assert :ok = Transit.setup()
      assert %{status: 200} = raw(:get, "/v1/sys/mounts/#{mount}")
    end
  end

  describe "error discrimination" do
    test "a wrong token is ProviderUnavailable, never :destroyed", %{scope: scope} do
      scope = scope.()
      assert {:ok, _} = Transit.current_key(scope)

      put_config(token: "sentinel-bad-token-do-not-log")

      for result <- [
            Transit.current_key(scope),
            Transit.get_key(scope, 1),
            Transit.rotate(scope),
            Transit.destroy(scope)
          ] do
        assert {:error, %ProviderUnavailable{reason: :forbidden}} = result
      end

      put_config(token: @token)
      assert {:ok, %{version: 1}} = Transit.current_key(scope)
    end

    test "the token never appears in an error", %{scope: scope} do
      scope = scope.()
      sentinel = "sentinel-bad-token-do-not-log"
      put_config(token: sentinel)

      assert {:error, %ProviderUnavailable{} = error} = Transit.current_key(scope)

      refute inspect(error, structs: false, limit: :infinity) =~ sentinel
      refute Exception.message(error) =~ sentinel
    end

    test "an unreachable server is ProviderUnavailable, never :destroyed", %{scope: scope} do
      scope = scope.()
      put_config(token: @token, address: "http://127.0.0.1:1", max_retries: 0)

      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = Transit.current_key(scope)
      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = Transit.get_key(scope, 1)
      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = Transit.destroy(scope)
    end

    test "errors are attributed to this provider, not the exporting one", %{scope: scope} do
      scope = scope.()
      put_config(token: @token, address: "http://127.0.0.1:1", max_retries: 0)

      assert {:error, %ProviderUnavailable{provider: Transit}} = Transit.current_key(scope)
    end
  end

  describe "key_bytes/0" do
    # Not exported, deliberately: `AshVault.Vault.verify_key_sizes!/2` would otherwise
    # compare a meaningless number against the cipher's and could refuse a correct vault.
    test "is not exported, because this provider mints nothing the BEAM can size" do
      refute function_exported?(Transit, :key_bytes, 0)
      assert AshVault.KeyProvider.key_bytes(Transit) == 32
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────

  defp put_config(overrides) do
    config = Keyword.merge([address: @address, kv_mount: @kv_mount], overrides)
    previous = Application.get_env(:ash_vault, Transit)
    Application.put_env(:ash_vault, Transit, config)

    on_exit(fn ->
      if previous do
        Application.put_env(:ash_vault, Transit, previous)
      else
        Application.delete_env(:ash_vault, Transit)
      end
    end)

    :ok
  end

  defp raw(method, path, body \\ nil) do
    options = [
      method: method,
      base_url: @address,
      url: path,
      headers: [{"x-vault-token", @token}],
      receive_timeout: 5_000
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options

    case options |> Req.new() |> Req.request() do
      {:ok, response} -> response
      {:error, exception} -> exception
    end
  end

  defp clean_up do
    for name <- list("/v1/#{@transit_mount}/keys"), String.starts_with?(name, @name_prefix) do
      raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{deletion_allowed: true})
      raw(:delete, "/v1/#{@transit_mount}/keys/#{name}")
    end

    for name <- list("/v1/#{@kv_mount}/metadata/tombstones"),
        String.starts_with?(name, @name_prefix) do
      raw(:delete, "/v1/#{@kv_mount}/metadata/tombstones/#{name}")
    end

    :ok
  end

  defp list(path) do
    case raw(:get, path <> "?list=true") do
      %Req.Response{status: 200, body: %{"data" => %{"keys" => keys}}} when is_list(keys) ->
        keys

      _ ->
        []
    end
  end
end
