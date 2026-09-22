defmodule AshVault.KeyProviders.OpenBaoTest do
  @moduledoc """
  Contract and behaviour suite for `AshVault.KeyProviders.OpenBao`, run against a live
  OpenBao server.

  The suite is tagged `:openbao` and excluded by default, so `mix test` stays green
  without Docker. Run it with:

      mix test --include openbao test/ash_vault/key_providers/open_bao_test.exs

  If the server is unreachable when the suite loads, the whole module is additionally
  skipped, so even `--include openbao` degrades to "skipped", never "failed".
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao

  # Exclude this suite from a plain `mix test` run without clobbering any other
  # exclusions the project's test_helper may have configured.
  ExUnit.configure(exclude: Enum.uniq([:openbao | ExUnit.configuration()[:exclude] || []]))

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @token System.get_env("BAO_TOKEN") || "ashvault-root"
  @kv_mount "ashvault"
  @transit_mount "transit"

  # Every test scope starts with this 3-byte prefix, which (being a multiple of three)
  # survives base64 as a stable transit-key-name prefix used for cleanup.
  @scope_prefix "avt"
  @name_prefix "ashvault_" <> Base.url_encode64(@scope_prefix, padding: false)

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
    on_exit(&clean_up/0)
    :ok
  end

  @doc false
  def configure_provider(_context) do
    put_config(token: @token)

    %{
      provider: OpenBao,
      scope: fn -> @scope_prefix <> "_#{System.unique_integer([:positive])}" end,
      key_bytes: 32
    }
  end

  describe "key_name/1" do
    test "is derived, deterministic and injective" do
      assert OpenBao.key_name("tenant_42") == "ashvault_dGVuYW50XzQy"
      assert OpenBao.key_name("tenant_42") == OpenBao.key_name("tenant_42")
      refute OpenBao.key_name("ab>") == OpenBao.key_name("ab?")
      assert OpenBao.key_name("a/b c") =~ ~r/\A[a-zA-Z0-9_.\-]+\z/
    end
  end

  describe "destruction" do
    test "destroy then current_key is :destroyed, not a fresh v1", %{scope: scope} do
      scope = scope.()

      assert {:ok, %{version: 1, key: key}} = OpenBao.current_key(scope)
      assert :ok = OpenBao.destroy(scope)

      # The transit key really is gone from the server...
      assert %{status: 404} = raw(:get, "/v1/#{@transit_mount}/keys/#{OpenBao.key_name(scope)}")

      # ...and the tombstone stops it being silently re-minted.
      assert {:error, :destroyed} = OpenBao.current_key(scope)
      assert {:error, :destroyed} = OpenBao.get_key(scope, 1)
      assert {:error, :destroyed} = OpenBao.rotate(scope)

      # Still gone: nothing re-created it behind the tombstone.
      assert %{status: 404} = raw(:get, "/v1/#{@transit_mount}/keys/#{OpenBao.key_name(scope)}")
      refute match?({:ok, %{key: ^key}}, OpenBao.current_key(scope))
    end

    test "destroy is idempotent", %{scope: scope} do
      scope = scope.()

      assert {:ok, _} = OpenBao.current_key(scope)
      assert :ok = OpenBao.destroy(scope)
      assert :ok = OpenBao.destroy(scope)
      assert :ok = OpenBao.destroy(scope)
      assert {:error, :destroyed} = OpenBao.current_key(scope)
    end

    test "destroy writes a tombstone that survives the transit key being re-creatable",
         %{scope: scope} do
      scope = scope.()
      name = OpenBao.key_name(scope)

      assert {:ok, _} = OpenBao.current_key(scope)
      assert :ok = OpenBao.destroy(scope)

      # Somebody re-creates the transit key out of band. The tombstone still wins.
      assert %{status: 200} =
               raw(:post, "/v1/#{@transit_mount}/keys/#{name}", %{
                 type: "aes256-gcm96",
                 exportable: true
               })

      assert {:error, :destroyed} = OpenBao.current_key(scope)
      assert {:error, :destroyed} = OpenBao.get_key(scope, 1)
    end
  end

  describe "versions" do
    test "a version above latest is :not_found", %{scope: scope} do
      scope = scope.()

      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)
      assert {:error, :not_found} = OpenBao.get_key(scope, 2)
      assert {:error, :not_found} = OpenBao.get_key(scope, 99)
    end

    test "a version below min_decryption_version is :not_found", %{scope: scope} do
      scope = scope.()
      name = OpenBao.key_name(scope)

      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)
      assert {:ok, 2} = OpenBao.rotate(scope)
      assert {:ok, _} = OpenBao.get_key(scope, 1)

      assert %{status: 200} =
               raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{
                 min_decryption_version: 2
               })

      assert {:error, :not_found} = OpenBao.get_key(scope, 1)
      assert {:ok, _} = OpenBao.get_key(scope, 2)
    end

    test "rotate on a scope with no key mints version 1", %{scope: scope} do
      scope = scope.()

      assert {:ok, 1} = OpenBao.rotate(scope)
      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)
      assert {:ok, 2} = OpenBao.rotate(scope)
    end

    test "a non-positive or non-integer version is :not_found", %{scope: scope} do
      scope = scope.()

      assert {:ok, _} = OpenBao.current_key(scope)
      assert {:error, :not_found} = OpenBao.get_key(scope, 0)
      assert {:error, :not_found} = OpenBao.get_key(scope, -1)
    end
  end

  describe "error discrimination" do
    test "a wrong token is ProviderUnavailable, never :destroyed", %{scope: scope} do
      scope = scope.()
      assert {:ok, _} = OpenBao.current_key(scope)

      put_config(token: "sentinel-bad-token-do-not-log")

      for result <- [
            OpenBao.current_key(scope),
            OpenBao.get_key(scope, 1),
            OpenBao.rotate(scope),
            OpenBao.destroy(scope)
          ] do
        assert {:error, %ProviderUnavailable{reason: :forbidden}} = result
      end

      # The scope is intact once the token is right again: an outage is not erasure.
      put_config(token: @token)
      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)
    end

    test "the token never appears in an error", %{scope: scope} do
      scope = scope.()
      sentinel = "sentinel-bad-token-do-not-log"
      put_config(token: sentinel)

      assert {:error, %ProviderUnavailable{} = error} = OpenBao.current_key(scope)

      refute inspect(error) =~ sentinel
      refute Exception.message(error) =~ sentinel
      refute inspect(error, structs: false, limit: :infinity) =~ sentinel
    end

    test "a missing token is ProviderUnavailable", %{scope: scope} do
      scope = scope.()
      put_config(token: nil)

      assert {:error, %ProviderUnavailable{reason: :missing_token}} = OpenBao.current_key(scope)
      assert {:error, %ProviderUnavailable{reason: :missing_token}} = OpenBao.destroy(scope)
    end

    test "an unreachable server is ProviderUnavailable, never :destroyed", %{scope: scope} do
      scope = scope.()
      put_config(token: @token, address: "http://127.0.0.1:1", max_retries: 0)

      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = OpenBao.current_key(scope)
      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = OpenBao.get_key(scope, 1)
      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} = OpenBao.destroy(scope)
    end
  end

  describe "token resolution" do
    test "accepts {:system, var} and a zero-arity function", %{scope: scope} do
      scope = scope.()

      System.put_env("ASH_VAULT_TEST_BAO_TOKEN", @token)
      on_exit(fn -> System.delete_env("ASH_VAULT_TEST_BAO_TOKEN") end)

      put_config(token: {:system, "ASH_VAULT_TEST_BAO_TOKEN"})
      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)

      put_config(token: fn -> @token end)
      assert {:ok, %{version: 1}} = OpenBao.current_key(scope)
    end
  end

  describe "key_bytes/0" do
    test "follows the configured key type" do
      put_config(token: @token, key_type: "aes128-gcm96")
      assert OpenBao.key_bytes() == 16

      put_config(token: @token)
      assert OpenBao.key_bytes() == 32
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────

  defp put_config(overrides) do
    config = Keyword.merge([address: @address, kv_mount: @kv_mount], overrides)
    previous = Application.get_env(:ash_vault, OpenBao)
    Application.put_env(:ash_vault, OpenBao, config)

    on_exit(fn ->
      if previous do
        Application.put_env(:ash_vault, OpenBao, previous)
      else
        Application.delete_env(:ash_vault, OpenBao)
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
