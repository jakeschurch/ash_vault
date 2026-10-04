defmodule AshVault.KeyProviders.OpenBaoTransitStubbedTest do
  @moduledoc """
  `AshVault.KeyProviders.OpenBaoTransit` against a stubbed OpenBao (`Req.Test`): the
  request sequence of a scope's first write, and the classification of a `403`.

  The sequence matters because of the policy the provider documents: an application token
  without `create` on `transit/encrypt/*` gets `403` for an encrypt against a key that
  does not exist, since OpenBao treats that encrypt as a request to create it. Every
  first write must therefore create the key explicitly, through `transit/keys`, before
  the cipher ever issues the encrypt.

  `async: false`: the provider's configuration and the stub are global.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.ProviderForbidden
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBaoTransit, as: Transit
  alias AshVault.Test.Support.TransitVault

  @stub AshVault.Test.OpenBaoTransitStub
  @scope "tenant-stubbed"
  @name Transit.key_name(@scope)
  @mac_name Transit.mac_key_name(@scope)
  @created 1_791_000_000

  setup context do
    Req.Test.set_req_test_to_shared(context)
    previous = Application.get_env(:ash_vault, Transit)

    Application.put_env(:ash_vault, Transit,
      address: "http://openbao.test:8200",
      token: "stub-token",
      max_retries: 0,
      req_options: [plug: {Req.Test, @stub}]
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_vault, Transit, previous),
        else: Application.delete_env(:ash_vault, Transit)

      Req.Test.set_req_test_to_private(%{})
    end)

    :ok
  end

  describe "a scope's first write" do
    test "creates the missing data key explicitly, then encrypts" do
      start_server(keys: %{})

      assert {:ok, %{version: 1, key: key}} = Transit.current_key(@scope)

      assert {:ok, %{ciphertext: "vault:v1:" <> _}} =
               AshVault.Ciphers.OpenBaoTransit.encrypt("x", key, "aad")

      assert requests() == [
               {"GET", "/v1/ashvault/data/tombstones/#{@name}"},
               {"GET", "/v1/transit/keys/#{@name}"},
               {"POST", "/v1/transit/keys/#{@name}"},
               {"POST", "/v1/transit/encrypt/#{@name}"}
             ]

      assert %{"exportable" => false, "type" => "aes256-gcm96"} = created_body(@name)
    end

    test "through the vault, the create precedes the encrypt" do
      start_server(keys: %{})

      assert "AV" <> _ = TransitVault.encrypt!("secret", context())

      posts = for {"POST", path} <- requests(), do: path
      assert posts == ["/v1/transit/keys/#{@name}", "/v1/transit/encrypt/#{@name}"]
    end

    test "creates the missing :mac key explicitly, non-exportable" do
      start_server(keys: %{})

      assert {:ok, %{version: 1}} = Transit.current_key(@scope, :mac)
      assert {"POST", "/v1/transit/keys/#{@mac_name}"} in requests()
      assert %{"exportable" => false} = created_body(@mac_name)
    end

    test "two writers racing on a new scope both succeed" do
      start_server(keys: %{})

      results =
        [fn -> Transit.current_key(@scope) end, fn -> Transit.current_key(@scope) end]
        |> Enum.map(&Task.async/1)
        |> Task.await_many()

      assert [{:ok, %{version: 1}}, {:ok, %{version: 1}}] = results
    end
  end

  describe "a scope whose key exists" do
    test "never posts to transit/keys" do
      start_server(keys: %{@name => meta()})

      assert {:ok, %{version: 1}} = Transit.current_key(@scope)
      refute Enum.any?(requests(), &match?({"POST", "/v1/transit/keys/" <> _}, &1))
    end
  end

  describe "a destroyed scope" do
    test "is never re-created: KeyDestroyed, and no transit request at all" do
      start_server(keys: %{}, tombstone: :destroyed)

      assert {:error, :destroyed} = Transit.current_key(@scope)
      assert {:error, :destroyed} = Transit.current_key(@scope, :mac)
      assert {:error, :destroyed} = Transit.rotate(@scope)
      refute Enum.any?(requests(), &match?({_, "/v1/transit/" <> _}, &1))

      assert_raise KeyDestroyed, fn -> TransitVault.encrypt!("secret", context()) end
    end
  end

  describe "a 403" do
    test "on encrypt is ProviderForbidden naming the operation, never ProviderUnavailable" do
      start_server(keys: %{@name => meta()}, deny: ["/v1/transit/encrypt/"])

      error = assert_raise ProviderForbidden, fn -> TransitVault.encrypt!("s", context()) end
      assert error.provider == Transit
      assert error.operation == :encrypt
      assert Exception.message(error) =~ "retrying will not help"
      refute Exception.message(error) =~ @name
      refute inspect(error) =~ @name
    end

    test "on the key create is ProviderForbidden(:create_key)" do
      start_server(keys: %{}, deny: ["POST /v1/transit/keys/"])

      assert {:error, %ProviderForbidden{operation: :create_key}} = Transit.current_key(@scope)
    end

    test "on the key metadata read is ProviderForbidden(:read_key)" do
      start_server(keys: %{}, deny: ["GET /v1/transit/keys/"])

      assert {:error, %ProviderForbidden{operation: :read_key}} = Transit.current_key(@scope)
    end

    test "on the tombstone read fails closed as ProviderForbidden(:read_tombstone)" do
      start_server(keys: %{@name => meta()}, deny: ["/v1/ashvault/data/tombstones/"])

      for result <- [
            Transit.current_key(@scope),
            Transit.get_key(@scope, 1),
            Transit.rotate(@scope)
          ] do
        assert {:error, %ProviderForbidden{operation: :read_tombstone}} = result
      end

      refute Enum.any?(requests(), &match?({_, "/v1/transit/" <> _}, &1))
    end

    test "on hmac is ProviderForbidden(:hmac) through the MAC module" do
      start_server(keys: %{@mac_name => meta()}, deny: ["/v1/transit/hmac/"])

      {:ok, %{key: key}} = Transit.current_key(@scope, :mac)

      assert {:error, %ProviderForbidden{operation: :hmac}} =
               AshVault.Macs.OpenBaoTransit.mac("data", key, "aad")
    end

    test "a 5xx stays ProviderUnavailable" do
      start_server(keys: %{@name => meta()}, fail: ["/v1/transit/encrypt/"])

      error = assert_raise ProviderUnavailable, fn -> TransitVault.encrypt!("s", context()) end
      assert error.reason == {:http_status, 503}
    end
  end

  describe "operation/3" do
    test "names transit, tombstone, mount and login requests without the key name" do
      for {method, path, operation} <- [
            {:get, "/v1/transit/keys/#{@name}", :read_key},
            {:post, "/v1/transit/keys/#{@name}", :create_key},
            {:delete, "/v1/transit/keys/#{@name}", :delete_key},
            {:post, "/v1/transit/keys/#{@name}/rotate", :rotate_key},
            {:post, "/v1/transit/keys/#{@name}/config", :configure_key},
            {:post, "/v1/transit/encrypt/#{@name}", :encrypt},
            {:post, "/v1/transit/decrypt/#{@name}", :decrypt},
            {:post, "/v1/transit/hmac/#{@mac_name}/sha2-256", :hmac},
            {:post, "/v1/transit/verify/#{@mac_name}/sha2-256", :verify},
            {:get, "/v1/transit/export/encryption-key/#{@name}/1", :export},
            {:get, "/v1/ashvault/data/tombstones/#{@name}", :read_tombstone},
            {:post, "/v1/ashvault/data/tombstones/#{@name}", :write_tombstone},
            {:post, "/v1/sys/mounts/ashvault", :mount},
            {:post, "/v1/auth/kubernetes/login", :login},
            {:get, "/v1/sys/health", :unknown}
          ] do
        assert AshVault.KeyProviders.OpenBao.Transport.operation(Transit, method, path) ==
                 operation
      end
    end
  end

  # ── the stub server ─────────────────────────────────────────────────────────────

  defp context do
    %AshVault.Context{resource: __MODULE__, field: :secret, ash_context: %{tenant: @scope}}
  end

  defp meta do
    %{
      "type" => "aes256-gcm96",
      "exportable" => false,
      "latest_version" => 1,
      "min_decryption_version" => 1,
      "keys" => %{"1" => @created}
    }
  end

  defp start_server(opts) do
    {:ok, state} =
      Agent.start_link(fn ->
        %{
          keys: Keyword.fetch!(opts, :keys),
          tombstone: Keyword.get(opts, :tombstone, :absent),
          deny: Keyword.get(opts, :deny, []),
          fail: Keyword.get(opts, :fail, []),
          log: [],
          bodies: %{}
        }
      end)

    Process.put(:stub_state, state)

    Req.Test.stub(@stub, fn conn -> handle(conn, state) end)
  end

  defp requests, do: Agent.get(Process.get(:stub_state), &Enum.reverse(&1.log))

  defp created_body(name), do: Agent.get(Process.get(:stub_state), &Map.fetch!(&1.bodies, name))

  defp handle(conn, state) do
    {:ok, raw, conn} = Plug.Conn.read_body(conn)
    body = if raw == "", do: %{}, else: Jason.decode!(raw)
    request = "#{conn.method} #{conn.request_path}"

    %{deny: deny, fail: fail} =
      Agent.get_and_update(state, &{&1, %{&1 | log: [{conn.method, conn.request_path} | &1.log]}})

    cond do
      Enum.any?(deny, &matches?(request, &1)) ->
        reply(conn, 403, %{"errors" => ["1 error occurred:\n\t* permission denied\n\n"]})

      Enum.any?(fail, &matches?(request, &1)) ->
        reply(conn, 503, %{"errors" => ["Vault is sealed"]})

      true ->
        route(conn, conn.method, conn.request_path, body, state)
    end
  end

  defp matches?(request, "/" <> _ = prefix),
    do: request |> String.split(" ") |> List.last() |> String.starts_with?(prefix)

  defp matches?(request, prefix), do: String.starts_with?(request, prefix)

  defp route(conn, "GET", "/v1/ashvault/data/tombstones/" <> _name, _body, state) do
    case Agent.get(state, & &1.tombstone) do
      :absent -> reply(conn, 404, %{"errors" => []})
      :destroyed -> reply(conn, 200, %{"data" => %{"data" => %{"destroyed_at" => "x"}}})
    end
  end

  defp route(conn, "GET", "/v1/transit/keys/" <> name, _body, state) do
    case Agent.get(state, &Map.get(&1.keys, name)) do
      nil -> reply(conn, 404, %{"errors" => []})
      meta -> reply(conn, 200, %{"data" => meta})
    end
  end

  # Creating a key that exists is a silent no-op on OpenBao: it answers with the existing
  # metadata. That is what makes two racing creators both succeed.
  defp route(conn, "POST", "/v1/transit/keys/" <> name, body, state) do
    meta =
      Agent.get_and_update(state, fn server ->
        meta = Map.get(server.keys, name) || Map.put(meta(), "exportable", body["exportable"])

        {meta,
         %{
           server
           | keys: Map.put(server.keys, name, meta),
             bodies: Map.put(server.bodies, name, body)
         }}
      end)

    reply(conn, 200, %{"data" => meta})
  end

  # Mirrors the server's implicit create: an encrypt against a missing key is a create,
  # which these tests' "policy" never grants.
  defp route(conn, "POST", "/v1/transit/encrypt/" <> name, _body, state) do
    if Agent.get(state, &Map.has_key?(&1.keys, name)) do
      reply(conn, 200, %{"data" => %{"ciphertext" => "vault:v1:c3R1Yg==", "key_version" => 1}})
    else
      reply(conn, 403, %{"errors" => ["permission denied"]})
    end
  end

  defp route(conn, method, path, _body, _state) do
    reply(conn, 500, %{"errors" => ["unexpected #{method} #{path}"]})
  end

  defp reply(conn, status, body), do: conn |> Plug.Conn.put_status(status) |> Req.Test.json(body)
end
