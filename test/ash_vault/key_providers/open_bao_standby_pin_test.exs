defmodule AshVault.KeyProviders.OpenBaoStandbyPinTest do
  @moduledoc """
  An HA OpenBao behind a `<release>-active` Service, after a leader change, with a stub
  (`Req.Test`) that routes like the Service does.

  The stub cannot see sockets, so it models them by the one thing that decides them: a
  request carrying `connection: close` will be followed by a fresh dial, and a fresh dial
  through the `-active` Service reaches the node that is active now. Any other request is
  treated as riding a pooled keep-alive connection opened before the failover, which is
  pinned to the demoted node. That standby forwards writes to the active node and serves
  reads from a copy that has not seen them yet (OpenBao 2.5+ standby reads): exactly the
  sequence that failed in production on 2026-10-22 — a fresh tenant's `.mac` key create
  was forwarded and applied, and the immediately following read and `transit/hmac` on the
  standby found no key.

  This is a header-contract test: it proves every request asks for a fresh connection.
  `open_bao_connection_test.exs` proves, over real sockets, that the request is then
  actually made on one.

  `async: false`: the provider's configuration and the stub are global.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderForbidden
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.KeyProviders.OpenBaoTransit, as: Transit
  alias AshVault.Test.Support.TransitVault

  @stub AshVault.Test.OpenBaoStandbyStub
  @created 1_791_000_000

  setup context do
    Req.Test.set_req_test_to_shared(context)
    previous = Application.get_env(:ash_vault, Transit)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_vault, Transit, previous),
        else: Application.delete_env(:ash_vault, Transit)

      Req.Test.set_req_test_to_private(%{})
    end)

    configure([])
    :ok
  end

  describe "by default (reuse_connections: false)" do
    test "a fresh scope's mac!, mac_key_version! and mac_at! succeed, all on the active node" do
      start_cluster()
      scope = fresh_scope()

      assert {1, tag} = TransitVault.mac!("payload", context(scope))
      assert TransitVault.mac_key_version!(context(scope)) == 1
      assert TransitVault.mac_at!("payload", 1, context(scope)) == tag
      assert :ok = TransitVault.verify_mac!("payload", 1, tag, context(scope))

      assert {"POST", "/v1/transit/keys/" <> _, :active} =
               Enum.find(log(), &match?({"POST", "/v1/transit/keys/" <> _, _}, &1))

      assert nodes() == [:active]
    end

    test "a fresh scope's first encrypt is not refused by a standby's implicit create" do
      start_cluster()

      assert "AV" <> _ = TransitVault.encrypt!("secret", context(fresh_scope()))
      assert nodes() == [:active]
    end

    test "every request, health included, asks for a fresh connection" do
      start_cluster()

      TransitVault.mac!("payload", context(fresh_scope()))
      {:ok, _role} = Transit.node_status()

      assert Enum.all?(headers(), &({"connection", "close"} in &1))
    end
  end

  describe "with reuse_connections: true" do
    setup do
      configure(reuse_connections: true)
    end

    test "a fresh scope's first MAC fails on the pinned standby (the production failure)" do
      start_cluster()

      assert_raise ProviderUnavailable, fn ->
        TransitVault.mac!("payload", context(fresh_scope()))
      end

      assert {"POST", "/v1/transit/keys/" <> _, :standby} =
               Enum.find(log(), &match?({"POST", "/v1/transit/keys/" <> _, _}, &1))

      assert nodes() == [:standby]
    end

    test "a fresh scope's first encrypt is the standby's 403" do
      start_cluster()

      assert_raise ProviderForbidden, fn ->
        TransitVault.encrypt!("secret", context(fresh_scope()))
      end
    end

    test "sends no connection header" do
      start_cluster()

      {:ok, _role} = Transit.node_status()
      refute Enum.any?(headers(), &List.keymember?(&1, "connection", 0))
    end
  end

  describe "reuse_connections?/1" do
    test "defaults to false" do
      refute Transport.reuse_connections?(Transit)
    end

    test "refuses anything but a boolean" do
      configure(reuse_connections: "false")

      assert_raise ArgumentError, ~r/:reuse_connections must be a boolean/, fn ->
        Transport.reuse_connections?(Transit)
      end
    end
  end

  describe "node_status/0" do
    test "reports the role of the node a request lands on" do
      start_cluster()
      assert {:ok, :active} = Transit.node_status()

      configure(reuse_connections: true)
      assert {:ok, :standby} = Transit.node_status()
    end

    test "is unauthenticated, asks every role to answer 200, and is never retried" do
      start_cluster(health_status: 429)
      configure(max_retries: 3)

      assert {:error, %ProviderUnavailable{reason: {:http_status, 429}}} = Transit.node_status()

      assert [{"GET", "/v1/sys/health", :active}] = log()
      assert [headers] = headers()
      refute List.keymember?(headers, "x-vault-token", 0)

      assert %{
               "standbyok" => "true",
               "perfstandbyok" => "true",
               "sealedcode" => "200",
               "uninitcode" => "200"
             } = Agent.get(Process.get(:cluster), & &1.health_query)
    end

    test "classifies the bodies a server returns, and refuses anything else" do
      for {body, expected} <- [
            {%{"initialized" => true, "sealed" => false, "standby" => false}, {:ok, :active}},
            {%{"initialized" => true, "sealed" => false, "standby" => true}, {:ok, :standby}},
            {%{
               "initialized" => true,
               "sealed" => false,
               "standby" => false,
               "performance_standby" => true
             }, {:ok, :standby}},
            {%{"initialized" => true, "sealed" => true, "standby" => true}, {:ok, :sealed}},
            {%{"initialized" => false, "sealed" => true}, {:ok, :uninitialized}}
          ] do
        assert Transport.classify_health(Transit, body) == expected
      end

      for body <- [%{}, %{"standby" => "no"}, "<html>", nil] do
        assert {:error, %ProviderUnavailable{reason: :ambiguous_health_response}} =
                 Transport.classify_health(Transit, body)
      end
    end
  end

  # ── the stub cluster ────────────────────────────────────────────────────────────

  defp configure(overrides) do
    Application.put_env(
      :ash_vault,
      Transit,
      Keyword.merge(
        [
          address: "http://openbao-active.test:8200",
          token: "stub-token",
          max_retries: 0,
          req_options: [plug: {Req.Test, @stub}]
        ],
        overrides
      )
    )

    :ok
  end

  defp fresh_scope, do: "tenant-#{System.unique_integer([:positive])}"

  defp context(scope) do
    %AshVault.Context{resource: __MODULE__, field: :secret, ash_context: %{tenant: scope}}
  end

  defp meta(exportable) do
    %{
      "type" => "aes256-gcm96",
      "exportable" => exportable,
      "latest_version" => 1,
      "min_decryption_version" => 1,
      "keys" => %{"1" => @created}
    }
  end

  defp start_cluster(opts \\ []) do
    {:ok, cluster} =
      Agent.start_link(fn ->
        %{
          active: %{},
          standby: %{},
          health_status: Keyword.get(opts, :health_status, 200),
          health_query: nil,
          log: [],
          headers: []
        }
      end)

    Process.put(:cluster, cluster)
    Req.Test.stub(@stub, fn conn -> handle(conn, cluster) end)
  end

  defp log, do: Agent.get(Process.get(:cluster), &Enum.reverse(&1.log))
  defp headers, do: Agent.get(Process.get(:cluster), &Enum.reverse(&1.headers))
  defp nodes, do: log() |> Enum.map(&elem(&1, 2)) |> Enum.uniq()

  defp handle(conn, cluster) do
    {:ok, raw, conn} = Plug.Conn.read_body(conn)
    body = if raw == "", do: %{}, else: Jason.decode!(raw)

    node =
      if Plug.Conn.get_req_header(conn, "connection") == ["close"], do: :active, else: :standby

    Agent.update(cluster, fn state ->
      %{
        state
        | log: [{conn.method, conn.request_path, node} | state.log],
          headers: [conn.req_headers | state.headers]
      }
    end)

    route(conn, node, conn.method, conn.request_path, body, cluster)
  end

  defp route(conn, node, "GET", "/v1/sys/health", _body, cluster) do
    conn = Plug.Conn.fetch_query_params(conn)

    status =
      Agent.get_and_update(cluster, &{&1.health_status, %{&1 | health_query: conn.query_params}})

    reply(conn, status, %{
      "initialized" => true,
      "sealed" => false,
      "standby" => node == :standby,
      "version" => "2.6.3"
    })
  end

  defp route(conn, _node, "GET", "/v1/ashvault/data/tombstones/" <> _name, _body, _cluster),
    do: reply(conn, 404, %{"errors" => []})

  defp route(conn, node, "GET", "/v1/transit/keys/" <> name, _body, cluster) do
    case Agent.get(cluster, &Map.get(Map.fetch!(&1, node), name)) do
      nil -> reply(conn, 404, %{"errors" => []})
      meta -> reply(conn, 200, %{"data" => meta})
    end
  end

  defp route(conn, _node, "POST", "/v1/transit/keys/" <> name, body, cluster) do
    meta =
      Agent.get_and_update(cluster, fn state ->
        meta = Map.get(state.active, name) || meta(body["exportable"])
        {meta, %{state | active: Map.put(state.active, name, meta)}}
      end)

    reply(conn, 200, %{"data" => meta})
  end

  defp route(conn, node, "POST", "/v1/transit/hmac/" <> rest, _body, cluster) do
    if known?(cluster, node, rest),
      do: reply(conn, 200, %{"data" => %{"hmac" => "vault:v1:" <> Base.encode64(<<7::256>>)}}),
      else: reply(conn, 400, %{"errors" => ["encryption key not found"]})
  end

  defp route(conn, node, "POST", "/v1/transit/verify/" <> rest, _body, cluster) do
    if known?(cluster, node, rest),
      do: reply(conn, 200, %{"data" => %{"valid" => true}}),
      else: reply(conn, 400, %{"errors" => ["encryption key not found"]})
  end

  defp route(conn, node, "POST", "/v1/transit/encrypt/" <> name, _body, cluster) do
    if known?(cluster, node, name),
      do:
        reply(conn, 200, %{"data" => %{"ciphertext" => "vault:v1:c3R1Yg==", "key_version" => 1}}),
      else: reply(conn, 403, %{"errors" => ["permission denied"]})
  end

  defp route(conn, _node, method, path, _body, _cluster),
    do: reply(conn, 500, %{"errors" => ["unexpected #{method} #{path}"]})

  defp known?(cluster, node, path) do
    name = path |> String.split("/") |> hd()
    Agent.get(cluster, &Map.has_key?(Map.fetch!(&1, node), name))
  end

  defp reply(conn, status, body), do: conn |> Plug.Conn.put_status(status) |> Req.Test.json(body)
end
