defmodule AshVault.Macaroon.RotationOpenBaoKVTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Macaroon.Rotation.{Context, OpenBaoKV, Secret}

  # Any configured OpenBao provider's connection is borrowed; this one exists only here.
  @provider AshVault.Macaroon.RotationOpenBaoKVTest.Provider
  @context %Context{ref: "nix-cache/pr-farm"}

  setup context do
    Req.Test.set_req_test_to_shared(context)

    Application.put_env(:ash_vault, @provider,
      address: "http://bao.test",
      token: "synthetic-test-token",
      max_retries: 0,
      req_options: [plug: {Req.Test, __MODULE__}]
    )

    Application.put_env(:ash_vault, OpenBaoKV, provider: @provider, mount: "rotated")
    server = start_supervised!({Agent, fn -> %{kv: %{}, status: nil, requests: []} end})
    Req.Test.stub(__MODULE__, &route(&1, server))

    on_exit(fn ->
      Application.delete_env(:ash_vault, @provider)
      Application.delete_env(:ash_vault, OpenBaoKV)
    end)

    %{server: server}
  end

  defp route(conn, server) do
    Agent.update(
      server,
      &Map.update!(&1, :requests, fn r -> [{conn.method, conn.request_path} | r] end)
    )

    "/v1/rotated/data/" <> path = conn.request_path

    case Agent.get(server, & &1.status) do
      nil ->
        case conn.method do
          "POST" ->
            {:ok, body, conn} = Plug.Conn.read_body(conn)
            Agent.update(server, &put_in(&1, [:kv, path], Jason.decode!(body)["data"]))
            Req.Test.json(conn, %{"data" => %{"version" => 1}})

          "GET" ->
            case Agent.get(server, &get_in(&1, [:kv, path])) do
              nil -> conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"errors" => []})
              data -> Req.Test.json(conn, %{"data" => %{"data" => data}})
            end
        end

      status ->
        conn
        |> Plug.Conn.put_status(status)
        |> Req.Test.json(%{"errors" => ["permission denied"]})
    end
  end

  defp secret, do: Secret.new("avrot_kv-token-value")

  test "stages under staging/<ref> and reads it back only for the same credential", %{
    server: server
  } do
    assert :ok = OpenBaoKV.stage(@context, "id-1", secret())

    assert Agent.get(server, & &1.kv)["staging/nix-cache/pr-farm"] == %{
             "token" => "avrot_kv-token-value",
             "credential_id" => "id-1"
           }

    assert {:ok, staged} = OpenBaoKV.staged(@context, "id-1")
    assert Secret.reveal(staged) == "avrot_kv-token-value"
    assert OpenBaoKV.staged(@context, "id-2") == :lost
    assert OpenBaoKV.staged(%Context{ref: "nix-cache/other"}, "id-1") == :lost
  end

  test "delivers to each consumer's own path", %{server: server} do
    consumer = %{"name" => "nix-csi/pr", "path" => "consumers/nix-csi/pr"}
    assert OpenBaoKV.consumer_name(consumer) == "nix-csi/pr"
    assert :ok = OpenBaoKV.deliver(@context, consumer, "id-1", secret())
    assert Agent.get(server, & &1.kv)["consumers/nix-csi/pr"]["token"] == "avrot_kv-token-value"
  end

  test "refuses consumer paths into staging or out of the mount" do
    for path <- ["staging/nix-cache/pr-farm", "../sys/policy", "a//b", "", nil] do
      assert {:error, {:openbao_kv, :path, _}} =
               OpenBaoKV.deliver(@context, %{name: "x", path: path}, "id", secret())
    end
  end

  test "a refused write is an error naming the path and status, never the body", %{server: server} do
    Agent.update(server, &Map.put(&1, :status, 403))

    log =
      capture_log(fn ->
        assert {:error, {:openbao_kv, :write, "consumers/argo/ci", 403} = error} =
                 OpenBaoKV.deliver(
                   @context,
                   %{name: "argo/ci", path: "consumers/argo/ci"},
                   "id",
                   secret()
                 )

        assert OpenBaoKV.describe_error(error) == "openbao kv write consumers/argo/ci: HTTP 403"
        assert {:error, {:openbao_kv, :read, _, 403}} = OpenBaoKV.staged(@context, "id")
      end)

    refute log =~ "kv-token-value"
  end

  test "an unreachable OpenBao is the provider's ProviderUnavailable" do
    Req.Test.stub(__MODULE__, &Req.Test.transport_error(&1, :econnrefused))
    assert {:error, %ProviderUnavailable{} = error} = OpenBaoKV.stage(@context, "id", secret())
    refute inspect(error) =~ "kv-token-value"
  end

  test "missing configuration is an error, not a crash" do
    Application.delete_env(:ash_vault, OpenBaoKV)
    assert {:error, {:openbao_kv, :config, _}} = OpenBaoKV.stage(@context, "id", secret())
  end
end
