defmodule AshVault.KeyProviders.OpenBaoKubernetesAuthTest do
  @moduledoc """
  The Kubernetes auth token holder, against a stubbed OpenBao (`Req.Test`).

  `async: false`: the holder is spawned by AshVault's supervisor, not the test process,
  so the `Req.Test` stub runs in shared mode, and the logger level is global.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao.KubernetesAuth
  alias AshVault.KeyProviders.OpenBao.Transport

  @provider AshVault.Test.KubernetesAuthProvider
  @stub AshVault.Test.KubernetesAuthStub
  @token "hvs.k8s-client-token-SECRET"

  setup context do
    Req.Test.set_req_test_to_shared(context)

    directory =
      Path.join(System.tmp_dir!(), "ash_vault_k8s_#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    jwt_path = Path.join(directory, "token")
    File.write!(jwt_path, "jwt-1\n")

    on_exit(fn ->
      KubernetesAuth.stop(@provider)
      Application.delete_env(:ash_vault, @provider)
      Req.Test.set_req_test_to_private(%{})
      File.rm_rf!(directory)
    end)

    {:ok, jwt_path: jwt_path}
  end

  defp configure(jwt_path, auth_overrides \\ [], overrides \\ []) do
    auth =
      Keyword.merge(
        [role: "ashvault-foundry", jwt_path: jwt_path, backoff_min: 50, backoff_max: 200],
        auth_overrides
      )

    Application.put_env(
      :ash_vault,
      @provider,
      Keyword.merge(
        [
          address: "http://openbao.test:8200",
          auth: {:kubernetes, auth},
          max_retries: 0,
          req_options: [plug: {Req.Test, @stub}]
        ],
        overrides
      )
    )
  end

  defp stub_bao(test_pid, login_fun) do
    Req.Test.stub(@stub, fn conn ->
      case conn.request_path do
        "/v1/auth/" <> _rest ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          decoded = Jason.decode!(body)

          send(
            test_pid,
            {:login, conn.request_path, decoded, Plug.Conn.get_req_header(conn, "x-vault-token")}
          )

          login_fun.(conn, decoded)

        path ->
          send(test_pid, {:request, path, Plug.Conn.get_req_header(conn, "x-vault-token")})
          Req.Test.json(conn, %{"data" => %{}})
      end
    end)
  end

  defp login_ok(token, lease) do
    fn conn, _decoded ->
      Req.Test.json(conn, %{
        "auth" => %{"client_token" => token, "lease_duration" => lease, "renewable" => true}
      })
    end
  end

  defp holder_pid do
    [{pid, _value}] = Registry.lookup(AshVault.KeyProviders.OpenBao.AuthRegistry, @provider)
    pid
  end

  # The stub reports a login when the request *arrives*; the holder swaps the token in
  # only when the login Task's result comes back. Until then it rightly keeps serving the
  # still-valid old token, so a test that needs the new one must wait for the swap.
  defp await_holder_token(token, attempts \\ 100) do
    cond do
      :sys.get_state(holder_pid()).token == token ->
        :ok

      attempts == 0 ->
        flunk("holder never switched to #{inspect(token)}")

      true ->
        Process.sleep(10)
        await_holder_token(token, attempts - 1)
    end
  end

  describe "login" do
    test "logs in with the SA JWT, caches the token and sends it on requests", %{
      jwt_path: jwt_path
    } do
      configure(jwt_path)
      stub_bao(self(), login_ok(@token, 3600))

      assert {:ok, %{status: 200}} = Transport.get(@provider, "/v1/transit/keys/a")

      assert_received {:login, "/v1/auth/kubernetes/login",
                       %{"role" => "ashvault-foundry", "jwt" => "jwt-1"}, []}

      assert_received {:request, "/v1/transit/keys/a", [@token]}

      assert {:ok, %{status: 200}} = Transport.get(@provider, "/v1/transit/keys/b")
      assert_received {:request, "/v1/transit/keys/b", [@token]}
      refute_received {:login, _, _, _}
    end

    test "honours a custom mount", %{jwt_path: jwt_path} do
      configure(jwt_path, mount: "k8s-prod")
      stub_bao(self(), login_ok(@token, 3600))

      assert {:ok, _response} = Transport.get(@provider, "/v1/sys/health")
      assert_received {:login, "/v1/auth/k8s-prod/login", _body, []}
    end

    test "concurrent callers with no token share one login", %{jwt_path: jwt_path} do
      configure(jwt_path)
      test_pid = self()

      stub_bao(test_pid, fn conn, decoded ->
        Process.sleep(100)
        login_ok(@token, 3600).(conn, decoded)
      end)

      1..5
      |> Enum.map(fn n -> Task.async(fn -> Transport.get(@provider, "/v1/x/#{n}") end) end)
      |> Enum.each(fn task -> assert {:ok, %{status: 200}} = Task.await(task) end)

      assert_received {:login, _, _, _}
      refute_received {:login, _, _, _}
    end

    test "a zero lease never expires and is never refreshed", %{jwt_path: jwt_path} do
      configure(jwt_path)
      stub_bao(self(), login_ok(@token, 0))

      assert {:ok, _response} = Transport.get(@provider, "/v1/x")
      assert_received {:login, _, _, _}
      assert :sys.get_state(holder_pid()).timer == nil
    end
  end

  describe "renewal" do
    test "logs in again before the lease expires, re-reading the rotated JWT",
         %{jwt_path: jwt_path} do
      configure(jwt_path, refresh_fraction: 0.5)

      stub_bao(self(), fn conn, decoded ->
        login_ok("token-for-" <> decoded["jwt"], 1).(conn, decoded)
      end)

      assert {:ok, _response} = Transport.get(@provider, "/v1/x")
      assert_received {:login, _, %{"jwt" => "jwt-1"}, _}
      File.write!(jwt_path, "jwt-2")

      assert_receive {:login, _, %{"jwt" => "jwt-2"}, _}, 900
      await_holder_token("token-for-jwt-2")

      assert {:ok, _response} = Transport.get(@provider, "/v1/y")
      assert_received {:request, "/v1/y", ["token-for-jwt-2"]}
    end

    test "a failed refresh keeps serving the still-valid token", %{jwt_path: jwt_path} do
      configure(jwt_path, refresh_fraction: 0.1)
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      stub_bao(self(), fn conn, decoded ->
        case Agent.get_and_update(attempts, &{&1, &1 + 1}) do
          0 -> login_ok(@token, 5).(conn, decoded)
          _ -> conn |> Plug.Conn.put_status(503) |> Req.Test.json(%{"errors" => ["sealed"]})
        end
      end)

      capture_log(fn ->
        assert {:ok, _response} = Transport.get(@provider, "/v1/x")
        assert_received {:login, _, _, _}
        assert_receive {:login, _, _, _}, 1_000

        assert {:ok, _response} = Transport.get(@provider, "/v1/y")
        assert_received {:request, "/v1/y", [@token]}
      end)
    end
  end

  describe "failures are ProviderUnavailable" do
    test "a 403 from the login endpoint", %{jwt_path: jwt_path} do
      configure(jwt_path)

      stub_bao(self(), fn conn, _decoded ->
        conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"errors" => ["permission denied"]})
      end)

      capture_log(fn ->
        assert {:error,
                %ProviderUnavailable{provider: @provider, reason: {:kubernetes_auth, :forbidden}}} =
                 Transport.get(@provider, "/v1/x")
      end)

      refute_received {:request, _, _}
    end

    test "a transport failure", %{jwt_path: jwt_path} do
      configure(jwt_path)
      stub_bao(self(), fn conn, _decoded -> Req.Test.transport_error(conn, :econnrefused) end)

      capture_log(fn ->
        assert {:error,
                %ProviderUnavailable{reason: {:kubernetes_auth, {:transport, :econnrefused}}}} =
                 Transport.get(@provider, "/v1/x")
      end)
    end

    test "a missing service-account JWT", %{jwt_path: jwt_path} do
      File.rm!(jwt_path)
      configure(jwt_path)
      stub_bao(self(), login_ok(@token, 3600))

      capture_log(fn ->
        assert {:error,
                %ProviderUnavailable{
                  reason: {:kubernetes_auth, {:jwt_unreadable, ^jwt_path, :enoent}}
                } = error} =
                 Transport.get(@provider, "/v1/x")

        assert Exception.message(error) =~ "Kubernetes auth"
      end)

      refute_received {:login, _, _, _}
    end

    test "a 200 without a client token", %{jwt_path: jwt_path} do
      configure(jwt_path)
      stub_bao(self(), fn conn, _decoded -> Req.Test.json(conn, %{"auth" => nil}) end)

      capture_log(fn ->
        assert {:error,
                %ProviderUnavailable{reason: {:kubernetes_auth, :malformed_login_response}}} =
                 Transport.get(@provider, "/v1/x")
      end)
    end

    test "backs off: a caller inside the window does not trigger another login, the retry does",
         %{jwt_path: jwt_path} do
      configure(jwt_path, backoff_min: 300, backoff_max: 300)
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      stub_bao(self(), fn conn, decoded ->
        case Agent.get_and_update(attempts, &{&1, &1 + 1}) do
          0 -> conn |> Plug.Conn.put_status(500) |> Req.Test.json(%{"errors" => []})
          _ -> login_ok(@token, 3600).(conn, decoded)
        end
      end)

      capture_log(fn ->
        assert {:error, %ProviderUnavailable{reason: {:kubernetes_auth, {:http_status, 500}}}} =
                 Transport.get(@provider, "/v1/x")

        assert {:error, %ProviderUnavailable{reason: {:kubernetes_auth, {:http_status, 500}}}} =
                 Transport.get(@provider, "/v1/x")

        assert_received {:login, _, _, _}
        refute_received {:login, _, _, _}

        assert_receive {:login, _, _, _}, 1_000
        assert {:ok, _response} = Transport.get(@provider, "/v1/y")
        assert_received {:request, "/v1/y", [@token]}
      end)
    end

    test "backoff doubles up to the cap" do
      options =
        KubernetesAuth.options!(@provider, role: "r", backoff_min: 100, backoff_max: 1_000)

      assert Enum.map(1..6, &KubernetesAuth.backoff(options, &1)) == [
               100,
               200,
               400,
               800,
               1_000,
               1_000
             ]
    end
  end

  describe "secrets" do
    setup do
      level = Logger.level()
      Logger.configure(level: :debug)
      on_exit(fn -> Logger.configure(level: level) end)
    end

    test "neither the client token nor the JWT reaches a log line or the process status",
         %{jwt_path: jwt_path} do
      File.write!(jwt_path, "jwt-SECRET-VALUE")
      configure(jwt_path, refresh_fraction: 0.1)
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      stub_bao(self(), fn conn, decoded ->
        case Agent.get_and_update(attempts, &{&1, &1 + 1}) do
          0 -> login_ok(@token, 2).(conn, decoded)
          _ -> conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"errors" => [@token]})
        end
      end)

      log =
        capture_log(fn ->
          assert {:ok, _response} = Transport.get(@provider, "/v1/x")
          assert_receive {:login, _, _, _}
          assert_receive {:login, _, _, _}, 1_000
          Process.sleep(50)

          status = :sys.get_status(holder_pid())
          {:status, _pid, _module, [_dictionary, _sys_state, _parent, _debug, misc]} = status

          state =
            misc
            |> Keyword.get_values(:data)
            |> List.flatten()
            |> Enum.find_value(fn
              {~c"State", state} -> state
              _other -> nil
            end)

          assert state.token == :redacted

          raw = inspect(status, structs: false, limit: :infinity, printable_limit: :infinity)
          refute raw =~ @token
          refute raw =~ "jwt-SECRET-VALUE"
          refute inspect(:sys.get_state(holder_pid())) =~ @token

          KubernetesAuth.stop(@provider)
        end)

      assert log =~ "Kubernetes auth login"
      assert log =~ "succeeded"
      assert log =~ "failed"
      refute log =~ @token
      refute log =~ "jwt-SECRET-VALUE"
    end
  end

  describe "configuration" do
    test ":token and :auth together is refused, without echoing the token", %{jwt_path: jwt_path} do
      configure(jwt_path, [], token: @token)

      error = assert_raise ArgumentError, fn -> Transport.get(@provider, "/v1/x") end
      assert error.message =~ "both :token and auth"
      refute error.message =~ @token
    end

    test "a missing :role is refused", %{jwt_path: jwt_path} do
      configure(jwt_path, role: nil)
      assert_raise ArgumentError, ~r/:role/, fn -> Transport.get(@provider, "/v1/x") end
    end

    test "an unknown auth method is refused" do
      Application.put_env(:ash_vault, @provider, auth: {:approle, role_id: "x"})
      assert_raise ArgumentError, ~r/:approle/, fn -> Transport.get(@provider, "/v1/x") end
    end

    test "the static :token forms still work" do
      System.put_env("ASH_VAULT_K8S_TEST_TOKEN", "from-env")
      on_exit(fn -> System.delete_env("ASH_VAULT_K8S_TEST_TOKEN") end)
      stub_bao(self(), login_ok(@token, 0))

      for {token, expected} <- [
            {"literal", "literal"},
            {{:system, "ASH_VAULT_K8S_TEST_TOKEN"}, "from-env"},
            {fn -> "from-fun" end, "from-fun"}
          ] do
        Application.put_env(:ash_vault, @provider,
          address: "http://openbao.test:8200",
          token: token,
          req_options: [plug: {Req.Test, @stub}]
        )

        assert {:ok, _response} = Transport.get(@provider, "/v1/x")
        assert_received {:request, "/v1/x", [^expected]}
      end

      refute_received {:login, _, _, _}
    end
  end
end
