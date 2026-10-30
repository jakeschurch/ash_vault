defmodule AshVault.KeyProviders.OpenBaoRedirectTest do
  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao
  alias AshVault.KeyProviders.OpenBao.KubernetesAuth
  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.KeyProviders.OpenBaoTransit

  @moduletag :tmp_dir

  setup do
    prior = Map.new([OpenBao, OpenBaoTransit], &{&1, Application.get_env(:ash_vault, &1)})

    on_exit(fn ->
      for {provider, config} <- prior do
        if config,
          do: Application.put_env(:ash_vault, provider, config),
          else: Application.delete_env(:ash_vault, provider)
      end
    end)
  end

  for provider <- [OpenBao, OpenBaoTransit], status <- [301, 302, 303, 307, 308] do
    @tag provider: provider, redirect_status: status
    test "#{inspect(provider)} refuses #{status} redirects without forwarding the token", %{
      provider: provider,
      redirect_status: status
    } do
      configure(provider)
      redirect_stub(status)

      assert {:error, %ProviderUnavailable{reason: {:http_status, ^status}}} =
               Transport.check_tombstone(provider, "scope")

      assert_received {:trusted_request, "/v1/ashvault/data/tombstones/scope"}
      refute_received :redirect_followed
    end
  end

  test "Kubernetes login does not replay the JWT to a redirected origin", %{tmp_dir: tmp_dir} do
    configure(OpenBao)
    redirect_stub(307)
    jwt_path = Path.join(tmp_dir, "jwt")
    File.write!(jwt_path, "synthetic-service-account-jwt")
    options = KubernetesAuth.options!(OpenBao, role: "review", jwt_path: jwt_path)

    assert {:error, %ProviderUnavailable{reason: {:kubernetes_auth, {:http_status, 307}}}} =
             Transport.kubernetes_login(OpenBao, options)

    assert_received {:trusted_request, "/v1/auth/kubernetes/login"}
    refute_received :redirect_followed
  end

  test "same-origin redirects are refused too" do
    configure(OpenBao)
    redirect_stub(307, "/redirected")

    assert {:ok, %{status: 307}} = Transport.get(OpenBao, "/v1/x")
    assert_received {:trusted_request, "/v1/x"}
    refute_received :redirect_followed
  end

  defp configure(provider) do
    Application.put_env(:ash_vault, provider,
      address: "https://trusted.review.test",
      token: "synthetic-review-token",
      max_retries: 0,
      # An arbitrary Req option cannot override the transport's credential boundary.
      req_options: [plug: {Req.Test, __MODULE__}, redirect: true, follow_redirects: true]
    )
  end

  defp redirect_stub(status, location \\ "http://untrusted.review.test/capture") do
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      if conn.host == "trusted.review.test" and conn.request_path != "/redirected" do
        send(test_pid, {:trusted_request, conn.request_path})
        conn |> Plug.Conn.put_resp_header("location", location) |> Plug.Conn.send_resp(status, "")
      else
        send(test_pid, :redirect_followed)
        Req.Test.json(conn, %{"data" => %{}})
      end
    end)
  end
end
