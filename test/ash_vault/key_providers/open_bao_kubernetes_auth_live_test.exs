defmodule AshVault.KeyProviders.OpenBaoKubernetesAuthLiveTest do
  @moduledoc """
  Kubernetes auth against a live OpenBao.

  OpenBao validates a service-account JWT by calling the Kubernetes TokenReview API at
  the mount's `kubernetes_host`. There is no cluster here, so the test serves that one
  endpoint itself, over plain HTTP on a loopback port, and approves exactly the
  service account the role binds. Everything on the OpenBao side — the auth mount, the
  role, the login, the token's policies and TTL — is real.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.OpenBao.KubernetesAuth
  alias AshVault.KeyProviders.OpenBao.Transport

  @moduletag :openbao

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @root System.get_env("BAO_TOKEN") || "ashvault-root"
  @provider AshVault.Test.KubernetesAuthLiveProvider
  @namespace "foundry"
  @service_account "ashvault"

  setup do
    mount = "k8s-test-#{System.unique_integer([:positive])}"

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)
    reviewer = spawn_link(fn -> review_loop(listener) end)

    directory =
      Path.join(System.tmp_dir!(), "ash_vault_k8s_live_#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    jwt_path = Path.join(directory, "token")
    File.write!(jwt_path, service_account_jwt())

    root!(:post, "/v1/sys/auth/#{mount}", %{type: "kubernetes"})

    root!(:post, "/v1/auth/#{mount}/config", %{
      kubernetes_host: "http://127.0.0.1:#{port}",
      kubernetes_ca_cert: placeholder_ca_pem(),
      disable_local_ca_jwt: true
    })

    root!(:post, "/v1/auth/#{mount}/role/ashvault-foundry", %{
      bound_service_account_names: [@service_account],
      bound_service_account_namespaces: [@namespace],
      token_policies: ["default"],
      token_ttl: "1h",
      token_max_ttl: "4h"
    })

    Application.put_env(:ash_vault, @provider,
      address: @address,
      max_retries: 0,
      auth: {:kubernetes, role: "ashvault-foundry", mount: mount, jwt_path: jwt_path}
    )

    on_exit(fn ->
      KubernetesAuth.stop(@provider)
      Application.delete_env(:ash_vault, @provider)
      root!(:delete, "/v1/sys/auth/#{mount}", nil)
      Process.exit(reviewer, :kill)
      :gen_tcp.close(listener)
      File.rm_rf!(directory)
    end)

    {:ok, mount: mount}
  end

  test "logs in and uses the issued token", %{mount: mount} do
    assert {:ok, %{status: 200, body: body}} =
             Transport.get(@provider, "/v1/auth/token/lookup-self")

    data = body["data"]
    assert data["path"] == "auth/#{mount}/login"
    assert data["meta"]["role"] == "ashvault-foundry"
    assert data["meta"]["service_account_name"] == @service_account
    assert "default" in data["policies"]
    assert data["ttl"] > 3_000 and data["ttl"] <= 3_600
  end

  test "a role the service account is not bound to is a retryable ProviderUnavailable",
       %{mount: mount} do
    root!(:post, "/v1/auth/#{mount}/role/other", %{
      bound_service_account_names: ["someone-else"],
      bound_service_account_namespaces: [@namespace],
      token_policies: ["default"]
    })

    config = Application.get_env(:ash_vault, @provider)
    {:kubernetes, auth} = config[:auth]

    Application.put_env(
      :ash_vault,
      @provider,
      Keyword.put(config, :auth, {:kubernetes, Keyword.put(auth, :role, "other")})
    )

    ExUnit.CaptureLog.capture_log(fn ->
      assert {:error, %AshVault.Errors.ProviderUnavailable{reason: {:kubernetes_auth, reason}}} =
               Transport.get(@provider, "/v1/auth/token/lookup-self")

      assert reason in [:forbidden, {:http_status, 400}]
    end)
  end

  defp root!(method, path, body) do
    options = [
      method: method,
      base_url: @address,
      url: path,
      headers: [{"x-vault-token", @root}],
      retry: false
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options
    response = Req.request!(options)

    unless response.status in 200..299 do
      flunk("OpenBao #{method} #{path} returned #{response.status}: #{inspect(response.body)}")
    end

    response
  end

  # Required by OpenBao once `disable_local_ca_jwt` is set; unused against an `http://`
  # `kubernetes_host`.
  defp placeholder_ca_pem do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"placeholder", [])
    :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
  end

  defp service_account_jwt do
    header = Base.url_encode64(Jason.encode!(%{alg: "RS256", typ: "JWT"}), padding: false)

    claims =
      Base.url_encode64(
        Jason.encode!(%{
          iss: "kubernetes/serviceaccount",
          sub: "system:serviceaccount:#{@namespace}:#{@service_account}",
          "kubernetes.io/serviceaccount/namespace": @namespace,
          "kubernetes.io/serviceaccount/service-account.name": @service_account,
          "kubernetes.io/serviceaccount/service-account.uid":
            "00000000-0000-0000-0000-000000000001"
        }),
        padding: false
      )

    "#{header}.#{claims}.c2lnbmF0dXJl"
  end

  defp review_loop(listener) do
    with {:ok, socket} <- :gen_tcp.accept(listener) do
      review(socket)
      review_loop(listener)
    end
  end

  defp review(socket) do
    with {:ok, request} <- read_request(socket, "") do
      body =
        Jason.encode!(%{
          apiVersion: "authentication.k8s.io/v1",
          kind: "TokenReview",
          status: %{
            authenticated: String.contains?(request, "tokenreviews"),
            user: %{
              username: "system:serviceaccount:#{@namespace}:#{@service_account}",
              uid: "00000000-0000-0000-0000-000000000001",
              groups: ["system:serviceaccounts"]
            }
          }
        })

      :gen_tcp.send(socket, [
        "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\nconnection: close\r\n",
        "content-length: #{byte_size(body)}\r\n\r\n",
        body
      ])
    end

    :gen_tcp.close(socket)
  end

  defp read_request(socket, buffer) do
    case :binary.split(buffer, "\r\n\r\n") do
      [head, rest] ->
        length =
          case Regex.run(~r/content-length:\s*(\d+)/i, head) do
            [_, value] -> String.to_integer(value)
            nil -> 0
          end

        read_body(socket, head, rest, length)

      [_incomplete] ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> read_request(socket, buffer <> data)
          error -> error
        end
    end
  end

  defp read_body(_socket, head, body, length) when byte_size(body) >= length,
    do: {:ok, head <> "\r\n\r\n" <> body}

  defp read_body(socket, head, body, length) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> read_body(socket, head, body <> data, length)
      error -> error
    end
  end
end
