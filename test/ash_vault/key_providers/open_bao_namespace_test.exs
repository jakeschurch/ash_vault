defmodule AshVault.KeyProviders.OpenBaoNamespaceTest do
  use ExUnit.Case, async: false
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.{OpenBao, OpenBaoTransit}
  @scope Base.url_decode64!("nx_YWJk", padding: false)

  setup context do
    Req.Test.set_req_test_to_shared(context)

    for provider <- [OpenBao, OpenBaoTransit] do
      previous = Application.get_env(:ash_vault, provider)

      Application.put_env(:ash_vault, provider,
        token: "test-token",
        max_retries: 0,
        server_retirement: context[:strong] || false,
        req_options: [plug: {Req.Test, __MODULE__}]
      )

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_vault, provider, previous),
          else: Application.delete_env(:ash_vault, provider)
      end)
    end

    {:ok, requests} = Agent.start_link(fn -> [] end)

    Req.Test.stub(__MODULE__, fn conn ->
      Agent.update(requests, &[{conn.method, conn.request_path} | &1])

      {status, body} =
        cond do
          context[:foreign] ->
            if conn.request_path == "/v1/transit/keys/ashvault_nx_YWJk#{context.suffix}",
              do: {200, %{"data" => %{"exportable" => true}}},
              else: {404, %{"errors" => []}}

          true ->
            context[:reply] || {404, %{"errors" => []}}
        end

      Req.Test.json(Plug.Conn.put_status(conn, status), body)
    end)

    %{requests: requests}
  end

  for action <- [:current_key, :get_key, :rotate, :lookup_key, :destroy, :mac] do
    @tag action: action
    test "#{action} refuses to use an unprovisioned binary namespace", context do
      result =
        case context.action do
          :current_key -> OpenBao.current_key(@scope)
          :get_key -> OpenBao.get_key(@scope, 1)
          :rotate -> OpenBao.rotate(@scope)
          :lookup_key -> OpenBao.lookup_key(@scope)
          :destroy -> OpenBao.destroy(@scope)
          :mac -> OpenBao.current_key(@scope, :mac)
        end

      assert {:error, %ProviderUnavailable{reason: :binary_scope_namespace_migration_required}} =
               result

      assert [{"GET", "/v1/ashvault/data/namespaces/ashvault.v2.export.nx_YWJk"}] =
               Agent.get(context.requests, & &1)
    end
  end

  for strong <- [false, true], suffix <- ["", ".mac", "_lookup"] do
    @tag foreign: true, strong: strong, suffix: suffix
    test "native destruction refuses exportable #{suffix} keys in strong=#{strong}", context do
      assert {:error, %ProviderUnavailable{reason: :scope_namespace_conflict}} =
               OpenBaoTransit.destroy("abd")

      assert Enum.all?(Agent.get(context.requests, & &1), fn {method, path} ->
               method == "GET" and path =~ "/keys/"
             end)
    end
  end

  for reply <- [
        {200, %{"data" => %{}}},
        {200,
         %{"data" => %{"data" => %{"protocol" => "ashvault-namespace/v2", "ready" => false}}}},
        {404, %{"data" => %{"data" => nil, "metadata" => %{}}}},
        {503, %{}}
      ] do
    @tag reply: reply
    test "ambiguous namespace readiness fails closed #{inspect(reply)}" do
      assert {:error, %ProviderUnavailable{}} = OpenBao.current_key(@scope)
    end
  end
end
