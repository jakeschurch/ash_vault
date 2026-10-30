defmodule AshVault.KeyProviders.OpenBaoCreateDestroyTest do
  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderForbidden
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.{OpenBao, OpenBaoTransit}

  @providers [OpenBao, OpenBaoTransit]
  @scope "create-destroy-race"

  setup context do
    Req.Test.set_req_test_to_shared(context)
    previous = Map.new(@providers, &{&1, Application.get_env(:ash_vault, &1)})

    for provider <- @providers do
      Application.put_env(:ash_vault, provider,
        address: "http://bao.test",
        token: "synthetic-test-token",
        max_retries: 0,
        req_options: [plug: {Req.Test, __MODULE__}]
      )
    end

    on_exit(fn ->
      for {provider, config} <- previous do
        if config,
          do: Application.put_env(:ash_vault, provider, config),
          else: Application.delete_env(:ash_vault, provider)
      end

      Req.Test.set_req_test_to_private(%{})
    end)

    server =
      start_supervised!(
        {Agent,
         fn ->
           %{
             tombstone: false,
             keys: %{},
             cleanup_status: 200,
             create_status: 200,
             tombstone_status: 200,
             requests: [],
             pause: context[:pause] || :before
           }
         end}
      )

    owner = self()
    Req.Test.stub(__MODULE__, &route(&1, server, owner))
    %{server: server}
  end

  for provider <- @providers,
      operation <- [:current_data, :current_mac, :rotate_data, :rotate_mac, :lookup],
      not (provider == OpenBaoTransit and operation == :lookup) do
    @tag provider: provider, operation: operation
    test "#{inspect(provider)} #{operation} cleans a create completed after destroy", context do
      {reader, creator} = paused_create(context)
      assert :ok = context.provider.destroy(@scope)
      assert Agent.get(context.server, & &1.keys) == %{}

      send(creator, :finish_create)
      result = Task.await(reader)
      assert Agent.get(context.server, & &1.keys) == %{}
      assert {:error, :destroyed} = result

      refute Enum.any?(Agent.get(context.server, & &1.requests), fn
               {"GET", "/v1/transit/export/" <> _} -> true
               _ -> false
             end)

      assert {:error, :destroyed} = invoke(context.provider, context.operation)
      assert :ok = context.provider.destroy(@scope)
    end
  end

  for provider <- @providers do
    @tag provider: provider, operation: :current_mac, pause: :after
    test "#{inspect(provider)} refuses a response received after destroy deleted the new key",
         context do
      {reader, creator} = paused_create(context)
      assert map_size(Agent.get(context.server, & &1.keys)) == 1
      assert :ok = context.provider.destroy(@scope)
      send(creator, :finish_create)

      assert {:error, :destroyed} = Task.await(reader)
      assert Agent.get(context.server, & &1.keys) == %{}
    end

    @tag provider: provider, operation: :current_mac
    test "#{inspect(provider)} cleans up even when the create response is an error", context do
      Agent.update(context.server, &%{&1 | create_status: 500})
      {reader, creator} = paused_create(context)
      assert :ok = context.provider.destroy(@scope)
      send(creator, :finish_create)

      assert {:error, :destroyed} = Task.await(reader)
      assert Agent.get(context.server, & &1.keys) == %{}
    end

    @tag provider: provider, operation: :current_mac
    test "#{inspect(provider)} reports failed cleanup and lets destroy retry it", context do
      {reader, creator} = paused_create(context)
      assert :ok = context.provider.destroy(@scope)
      Agent.update(context.server, &%{&1 | cleanup_status: 403})
      send(creator, :finish_create)

      assert {:error, %ProviderForbidden{}} = Task.await(reader)
      assert map_size(Agent.get(context.server, & &1.keys)) == 1
      Agent.update(context.server, &%{&1 | cleanup_status: 200})
      assert :ok = context.provider.destroy(@scope)
      assert Agent.get(context.server, & &1.keys) == %{}
    end

    @tag provider: provider, operation: :current_mac
    test "#{inspect(provider)} refuses a key if the post-create tombstone read fails", context do
      {reader, creator} = paused_create(context)
      Agent.update(context.server, &%{&1 | tombstone_status: 503})
      send(creator, :finish_create)

      assert {:error, %ProviderUnavailable{}} = Task.await(reader)
      # An outage is not proof of destruction: never delete a healthy scope on it.
      assert map_size(Agent.get(context.server, & &1.keys)) == 1
    end
  end

  defp paused_create(context) do
    reader = Task.async(fn -> invoke(context.provider, context.operation) end)
    assert_receive {:creating, creator}, 1_000
    {reader, creator}
  end

  defp invoke(provider, :current_data), do: provider.current_key(@scope)
  defp invoke(provider, :current_mac), do: provider.current_key(@scope, :mac)
  defp invoke(provider, :rotate_data), do: provider.rotate(@scope)
  defp invoke(provider, :rotate_mac), do: provider.rotate(@scope, :mac)
  defp invoke(provider, :lookup), do: provider.lookup_key(@scope)

  defp route(conn, server, owner) do
    Agent.update(server, &%{&1 | requests: [{conn.method, conn.request_path} | &1.requests]})
    route(conn, conn.method, conn.request_path, server, owner)
  end

  defp route(conn, "GET", "/v1/ashvault/data/tombstones/" <> _name, server, _owner) do
    state = Agent.get(server, & &1)

    cond do
      state.tombstone_status != 200 -> reply(conn, state.tombstone_status, %{"errors" => []})
      state.tombstone -> reply(conn, 200, %{"data" => %{}})
      true -> reply(conn, 404, %{"errors" => []})
    end
  end

  defp route(conn, "POST", "/v1/ashvault/data/tombstones/" <> _name, server, _owner) do
    Agent.update(server, &%{&1 | tombstone: true})
    reply(conn, 200, %{"data" => %{}})
  end

  defp route(conn, "GET", "/v1/transit/keys/" <> name, server, _owner) do
    case Agent.get(server, &Map.get(&1.keys, name)) do
      nil -> reply(conn, 404, %{"errors" => []})
      meta -> reply(conn, 200, %{"data" => meta})
    end
  end

  defp route(conn, "POST", "/v1/transit/keys/" <> name, server, owner) do
    if String.ends_with?(name, "/config") do
      reply(conn, Agent.get(server, & &1.cleanup_status), %{"data" => %{}})
    else
      if Agent.get(server, & &1.pause) == :before, do: pause(owner)
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body = Jason.decode!(body)

      meta = %{
        "latest_version" => 1,
        "keys" => %{"1" => 1_791_000_000},
        "exportable" => body["exportable"]
      }

      Agent.update(server, &%{&1 | keys: Map.put(&1.keys, name, meta)})
      if Agent.get(server, & &1.pause) == :after, do: pause(owner)
      reply(conn, Agent.get(server, & &1.create_status), %{"data" => meta})
    end
  end

  defp route(conn, "DELETE", "/v1/transit/keys/" <> name, server, _owner) do
    Agent.update(server, &%{&1 | keys: Map.delete(&1.keys, name)})
    Plug.Conn.send_resp(conn, 204, "")
  end

  defp route(conn, "GET", "/v1/transit/export/" <> rest, server, _owner) do
    [_kind, name, _version] = String.split(rest, "/")

    if Agent.get(server, &Map.has_key?(&1.keys, name)) do
      reply(conn, 200, %{"data" => %{"keys" => %{"1" => Base.encode64(<<1::256>>)}}})
    else
      reply(conn, 404, %{"errors" => []})
    end
  end

  defp pause(owner) do
    send(owner, {:creating, self()})
    receive do: (:finish_create -> :ok)
  end

  defp reply(conn, status, body), do: conn |> Plug.Conn.put_status(status) |> Req.Test.json(body)
end
