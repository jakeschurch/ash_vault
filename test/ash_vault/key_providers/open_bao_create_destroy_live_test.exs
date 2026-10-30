defmodule AshVault.KeyProviders.OpenBaoCreateDestroyLiveTest do
  @moduledoc """
  Pause a real transit create until after a real destroy has completed. Req.Test only
  controls scheduling; every HTTP operation is forwarded to the live OpenBao server.
  """
  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.{OpenBao, OpenBaoTransit}

  @moduletag :openbao
  @address System.get_env("BAO_ADDR", "http://127.0.0.1:8200")
  @token System.get_env("BAO_TOKEN", "ashvault-root")

  setup context do
    Req.Test.set_req_test_to_shared(context)
    provider = context.provider
    previous = Application.get_env(:ash_vault, provider)
    scope = "race-live-#{System.unique_integer([:positive])}"
    name = key_name(provider, scope, context.operation)
    owner = self()

    Application.put_env(:ash_vault, provider,
      address: @address,
      token: @token,
      max_retries: 0,
      req_options: [plug: {Req.Test, __MODULE__}]
    )

    Req.Test.stub(__MODULE__, fn conn ->
      if conn.method == "POST" and conn.request_path == "/v1/transit/keys/#{name}" do
        send(owner, {:creating, self()})
        receive do: (:finish_create -> :ok)
      end

      forward(conn)
    end)

    on_exit(fn ->
      # Cleanup bypasses the scheduling stub, including after a failed assertion.
      Application.put_env(:ash_vault, provider, address: @address, token: @token, max_retries: 0)
      provider.destroy(scope)

      if previous,
        do: Application.put_env(:ash_vault, provider, previous),
        else: Application.delete_env(:ash_vault, provider)

      Req.Test.set_req_test_to_private(%{})
    end)

    assert :ok = provider.setup()
    %{scope: scope, name: name}
  end

  for provider <- [OpenBao, OpenBaoTransit],
      operation <- [
        current_key: :data,
        current_key: :mac,
        rotate: :data,
        rotate: :mac,
        lookup_key: :data
      ],
      not (provider == OpenBaoTransit and elem(operation, 0) == :lookup_key) do
    @tag provider: provider, operation: operation
    test "#{inspect(provider)} #{inspect(operation)} removes a late-created key", context do
      {function, purpose} = context.operation
      args = if function == :lookup_key, do: [context.scope], else: [context.scope, purpose]
      reader = Task.async(fn -> apply(context.provider, function, args) end)
      assert_receive {:creating, creator}, 5_000
      assert :ok = context.provider.destroy(context.scope)
      assert_absent(context.name)
      send(creator, :finish_create)

      assert {:error, :destroyed} = Task.await(reader, 10_000)
      assert_absent(context.name)
      assert {:error, :destroyed} = apply(context.provider, function, args)
      assert :ok = context.provider.destroy(context.scope)
    end
  end

  defp key_name(provider, scope, {:lookup_key, _}), do: provider.lookup_key_name(scope)
  defp key_name(provider, scope, {_, :mac}), do: provider.mac_key_name(scope)
  defp key_name(provider, scope, {_, :data}), do: provider.key_name(scope)

  defp assert_absent(name) do
    response = Req.get!(@address <> "/v1/transit/keys/#{name}", headers: headers(), retry: false)
    assert response.status == 404
    assert response.body == %{"errors" => []}
  end

  defp forward(conn) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)

    response =
      Req.request!(
        url: @address <> conn.request_path,
        method: conn.method |> String.downcase() |> String.to_existing_atom(),
        headers: headers(),
        body: body,
        retry: false,
        redirect: false
      )

    if is_map(response.body),
      do: conn |> Plug.Conn.put_status(response.status) |> Req.Test.json(response.body),
      else: Plug.Conn.send_resp(conn, response.status, response.body)
  end

  defp headers, do: [{"x-vault-token", @token}, {"content-type", "application/json"}]
end
