defmodule AshVault.Macs.OpenBaoTransitFailureTest do
  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider
  alias AshVault.Macs.OpenBaoTransit, as: Mac
  alias AshVault.Errors.{ProviderUnavailable, ProviderForbidden}

  @name Provider.mac_key_name("mac-failure")
  @handle Provider.mac_handle(@name, 1)
  @metadata %{
    "exportable" => false,
    "latest_version" => 2,
    "min_decryption_version" => 1,
    "keys" => %{"1" => 1_791_000_000, "2" => 1_791_000_001}
  }

  setup context do
    Req.Test.set_req_test_to_shared(context)
    previous = Application.get_env(:ash_vault, Provider)

    Application.put_env(:ash_vault, Provider,
      token: "test",
      max_retries: 0,
      req_options: [plug: {Req.Test, __MODULE__}]
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_vault, Provider, previous),
        else: Application.delete_env(:ash_vault, Provider)
    end)

    {:ok, attempted} = Agent.start_link(fn -> false end)

    Req.Test.stub(__MODULE__, fn conn ->
      if conn.method == "POST", do: Agent.update(attempted, fn _ -> true end)
      raced? = Agent.get(attempted, & &1)

      {status, body} =
        cond do
          conn.request_path == "/v1/sys/health" ->
            context[:health] ||
              {200, %{"initialized" => true, "sealed" => false, "standby" => false}}

          conn.method == "POST" ->
            context[:reply] || {400, %{"errors" => ["private-needle"]}}

          conn.request_path =~ "/data/tombstones/" ->
            if context[:race] == :erased and raced?,
              do: {200, %{"data" => %{"data" => %{}}}},
              else: context[:tombstone] || {404, %{"errors" => []}}

          conn.request_path == "/v1/transit/keys/#{@name}" ->
            case {context[:race], raced?} do
              {:deleted, true} -> {404, %{"errors" => []}}
              {:retired, true} -> {200, %{"data" => %{@metadata | "min_decryption_version" => 2}}}
              _ -> context[:metadata] || {200, %{"data" => @metadata}}
            end

          true ->
            flunk("unexpected request: #{conn.request_path}")
        end

      Req.Test.json(Plug.Conn.put_status(conn, status), body)
    end)

    :ok
  end

  for race <- [:deleted, :retired, :erased] do
    @tag race: race
    test "the vault classifies #{race} after resolving a valid handle" do
      expected =
        if unquote(race) == :erased,
          do: AshVault.Errors.KeyDestroyed,
          else: AshVault.Errors.KeyNotFound

      ctx = %AshVault.Context{
        resource: __MODULE__,
        field: :token,
        ash_context: %{tenant: "mac-failure"}
      }

      error =
        assert_raise expected, fn ->
          AshVault.Test.Support.TransitVault.verify_mac!("payload", 1, <<0::256>>, ctx)
        end

      assert error.scope == "mac-failure"
      if expected == AshVault.Errors.KeyNotFound, do: assert(error.key_version == 1)
    end
  end

  @tag metadata: {404, %{"errors" => []}}
  test "a positively absent key is not an outage" do
    assert {:error, {:key_not_found, 1}} = Mac.verify("d", <<0::256>>, @handle, "a")
    assert {:error, {:key_not_found, 1}} = Mac.mac("d", @handle, "a")
  end

  @tag metadata: {200, %{"data" => %{@metadata | "min_decryption_version" => 2}}}
  test "an operator-retired version is not an outage" do
    assert {:error, {:key_not_found, 1}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  @tag tombstone: {200, %{"data" => %{"data" => %{}}}}
  test "a concurrent erasure retains its taxonomy" do
    assert {:error, :destroyed} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  test "an unexplained 400 stays unavailable and redacts the response" do
    assert {:error, %ProviderUnavailable{} = error} = Mac.verify("d", <<0::256>>, @handle, "a")
    refute inspect(error) =~ "private-needle"
  end

  @tag tombstone: {503, %{"errors" => ["private-needle"]}}
  test "an unreadable tombstone cannot be classified as absence or erasure" do
    assert {:error, %ProviderUnavailable{}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  @tag metadata: {404, %{"errors" => ["no handler for route"]}}
  test "a missing Transit mount is unavailable" do
    assert {:error, %ProviderUnavailable{}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  @tag metadata: {200, %{"data" => %{"latest_version" => 2}}}
  test "incomplete metadata cannot prove a missing key version" do
    assert {:error, %ProviderUnavailable{}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  @tag health: {200, %{"initialized" => true, "sealed" => false, "standby" => true}},
       metadata: {404, %{"errors" => []}}
  test "a lagging standby cannot prove key absence" do
    assert {:error, %ProviderUnavailable{}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end

  @tag reply: {403, %{"errors" => ["private-needle"]}}
  test "policy denial stays forbidden" do
    assert {:error, %ProviderForbidden{}} = Mac.verify("d", <<0::256>>, @handle, "a")
  end
end
