defmodule AshVault.KeyProviders.OpenBaoRetirementTest do
  use ExUnit.Case, async: false
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Errors.ProviderForbidden
  alias AshVault.KeyProviders.{OpenBao, OpenBaoTransit}
  alias AshVault.KeyProviders.OpenBao.Transport

  @protocol "ashvault-retirement/v1"
  @name OpenBao.key_name("retirement-test")

  setup context do
    Req.Test.set_req_test_to_shared(context)

    for provider <- [OpenBao, OpenBaoTransit] do
      previous = Application.get_env(:ash_vault, provider)

      Application.put_env(:ash_vault, provider,
        token: "test-token",
        server_retirement: true,
        max_retries: 0,
        req_options: [plug: {Req.Test, __MODULE__}]
      )

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_vault, provider, previous),
          else: Application.delete_env(:ash_vault, provider)
      end)
    end

    {:ok, calls} = Agent.start_link(fn -> [] end)

    Req.Test.stub(__MODULE__, fn conn ->
      Agent.update(calls, &[{conn.method, conn.request_path} | &1])
      {status, body} = respond(context, conn)
      Req.Test.json(Plug.Conn.put_status(conn, status), body)
    end)

    %{calls: calls}
  end

  defp protocol(initialized),
    do: %{
      "data" => %{"protocol" => @protocol, "transactional" => true, "initialized" => initialized}
    }

  defp retired(value),
    do: %{"data" => %{"protocol" => @protocol, "initialized" => true, "retired" => value}}

  defp absent, do: {404, %{"errors" => []}}

  defp respond(%{scenario: :setup} = context, conn) do
    if conn.request_path =~ "/sys/mounts/",
      do: {204, %{}},
      else: context[:reply] || {200, protocol(true)}
  end

  defp respond(%{scenario: :destroy} = context, conn) do
    cond do
      conn.method == "GET" -> if(context[:existing], do: {200, %{"data" => %{}}}, else: absent())
      conn.request_path =~ "/data/tombstones/" -> {200, %{}}
      true -> context[:reply] || {200, retired(true)}
    end
  end

  defp respond(%{scenario: :status} = context, conn) do
    if conn.request_path =~ "/data/tombstones/",
      do: absent(),
      else: context[:reply] || {200, retired(true)}
  end

  defp respond(%{scenario: :migration} = context, conn) do
    cond do
      conn.request_path == "/v1/sys/mounts" ->
        context[:mount_reply] ||
          {200,
           %{"data" => %{"ashvault/" => %{"type" => "kv", "options" => %{"version" => "2"}}}}}

      conn.request_path =~ "/protocol" ->
        {200, protocol(false)}

      conn.request_path =~ "/metadata/tombstones" ->
        assert conn.query_string == "list=true"
        context[:reply] || {200, %{"data" => %{"keys" => [@name]}}}

      conn.method == "GET" ->
        context[:tombstone_reply] || {404, %{"data" => %{"data" => nil, "metadata" => %{}}}}

      conn.request_path =~ "/retire/" ->
        context[:retire_reply] || {200, retired(true)}

      true ->
        context[:initialize_reply] || {200, protocol(true)}
    end
  end

  defp respond(%{scenario: :runtime}, conn) do
    cond do
      conn.request_path =~ "/data/tombstones/" ->
        absent()

      conn.request_path =~ "/ashvault/retired/" ->
        {200, retired(false)}

      conn.request_path =~ "/keys/" ->
        {200,
         %{
           "data" => %{
             "exportable" => false,
             "type" => "aes256-gcm96",
             "latest_version" => 1,
             "min_decryption_version" => 1,
             "keys" => %{"1" => 1_791_000_000}
           }
         }}

      true ->
        {410, %{"protocol" => @protocol, "ashvault_error" => "scope_retired"}}
    end
  end

  defp respond(context, _conn), do: context.reply

  @tag reply: {403, %{"errors" => ["private-needle"]}}
  test "protocol policy refusal retains its taxonomy" do
    assert {:error, %ProviderForbidden{operation: :retirement_protocol} = error} =
             Transport.retirement_protocol(OpenBao, true)

    refute inspect(error) =~ "private-needle"
  end

  @tag scenario: :status, reply: {403, %{}}
  test "retirement status policy refusal retains its taxonomy" do
    assert {:error, %ProviderForbidden{operation: :read_retirement}} =
             OpenBao.current_key("retirement-test")
  end

  @tag scenario: :destroy, existing: true, reply: {403, %{}}
  test "retirement policy refusal retains its taxonomy" do
    assert {:error, %ProviderForbidden{operation: :retire_scope}} =
             OpenBao.destroy("retirement-test")
  end

  @tag scenario: :migration, reply: {403, %{}}
  test "listing policy refusal retains its taxonomy" do
    assert {:error, %ProviderForbidden{operation: :list_tombstones}} =
             Transport.initialize_retirement(OpenBao)
  end

  @tag scenario: :migration, initialize_reply: {403, %{}}
  test "initialization policy refusal retains its taxonomy" do
    assert {:error, %ProviderForbidden{operation: :initialize_retirement}} =
             Transport.initialize_retirement(OpenBao)
  end

  for options <- [
        [tombstone_reply: {503, %{}}],
        [tombstone_reply: {404, %{"errors" => []}}],
        [retire_reply: {503, %{}}],
        [retire_reply: {200, %{"data" => %{}}}]
      ] do
    @tag Keyword.merge([scenario: :migration], options)
    test "partial import never activates #{inspect(options)}", %{calls: calls} do
      assert {:error, %ProviderUnavailable{}} = Transport.initialize_retirement(OpenBao)
      refute {"POST", "/v1/transit/ashvault/initialize"} in Agent.get(calls, & &1)
    end
  end

  @tag scenario: :migration, reply: {404, %{"errors" => []}}
  test "operator task activates a fresh mount" do
    assert ExUnit.CaptureIO.capture_io(fn ->
             Mix.Tasks.AshVault.Openbao.InitRetirement.run(["AshVault.KeyProviders.OpenBao"])
           end) =~ "KV tombstones imported"
  end

  @tag reply: {200, %{}}
  test "stock remains default and malformed configuration is rejected" do
    config = Application.get_env(:ash_vault, OpenBao)
    Application.put_env(:ash_vault, OpenBao, Keyword.delete(config, :server_retirement))
    refute Transport.server_retirement?(OpenBao)
    Application.put_env(:ash_vault, OpenBao, Keyword.put(config, :server_retirement, "true"))

    assert_raise ArgumentError, ~r/server_retirement must be a boolean/, fn ->
      Transport.server_retirement?(OpenBao)
    end
  end

  for reply <- [
        {200, %{"data" => %{}}},
        {200, %{"data" => %{"ashvault/" => %{"type" => "kv", "options" => %{"version" => "1"}}}}},
        {200,
         %{"data" => %{"ashvault/" => %{"type" => "transit", "options" => %{"version" => "2"}}}}},
        {503, %{}}
      ] do
    @tag scenario: :migration, mount_reply: reply
    test "migration refuses an unconfirmed KV-v2 mount #{inspect(reply)}", %{calls: calls} do
      assert {:error, %ProviderUnavailable{}} = Transport.initialize_retirement(OpenBao)
      refute Enum.any?(Agent.get(calls, & &1), &match?({"POST", _}, &1))
    end
  end

  for provider <- [OpenBao, OpenBaoTransit] do
    @tag scenario: :setup
    test "#{inspect(provider)} requires an initialized transactional protocol" do
      assert :ok = unquote(provider).setup()
    end

    for reply <- [
          {404, %{"errors" => []}},
          {200, %{"data" => %{}}},
          {200,
           %{
             "data" => %{"protocol" => @protocol, "transactional" => false, "initialized" => true}
           }},
          {200,
           %{
             "data" => %{"protocol" => @protocol, "transactional" => true, "initialized" => false}
           }}
        ] do
      @tag scenario: :setup, reply: reply
      test "#{inspect(provider)} rejects protocol #{inspect(reply)}" do
        assert {:error, %ProviderUnavailable{}} = unquote(provider).setup()
      end
    end

    @tag scenario: :destroy
    test "#{inspect(provider)} writes legacy tombstone then retires without separate deletes", %{
      calls: calls
    } do
      provider = unquote(provider)
      name = provider.key_name("retirement-test")
      assert :ok = provider.destroy("retirement-test")

      preflight =
        if provider == OpenBaoTransit do
          for suffix <- ["", ".mac", "_lookup"], do: {"GET", "/v1/transit/keys/#{name}#{suffix}"}
        else
          []
        end

      assert Enum.reverse(Agent.get(calls, & &1)) ==
               preflight ++
                 [
                   {"GET", "/v1/ashvault/data/tombstones/#{name}"},
                   {"POST", "/v1/ashvault/data/tombstones/#{name}"},
                   {"POST", "/v1/transit/ashvault/retire/#{name}"}
                 ]
    end

    @tag scenario: :destroy, existing: true, reply: {503, %{"errors" => ["private-needle"]}}
    test "#{inspect(provider)} retries server retirement behind existing tombstone" do
      assert {:error, %ProviderUnavailable{} = error} =
               unquote(provider).destroy("retirement-test")

      refute inspect(error) =~ "private-needle"
    end
  end

  @tag scenario: :status
  test "server-only retirement remains permanent without a legacy tombstone" do
    assert {:error, :destroyed} = OpenBao.current_key("retirement-test")
  end

  for reply <- [{200, %{"data" => %{}}}, {404, %{"errors" => []}}, {503, %{}}] do
    @tag scenario: :status, reply: reply
    test "ambiguous retirement status fails closed #{inspect(reply)}" do
      assert {:error, %ProviderUnavailable{}} = OpenBao.current_key("retirement-test")
    end
  end

  @tag reply: {410, %{"protocol" => @protocol, "ashvault_error" => "scope_retired"}}
  test "only opted-in providers classify plugin retirement error" do
    assert {:error, :destroyed} = Transport.post(OpenBaoTransit, "/v1/transit/encrypt/#{@name}")

    Application.put_env(
      :ash_vault,
      OpenBaoTransit,
      Application.get_env(:ash_vault, OpenBaoTransit) |> Keyword.put(:server_retirement, false)
    )

    assert {:ok, %{status: 410}} = Transport.post(OpenBaoTransit, "/v1/transit/encrypt/#{@name}")
  end

  @tag reply: {410, %{"errors" => ["scope_retired"]}}
  test "arbitrary HTTP 410 never invents erasure" do
    assert {:ok, %{status: 410}} = Transport.post(OpenBaoTransit, "/v1/transit/encrypt/#{@name}")
  end

  for operation <- [:encrypt, :decrypt, :mac, :verify] do
    @tag scenario: :runtime, operation: operation
    test "retirement after handle acquisition remains KeyDestroyed during #{operation}",
         context do
      vault = AshVault.Test.Support.TransitVault
      ctx = AshVault.Test.Support.Helpers.context_for("retirement-test")

      blob =
        AshVault.Envelope.V1.encode(%{
          version: 1,
          cipher: AshVault.Ciphers.OpenBaoTransit.id(),
          key_version: 1,
          nonce: "",
          tag: "",
          ciphertext: "vault:v1:AAAA"
        })

      assert_raise AshVault.Errors.KeyDestroyed, fn ->
        case context.operation do
          :encrypt -> vault.encrypt!("secret", ctx)
          :decrypt -> vault.decrypt!(blob, ctx)
          :mac -> vault.mac!("payload", ctx)
          :verify -> vault.verify_mac!("payload", 1, <<0::256>>, ctx)
        end
      end
    end
  end

  @tag scenario: :migration
  test "migration imports soft-deleted tombstones before activating", %{calls: calls} do
    assert :ok = Transport.initialize_retirement(OpenBao)

    assert Enum.reverse(Agent.get(calls, & &1)) == [
             {"GET", "/v1/transit/ashvault/protocol"},
             {"GET", "/v1/sys/mounts"},
             {"GET", "/v1/ashvault/metadata/tombstones"},
             {"GET", "/v1/ashvault/data/tombstones/#{@name}"},
             {"POST", "/v1/transit/ashvault/retire/#{@name}"},
             {"POST", "/v1/transit/ashvault/initialize"}
           ]
  end

  for reply <- [
        {200, %{"data" => %{}}},
        {200, %{"data" => %{"keys" => ["../escape"]}}},
        {404, %{"errors" => ["no handler for route"]}},
        {503, %{}}
      ] do
    @tag scenario: :migration, reply: reply
    test "migration refuses unsafe listing #{inspect(reply)}", %{calls: calls} do
      assert {:error, %ProviderUnavailable{}} = Transport.initialize_retirement(OpenBao)
      refute Enum.any?(Agent.get(calls, & &1), &match?({"POST", _}, &1))
    end
  end
end
