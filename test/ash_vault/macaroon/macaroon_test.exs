defmodule AshVault.Macaroon.MacaroonTest do
  # Not async: the key provider is the default-named Memory, and the clock seam is
  # application env.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias AshVault.Errors.InvalidMacaroon
  alias AshVault.Errors.MacaroonRevoked
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.Memory
  alias AshVault.Macaroon
  alias AshVault.Macaroon.Envelope
  alias AshVault.Macaroon.Verified
  alias AshVault.Test.ApiClient
  alias AshVault.Test.FlakyApiClient
  alias AshVault.Test.GlobalApiClient
  alias AshVault.Test.Support.FlakyMacProvider
  alias AshVault.Test.Widget

  @clock {__MODULE__, :clock}

  def now, do: :persistent_term.get(@clock, DateTime.utc_now())

  setup do
    start_supervised!({Memory, name: Memory})
    Application.put_env(:ash_vault, :macaroon_clock, {__MODULE__, :now, []})

    on_exit(fn ->
      Application.delete_env(:ash_vault, :macaroon_clock)
      :persistent_term.erase(@clock)
      FlakyMacProvider.recover!()
    end)

    client =
      Ash.create!(ApiClient, %{name: "ci", org_id: "acme"}, tenant: "acme", authorize?: false)

    %{client: client}
  end

  defp mint(client, input \\ %{}, tenant \\ "acme") do
    ApiClient.mint_api(client.id, input, tenant: tenant, authorize?: false)
  end

  defp verify(token, opts \\ []), do: ApiClient.api_by_token(token, opts)

  defp reason({:error, %Ash.Error.Invalid{errors: [%InvalidMacaroon{reason: reason}]}}),
    do: {:invalid, reason}

  defp reason({:error, %Ash.Error.Invalid{errors: [%MacaroonRevoked{reason: reason}]}}),
    do: {:revoked, reason}

  defp reason({:error, %InvalidMacaroon{reason: reason}}), do: {:invalid, reason}
  defp reason({:error, %MacaroonRevoked{reason: reason}}), do: {:revoked, reason}
  defp reason(other), do: other

  defp sign_in(token, opts \\ []) do
    ApiClient
    |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: token}, opts)
    |> Ash.read()
  end

  defp capture_rejections(fun) do
    ref = make_ref()
    parent = self()
    id = "rejections-#{inspect(ref)}"

    :telemetry.attach(
      id,
      [:ash_vault, :macaroon, :rejected],
      fn _, _, metadata, _ ->
        send(parent, {ref, metadata.reason})
      end,
      nil
    )

    try do
      result = fun.()
      {result, collect(ref, [])}
    after
      :telemetry.detach(id)
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, reason} -> collect(ref, [reason | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp advance(seconds),
    do: :persistent_term.put(@clock, DateTime.add(DateTime.utc_now(), seconds, :second))

  describe "generated surface" do
    test "a mint action, a verifying read and code interfaces" do
      assert %{type: :action, returns: Ash.Type.String} =
               Ash.Resource.Info.action(ApiClient, :mint_api)

      assert %{type: :read, get?: true} = Ash.Resource.Info.action(ApiClient, :api_by_token)
      assert function_exported?(ApiClient, :mint_api, 3)
      assert function_exported?(ApiClient, :api_by_token, 2)
    end

    test "a macaroon is not an encrypted field" do
      assert AshVault.Info.encrypted_fields(ApiClient) == []
      assert [:api, :nilrev, :strict] = Enum.map(AshVault.Info.macaroons(ApiClient), & &1.name)
      assert %{prefix: "avtest"} = AshVault.Info.macaroon(ApiClient, :api)
    end
  end

  describe "mint and verify" do
    test "round trip: the record comes back with the verified macaroon in metadata", %{
      client: client
    } do
      {:ok, token} = mint(client)
      assert String.starts_with?(token, "avtest_")

      assert {:ok, record} = verify(token)
      assert record.id == client.id
      assert record.__metadata__.using_macaroon? == true

      assert %Verified{macaroon: :api, scope: "acme", key_version: 1, id: id} =
               record.__metadata__.macaroon

      assert id == client.id
      assert %DateTime{} = record.__metadata__.macaroon.expires_at
    end

    test "the token's scope becomes the tenant; a request tenant must agree", %{client: client} do
      {:ok, token} = mint(client)
      assert {:ok, _} = verify(token, tenant: "acme")
      assert reason(verify(token, tenant: "other")) == {:invalid, :scope_mismatch}
    end

    test "a missing or revoked record cannot be minted for", %{client: client} do
      assert {:error, %Ash.Error.Invalid{}} =
               ApiClient.mint_api(Ash.UUID.generate(), %{}, tenant: "acme", authorize?: false)

      Ash.update!(client, %{revoked_at: DateTime.utc_now()}, tenant: "acme", authorize?: false)
      assert {:error, error} = mint(client)
      assert Exception.message(error) =~ "revoked"
    end

    test "an undeclared caveat or a bad value cannot be minted", %{client: client} do
      assert {:error, error} = mint(client, %{caveats: %{admin: true}})
      assert Exception.message(error) =~ "undeclared caveats"
      assert {:error, _} = mint(client, %{caveats: %{max_amount: "lots"}})
    end

    test "default_ttl and :ttl set expiry against the verifier's clock", %{client: client} do
      {:ok, token} = mint(client)
      {:ok, short} = mint(client, %{ttl: 10})

      advance(60)
      assert {:ok, _} = verify(token)
      assert reason(verify(short)) == {:invalid, :expired}

      advance(3_601)
      assert reason(verify(token)) == {:invalid, :expired}
    end

    test "a request context cannot move the clock", %{client: client} do
      {:ok, short} = mint(client, %{ttl: 10})
      advance(60)
      assert reason(verify(short, context: %{now: DateTime.utc_now()})) == {:invalid, :expired}
    end

    test "every caveat type is checked against the request", %{client: client} do
      {:ok, token} =
        mint(client, %{
          caveats: %{
            ip: "10.0.0.1",
            max_amount: 100,
            readonly: true,
            not_after: DateTime.add(DateTime.utc_now(), 60),
            paths: ["/a", "/b"],
            ports: [443]
          }
        })

      ok = %{remote_ip: "10.0.0.1", amount: 50, path: "/a", port: 443}
      assert {:ok, _} = verify(token, context: ok)

      for {key, value, caveat} <- [
            {:remote_ip, "10.0.0.2", :ip},
            {:amount, 101, :max_amount},
            {:write?, true, :readonly},
            {:path, "/c", :paths},
            {:port, 80, :ports}
          ] do
        assert reason(verify(token, context: Map.put(ok, key, value))) ==
                 {:invalid, {:caveat_failed, caveat}}
      end

      advance(120)
      {:ok, fresh} = mint(client, %{caveats: %{not_after: DateTime.add(DateTime.utc_now(), 60)}})
      assert reason(verify(fresh)) == {:invalid, {:caveat_failed, :not_after}}
    end

    test "a global macaroon needs no tenant and carries the global scope" do
      svc = Ash.create!(GlobalApiClient, %{name: "svc"})
      {:ok, token} = GlobalApiClient.mint_svc(svc.id)
      assert {:ok, record} = GlobalApiClient.svc_by_token(token)
      assert record.__metadata__.macaroon.scope == "global"
      assert record.__metadata__.macaroon.expires_at == nil
    end
  end

  describe "tampering" do
    setup %{client: client} do
      {:ok, token} = mint(client, %{caveats: %{ip: "10.0.0.1", max_amount: 10}})
      {:ok, env} = Envelope.decode(token)
      %{token: token, env: env}
    end

    defp reencode(env) do
      {:ok, token} = Envelope.encode(env)
      token
    end

    test "flipping any payload byte fails closed", %{token: token} do
      [prefix, encoded] = String.split(token, "_", parts: 2)
      {:ok, payload} = Base.url_decode64(encoded, padding: false)

      for index <- 0..(byte_size(payload) - 1) do
        <<head::binary-size(^index), byte, tail::binary>> = payload

        forged =
          prefix <>
            "_" <>
            Base.url_encode64(<<head::binary, Bitwise.bxor(byte, 1), tail::binary>>,
              padding: false
            )

        assert {:invalid, _} = reason(verify(forged, context: %{remote_ip: "10.0.0.1"}))
      end
    end

    test "reordering, truncating or appending without the signature fails", %{env: env} do
      [a, b, c] = env.caveats
      assert reason(verify(reencode(%{env | caveats: [a, c, b]}))) == {:invalid, :bad_signature}
      assert reason(verify(reencode(%{env | caveats: [a, b]}))) == {:invalid, :bad_signature}

      {:ok, extra} = AshVault.Macaroon.CaveatCodec.encode("ip", :string, "10.0.0.9")

      assert reason(verify(reencode(%{env | caveats: env.caveats ++ [extra]}))) ==
               {:invalid, :bad_signature}
    end

    test "re-pointing at another record fails", %{env: env} do
      other =
        Ash.create!(ApiClient, %{name: "other", org_id: "acme"},
          tenant: "acme",
          authorize?: false
        )

      assert reason(verify(reencode(%{env | id: other.id}))) == {:invalid, :bad_signature}
    end

    test "every pre-signature failure looks the same to the caller; telemetry has the detail",
         %{env: env, client: client} do
      {:ok, erased_token} =
        ApiClient.mint_api(
          Ash.create!(ApiClient, %{name: "gone", org_id: "gone"},
            tenant: "gone",
            authorize?: false
          ).id,
          %{},
          tenant: "gone",
          authorize?: false
        )

      {:ok, erased} = Envelope.decode(erased_token)
      :ok = AshVault.destroy_keys!(AshVault.Test.Vault, "gone")
      _ = client

      cases = [
        {"avtest_garbage", :malformed},
        {reencode(%{env | prefix: "avsvc"}), :wrong_prefix},
        {reencode(%{env | scope: "nosuchtenant"}), :unknown_key_version},
        {reencode(%{env | key_version: 7}), :unknown_key_version},
        {reencode(%{erased | id: env.id}), :scope_destroyed},
        {reencode(%{env | sig: <<0::256>>}), :bad_signature}
      ]

      for {token, internal} <- cases do
        {result, reasons} = capture_rejections(fn -> verify(token) end)
        assert reason(result) == {:invalid, :bad_signature}
        assert reasons == [internal]
      end

      assert Memory.get_key("nosuchtenant", 1, :mac) == {:error, :not_found}
    end

    test "a request tenant that disagrees is checked only after the signature", %{
      env: env,
      token: token
    } do
      assert reason(verify(token, tenant: "other")) == {:invalid, :scope_mismatch}

      assert reason(verify(reencode(%{env | sig: <<0::256>>}), tenant: "other")) ==
               {:invalid, :bad_signature}
    end

    test "a forged maximum-length scope is invalid, not an outage", %{env: env} do
      long = String.duplicate("a", 180)
      assert reason(verify(reencode(%{env | scope: long}))) == {:invalid, :bad_signature}
      assert Envelope.encode(%{env | scope: String.duplicate("a", 181)}) == {:error, :malformed}
    end

    test "the root signature uses a reserved vault field, so mac! on a field is no oracle",
         %{env: env} do
      ctx = fn field ->
        %AshVault.Context{
          resource: ApiClient,
          field: field,
          ash_context: %{tenant: "acme", actor: nil, source_context: %{}}
        }
      end

      data = AshVault.Macaroon.Chain.root_data(env)
      root = AshVault.Test.Vault.mac_at!(data, env.key_version, ctx.(:"macaroon:api"))
      assert AshVault.Macaroon.Chain.extend(root, env.caveats) == env.sig

      {1, oracle} = AshVault.Test.Vault.mac!(data, ctx.(:api))
      forged = %{env | sig: AshVault.Macaroon.Chain.extend(oracle, env.caveats)}
      assert reason(verify(reencode(forged))) == {:invalid, :bad_signature}
    end

    test "errors carry no token material", %{token: token, env: env} do
      {:error, error} = verify(token, context: %{remote_ip: "1.1.1.1"})
      message = Exception.message(error)
      refute message =~ env.id
      refute message =~ String.slice(token, 7, 20)
    end
  end

  describe "attenuation" do
    test "an attenuated token verifies and carries the narrower caveats", %{client: client} do
      {:ok, token} = mint(client)
      {:ok, narrower} = Macaroon.attenuate(token, ip: "10.0.0.1")

      assert {:ok, _} = verify(narrower, context: %{remote_ip: "10.0.0.1"})

      assert reason(verify(narrower, context: %{remote_ip: "10.0.0.2"})) ==
               {:invalid, {:caveat_failed, :ip}}

      assert {:ok, _} = verify(token, context: %{remote_ip: "10.0.0.2"})
    end

    test "undeclared or mistyped caveats are refused", %{client: client} do
      {:ok, token} = mint(client)
      {:ok, unknown} = Macaroon.attenuate(token, admin: true)
      {:ok, mistyped} = Macaroon.attenuate(token, ip: 42)
      {:ok, expiry} = Macaroon.attenuate(token, expires_at: "never")

      assert reason(verify(unknown)) == {:invalid, :unknown_caveat}
      assert reason(verify(mistyped)) == {:invalid, :caveat_type}
      assert reason(verify(expiry)) == {:invalid, :caveat_type}
    end

    test "a shorter expiry can be added, a longer one cannot extend", %{client: client} do
      {:ok, token} = mint(client, %{ttl: 100})
      {:ok, shorter} = Macaroon.attenuate(token, expires_at: DateTime.add(DateTime.utc_now(), 10))

      {:ok, longer} =
        Macaroon.attenuate(token, expires_at: DateTime.add(DateTime.utc_now(), 10_000))

      advance(50)
      assert reason(verify(shorter)) == {:invalid, :expired}
      assert {:ok, _} = verify(longer)
      advance(200)
      assert reason(verify(longer)) == {:invalid, :expired}
    end

    defp caveat_gen do
      StreamData.one_of([
        StreamData.map(StreamData.member_of(~w(10.0.0.1 10.0.0.2)), &{:ip, &1}),
        StreamData.map(StreamData.integer(0..200), &{:max_amount, &1}),
        StreamData.map(
          StreamData.list_of(StreamData.member_of(~w(/a /b /c)), min_length: 1, max_length: 3),
          &{:paths, &1}
        ),
        StreamData.map(
          StreamData.list_of(StreamData.member_of([80, 443]), min_length: 1, max_length: 2),
          &{:ports, &1}
        )
      ])
    end

    defp request_gen do
      gen all(
            ip <- StreamData.member_of(~w(10.0.0.1 10.0.0.2)),
            amount <- StreamData.integer(0..200),
            path <- StreamData.member_of(~w(/a /b /c)),
            port <- StreamData.member_of([80, 443])
          ) do
        %{remote_ip: ip, amount: amount, path: path, port: port}
      end
    end

    property "attenuation only narrows: whatever the narrower token admits, the wider one admits",
             %{client: client} do
      {:ok, root} = mint(client)

      check all(
              first <- StreamData.list_of(caveat_gen(), max_length: 3),
              more <- StreamData.list_of(caveat_gen(), min_length: 1, max_length: 3),
              request <- request_gen(),
              max_runs: 60
            ) do
        {:ok, wider} = Macaroon.attenuate(root, first)
        {:ok, narrower} = Macaroon.attenuate(wider, more)

        if match?({:ok, _}, verify(narrower, context: request)) do
          assert {:ok, _} = verify(wider, context: request)
          assert {:ok, _} = verify(root, context: request)
        end
      end
    end
  end

  describe "revocation" do
    test "level 1: the record's revoked_when", %{client: client} do
      {:ok, token} = mint(client)
      Ash.update!(client, %{revoked_at: DateTime.utc_now()}, tenant: "acme", authorize?: false)

      assert reason(verify(token)) == {:revoked, :record}
      assert sign_in(token) == {:ok, []}
    end

    test "level 1: a deleted record is not_found, not revoked", %{client: client} do
      {:ok, token} = mint(client)
      Ash.destroy!(client, tenant: "acme", authorize?: false)
      assert reason(verify(token)) == {:invalid, :not_found}
    end

    test "level 2: rotating the :mac key retires versions outside accepted_key_versions", %{
      client: client
    } do
      {:ok, v1} = mint(client)
      {:ok, 2} = AshVault.rotate_key!(AshVault.Test.Vault, "acme", nil, purpose: :mac)
      {:ok, v2} = mint(client)

      assert {:ok, _} = verify(v1)
      assert {:ok, _} = verify(v2)

      {:ok, 3} = AshVault.rotate_key!(AshVault.Test.Vault, "acme", nil, purpose: :mac)
      assert reason(verify(v1)) == {:revoked, :key_retired}
      assert {:ok, _} = verify(v2)
      assert sign_in(v1) == {:ok, []}
    end

    test "level 2: only the :mac keyring matters, and only in its own scope", %{client: client} do
      {:ok, token} = mint(client)
      {:ok, _} = AshVault.rotate_key!(AshVault.Test.Vault, "acme")
      {:ok, _} = AshVault.rotate_key!(AshVault.Test.Vault, "acme")
      {:ok, _} = AshVault.rotate_key!(AshVault.Test.Vault, "other", nil, purpose: :mac)
      {:ok, _} = AshVault.rotate_key!(AshVault.Test.Vault, "other", nil, purpose: :mac)

      assert {:ok, _} = verify(token)
    end

    test "level 2: accepted_key_versions :all never retires" do
      svc = Ash.create!(GlobalApiClient, %{name: "svc"})
      {:ok, token} = GlobalApiClient.mint_svc(svc.id)

      for _ <- 1..3,
          do:
            {:ok, _} =
              AshVault.rotate_key!(AshVault.Test.GlobalVault, "global", nil, purpose: :mac)

      assert {:ok, _} = GlobalApiClient.svc_by_token(token)
    end

    test "level 3: destroying the scope revokes every token it issued", %{client: client} do
      {:ok, token} = mint(client)
      :ok = AshVault.destroy_keys!(AshVault.Test.Vault, "acme")

      {result, reasons} = capture_rejections(fn -> verify(token) end)
      assert reason(result) == {:invalid, :bad_signature}
      assert reasons == [:scope_destroyed]
      assert sign_in(token) == {:ok, []}
      assert {:error, _} = mint(client)
    end
  end

  describe "revoked_when that evaluates to nil" do
    test "fails closed: nil is not false", %{client: client} do
      assert {:error, error} =
               ApiClient.mint_nilrev(client.id, %{}, tenant: "acme", authorize?: false)

      assert Exception.message(error) =~ "revoked"

      client =
        Ash.update!(client, %{revoked_at: DateTime.add(DateTime.utc_now(), 3600)},
          tenant: "acme",
          authorize?: false
        )

      {:ok, token} = ApiClient.mint_nilrev(client.id, %{}, tenant: "acme", authorize?: false)
      assert {:ok, _} = ApiClient.nilrev_by_token(token)

      Ash.update!(client, %{revoked_at: nil}, tenant: "acme", authorize?: false)
      assert reason(ApiClient.nilrev_by_token(token)) == {:revoked, :record}
    end
  end

  describe "require_authorize_enforcement?" do
    test "refuses tokens with authorize caveats unless enforcement is asserted", %{client: client} do
      {:ok, plain} = ApiClient.mint_strict(client.id, %{}, tenant: "acme", authorize?: false)

      {:ok, scoped} =
        ApiClient.mint_strict(client.id, %{caveats: %{actions: ["read"]}},
          tenant: "acme",
          authorize?: false
        )

      assert {:ok, _} = ApiClient.strict_by_token(plain)
      assert reason(ApiClient.strict_by_token(scoped)) == {:invalid, :unenforced_caveats}

      assert {:ok, _} =
               ApiClient.strict_by_token(scoped,
                 context: %{ash_vault: %{authorize_caveats_enforced?: true}}
               )
    end
  end

  describe "outages" do
    setup do
      flaky = Ash.create!(FlakyApiClient, %{org_id: "acme"}, tenant: "acme")
      {:ok, token} = FlakyApiClient.mint_flaky(flaky.id, %{}, tenant: "acme")
      FlakyMacProvider.outage!()
      %{token: token}
    end

    test "ProviderUnavailable is returned as itself, never as an invalid token", %{token: token} do
      assert {:error, %Ash.Error.Invalid{errors: [%ProviderUnavailable{}]}} =
               FlakyApiClient.flaky_by_token(token)
    end

    test "sign-in reports an outage as an error, never as no record", %{token: token} do
      assert {:error, %Ash.Error.Invalid{errors: [%ProviderUnavailable{}]}} =
               FlakyApiClient
               |> Ash.Query.for_read(:sign_in, %{token: token})
               |> Ash.read()
    end

    test "a current-version lookup that says not_found is invalid, not a crash", %{token: token} do
      FlakyMacProvider.lose_current!()

      assert {:error,
              %Ash.Error.Invalid{errors: [%InvalidMacaroon{reason: :unknown_key_version}]}} =
               FlakyApiClient.flaky_by_token(token)
    end

    test "after recovery the same token verifies", %{token: token} do
      FlakyMacProvider.recover!()
      assert {:ok, _} = FlakyApiClient.flaky_by_token(token)
    end
  end

  describe "sign-in preparation" do
    test "follows the AshAuthentication shape: [record] with metadata, or []", %{client: client} do
      {:ok, token} = mint(client)
      assert {:ok, [record]} = sign_in(token)
      assert record.__metadata__.using_macaroon?
      assert sign_in("avtest_garbage") == {:ok, []}
      assert sign_in("not a token") == {:ok, []}
    end
  end

  describe "MacaroonAllows" do
    setup %{client: client} do
      widget = Ash.create!(Widget, %{name: "w"}, authorize?: false)
      %{widget: widget, client: client}
    end

    defp actor(client, caveats) do
      {:ok, token} = mint(client, %{caveats: caveats})
      {:ok, actor} = verify(token)
      actor
    end

    test "authorize-phase caveats limit what a macaroon actor may do", %{client: client} do
      actor = actor(client, %{actions: ["read"]})
      assert [{:actions, ["read"]}] = actor.__metadata__.macaroon.authorize_caveats

      assert {:ok, [_]} = Ash.read(Widget, actor: actor)
      assert {:error, %Ash.Error.Forbidden{}} = Ash.create(Widget, %{name: "x"}, actor: actor)
    end

    test "attenuating the actions caveat narrows authorization", %{client: client} do
      {:ok, token} = mint(client, %{caveats: %{actions: ["read", "create"]}})
      {:ok, narrower} = Macaroon.attenuate(token, actions: ["read"])

      {:ok, wide} = verify(token)
      {:ok, narrow} = verify(narrower)

      assert {:ok, _} = Ash.create(Widget, %{name: "x"}, actor: wide)
      assert {:error, %Ash.Error.Forbidden{}} = Ash.create(Widget, %{name: "y"}, actor: narrow)
    end

    test "a macaroon actor without authorize-phase caveats is not restricted", %{client: client} do
      assert {:ok, _} = Ash.create(Widget, %{name: "x"}, actor: actor(client, %{}))
    end

    test "an actor with no macaroon gets :when_absent" do
      assert {:ok, _} = Ash.create(Widget, %{name: "x"}, actor: %{id: 1})

      refute AshVault.Checks.MacaroonAllows.match?(%{id: 1}, %{}, macaroon: :api)
    end
  end
end
