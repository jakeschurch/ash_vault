defmodule AshVault.VaultMacTest do
  # Not async: vaults talk to the default-named `AshVault.KeyProviders.Memory`.
  use ExUnit.Case, async: false

  alias AshVault.Context
  alias AshVault.Errors.InvalidMac
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.MissingScope
  alias AshVault.Errors.OpaqueKeyUnsupported
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Errors.PurposeUnsupported
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Support.Resources
  alias AshVault.Test.Support.TenantVault
  alias AshVault.Test.Support.UnavailableVault

  defmodule CachedVault do
    @moduledoc false
    use AshVault.Vault, key_provider: AshVault.Test.Support.VaultMacTestCachedMemory
  end

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp ctx(opts \\ []) do
    %Context{
      resource: Keyword.get(opts, :resource, Resources.User),
      field: Keyword.get(opts, :field, :token),
      ash_context: %{tenant: Keyword.get(opts, :tenant, "acme"), actor: nil, source_context: %{}}
    }
  end

  describe "configuration" do
    test "the default MAC is HmacSha256, and OpenBaoTransit over the transit provider" do
      assert TenantVault.__ash_vault__(:mac) == AshVault.Macs.HmacSha256

      assert AshVault.Test.Support.TransitVault.__ash_vault__(:mac) ==
               AshVault.Macs.OpenBaoTransit
    end

    test "an explicit mac: over a provider with no :mac keyring does not compile" do
      unique = System.unique_integer([:positive])

      assert_raise ArgumentError, ~r/cannot serve :mac keys/, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.NoMacVault#{unique} do
          use AshVault.Vault,
            key_provider: AshVault.Test.Support.UnavailableProvider,
            mac: AshVault.Macs.HmacSha256
        end
        """)
      end
    end

    # Existing vaults over providers that predate purposes must keep compiling.
    test "without mac:, a provider with no :mac keyring still compiles" do
      assert UnavailableVault.__ash_vault__(:mac) == AshVault.Macs.HmacSha256
    end

    test "a MAC that cannot use the provider's keys does not compile" do
      unique = System.unique_integer([:positive])

      assert_raise ArgumentError, ~r/computes MACs inside OpenBao/, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.TransitMacOverMemory#{unique} do
          use AshVault.Vault,
            key_provider: AshVault.KeyProviders.Memory,
            mac: AshVault.Macs.OpenBaoTransit
        end
        """)
      end

      assert_raise ArgumentError, ~r/never exports key\s+material/, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.LocalMacOverTransit#{unique} do
          use AshVault.Vault,
            key_provider: AshVault.KeyProviders.OpenBaoTransit,
            cipher: AshVault.Ciphers.OpenBaoTransit,
            mac: AshVault.Macs.HmacSha256
        end
        """)
      end
    end
  end

  describe "mac!/2 and verify_mac!/4" do
    test "roundtrip" do
      assert {1, tag} = TenantVault.mac!("payload", ctx())
      assert is_binary(tag) and byte_size(tag) == 32
      assert :ok = TenantVault.verify_mac!("payload", 1, tag, ctx())
    end

    test "the :mac keyring is minted on first use and is not the data key" do
      {1, tag} = TenantVault.mac!("payload", ctx())

      {:ok, %{key: data_key}} = Memory.current_key("acme")
      {:ok, %{version: 1, key: mac_key}} = Memory.current_key("acme", :mac)

      refute data_key == mac_key
      assert tag == AshVault.Macs.HmacSha256.hmac(mac_key, AshVault.Mac.frame("payload", aad()))
      refute tag == AshVault.Macs.HmacSha256.hmac(data_key, AshVault.Mac.frame("payload", aad()))
    end

    test "tampered data or tag is InvalidMac" do
      {version, tag} = TenantVault.mac!("payload", ctx())
      <<first, rest::binary>> = tag

      assert_raise InvalidMac, fn -> TenantVault.verify_mac!("payloaD", version, tag, ctx()) end

      assert_raise InvalidMac, fn ->
        TenantVault.verify_mac!(
          "payload",
          version,
          <<Bitwise.bxor(first, 1), rest::binary>>,
          ctx()
        )
      end

      for bad <- [binary_part(tag, 0, 16), "", nil, 7, {:tag}] do
        assert_raise InvalidMac, fn -> TenantVault.verify_mac!("payload", version, bad, ctx()) end
      end
    end

    test "a tag does not verify under another scope, resource or field" do
      {version, tag} = TenantVault.mac!("payload", ctx())
      {_, _} = TenantVault.mac!("payload", ctx(tenant: "globex"))

      assert_raise InvalidMac, fn ->
        TenantVault.verify_mac!("payload", version, tag, ctx(tenant: "globex"))
      end

      assert_raise InvalidMac, fn ->
        TenantVault.verify_mac!("payload", version, tag, ctx(resource: Resources.Invoice))
      end

      assert_raise InvalidMac, fn ->
        TenantVault.verify_mac!("payload", version, tag, ctx(field: :other))
      end
    end

    test "an unknown or non-integer key version is KeyNotFound, not InvalidMac" do
      {_version, tag} = TenantVault.mac!("payload", ctx())

      for version <- [2, 99, 0, -1, "1", nil, :one] do
        assert_raise KeyNotFound, fn ->
          TenantVault.verify_mac!("payload", version, tag, ctx())
        end
      end
    end

    test "a real but wrong key version is InvalidMac" do
      {1, tag} = TenantVault.mac!("payload", ctx())
      {:ok, 2} = TenantVault.rotate!("acme", purpose: :mac)

      assert_raise InvalidMac, fn -> TenantVault.verify_mac!("payload", 2, tag, ctx()) end
    end

    test "a missing scope is MissingScope, naming the MAC operation" do
      error =
        assert_raise MissingScope, fn -> TenantVault.mac!("payload", ctx(tenant: nil)) end

      assert error.operation == :mac

      error =
        assert_raise MissingScope, fn ->
          TenantVault.verify_mac!("payload", 1, <<0::256>>, ctx(tenant: nil))
        end

      assert error.operation == :verify_mac
    end
  end

  describe "rotate!(scope, purpose: :mac)" do
    test "mints a new :mac version; old tags keep verifying; :data does not move" do
      {:ok, %{version: 1, key: data_key}} = Memory.current_key("acme")
      {1, old_tag} = TenantVault.mac!("payload", ctx())

      assert {:ok, 2} = TenantVault.rotate!("acme", purpose: :mac)
      assert {2, new_tag} = TenantVault.mac!("payload", ctx())
      refute old_tag == new_tag

      assert :ok = TenantVault.verify_mac!("payload", 1, old_tag, ctx())
      assert :ok = TenantVault.verify_mac!("payload", 2, new_tag, ctx())

      assert {:ok, %{version: 1, key: ^data_key}} = Memory.current_key("acme")
    end

    test "rotating :data does not move :mac" do
      {:ok, %{version: 1}} = Memory.current_key("acme")
      {1, tag} = TenantVault.mac!("payload", ctx())

      assert {:ok, 2} = TenantVault.rotate!("acme")
      assert {:ok, 3} = TenantVault.rotate!("acme", purpose: :data)

      assert {1, ^tag} = TenantVault.mac!("payload", ctx())
    end

    test "an unknown purpose or option is refused, never a silent data rotation" do
      assert_raise ArgumentError, ~r/:data or :mac/, fn ->
        TenantVault.rotate!("acme", purpose: :lookup)
      end

      assert_raise ArgumentError, ~r/accepts only `:purpose`/, fn ->
        TenantVault.rotate!("acme", purpos: :mac)
      end

      assert {:error, :not_found} = Memory.get_key("acme", 1)
    end

    test "AshVault.rotate_key!/4 rotates :mac and says so in telemetry" do
      ref = attach([[:ash_vault, :key, :rotate, :stop]])

      assert {:ok, 1} = AshVault.rotate_key!(TenantVault, "acme", nil, purpose: :mac)
      assert {:ok, %{version: 1}} = Memory.current_key("acme", :mac)
      assert {:error, :not_found} = Memory.get_key("acme", 1)

      assert_receive {^ref, [:ash_vault, :key, :rotate, :stop], _, metadata}
      assert metadata.purpose == :mac
      assert metadata.key_version == 1

      assert {:ok, 1} = AshVault.rotate_key!(TenantVault, "acme")
      assert_receive {^ref, [:ash_vault, :key, :rotate, :stop], _, %{purpose: :data}}
    end
  end

  describe "erasure revokes" do
    test "destroy! makes every tag KeyDestroyed, and mac! refuses to mint" do
      {version, tag} = TenantVault.mac!("payload", ctx())
      :ok = TenantVault.destroy!("acme")

      error =
        assert_raise KeyDestroyed, fn ->
          TenantVault.verify_mac!("payload", version, tag, ctx())
        end

      assert error.key_version == version

      assert_raise KeyDestroyed, fn -> TenantVault.mac!("payload", ctx()) end
      assert_raise KeyDestroyed, fn -> TenantVault.rotate!("acme", purpose: :mac) end

      # Still destroyed: never re-minted at v1 by the failed mac! above.
      assert_raise KeyDestroyed, fn -> TenantVault.verify_mac!("payload", 1, tag, ctx()) end
    end

    test "destroying one scope leaves another's tags valid" do
      {version, tag} = TenantVault.mac!("payload", ctx(tenant: "globex"))
      :ok = TenantVault.destroy!("acme")

      assert :ok = TenantVault.verify_mac!("payload", version, tag, ctx(tenant: "globex"))
    end
  end

  describe "outages are not verdicts" do
    test "a provider outage is ProviderUnavailable, never InvalidMac or KeyDestroyed" do
      {version, tag} = TenantVault.mac!("payload", ctx())
      stop_supervised!(Memory)

      assert_raise ProviderUnavailable, fn ->
        TenantVault.verify_mac!("payload", version, tag, ctx())
      end

      assert_raise ProviderUnavailable, fn -> TenantVault.mac!("payload", ctx()) end
    end

    test "a provider without a :mac keyring is PurposeUnsupported, not an outage" do
      error = assert_raise PurposeUnsupported, fn -> UnavailableVault.mac!("payload", ctx()) end
      assert error.purpose == :mac

      assert_raise PurposeUnsupported, fn ->
        UnavailableVault.verify_mac!("payload", 1, <<0::256>>, ctx())
      end

      assert_raise PurposeUnsupported, fn -> UnavailableVault.rotate!("acme", purpose: :mac) end
    end

    test "a MAC that cannot use the key is OpaqueKeyUnsupported, naming the MAC" do
      opts = %{
        key_provider: AshVault.Test.Support.VaultMacTestOpaqueProvider,
        cipher: AshVault.Ciphers.AES.GCM,
        envelope: AshVault.Envelope.V1,
        scope: AshVault.Scopes.AshTenant,
        rotation_policy: AshVault.RotationPolicies.Manual,
        mac: AshVault.Macs.HmacSha256
      }

      error =
        assert_raise OpaqueKeyUnsupported, fn ->
          AshVault.Vault.Runtime.mac!("payload", ctx(), opts)
        end

      assert error.cipher == AshVault.Macs.HmacSha256
      assert Exception.message(error) =~ "computing a MAC for"
    end
  end

  describe "the tag is a bearer credential" do
    test "no error, and no telemetry event, carries the tag or the data" do
      ref = attach([[:ash_vault, :mac, :sign, :stop], [:ash_vault, :mac, :verify, :stop]])

      {version, tag} = TenantVault.mac!("s3cret-payload", ctx())
      <<first, rest::binary>> = tag
      forged = <<Bitwise.bxor(first, 1), rest::binary>>

      error =
        assert_raise InvalidMac, fn ->
          TenantVault.verify_mac!("s3cret-payload", version, forged, ctx())
        end

      for rendered <- [inspect(error, limit: :infinity), Exception.message(error)] do
        refute rendered =~ "s3cret-payload"
        refute rendered =~ Base.encode16(forged)
        refute rendered =~ inspect(forged, limit: :infinity)
      end

      assert_receive {^ref, [:ash_vault, :mac, :sign, :stop], _, sign}
      assert sign.result == :ok
      assert sign.key_version == version
      assert sign.vault == TenantVault
      assert sign.resource == Resources.User
      assert sign.field == :token

      # A failed verification is a `:stop` with `result: :error`, not an `:exception`:
      # compliance handlers are told to watch `:stop`.
      assert_receive {^ref, [:ash_vault, :mac, :verify, :stop], _, verify}
      assert verify.result == :error
      assert verify.error == InvalidMac
      assert verify.key_version == version

      for metadata <- [sign, verify] do
        rendered = inspect(metadata, limit: :infinity, printable_limit: :infinity)
        refute rendered =~ "s3cret-payload"
        refute rendered =~ inspect(tag, limit: :infinity)
        refute rendered =~ inspect(forged, limit: :infinity)
        refute Map.has_key?(metadata, :scope)
      end
    end
  end

  describe "through AshVault.KeyProviders.Cached" do
    setup do
      start_supervised!(AshVault.Test.Support.VaultMacTestCachedMemory)
      :ok
    end

    test ":mac passes through, and erasure is honoured" do
      {version, tag} = CachedVault.mac!("payload", ctx())
      assert :ok = CachedVault.verify_mac!("payload", version, tag, ctx())
      assert {:ok, 2} = CachedVault.rotate!("acme", purpose: :mac)
      assert :ok = CachedVault.verify_mac!("payload", version, tag, ctx())

      :ok = CachedVault.destroy!("acme")

      assert_raise KeyDestroyed, fn -> CachedVault.verify_mac!("payload", version, tag, ctx()) end
      assert_raise KeyDestroyed, fn -> CachedVault.mac!("payload", ctx()) end
    end

    test "the wrapper reports the wrapped provider's purposes" do
      assert AshVault.Test.Support.VaultMacTestCachedMemory.purposes() == [:data, :mac]

      assert AshVault.KeyProvider.supports_purpose?(
               AshVault.Test.Support.VaultMacTestCachedMemory,
               :mac
             )

      refute AshVault.KeyProvider.supports_purpose?(
               AshVault.Test.Support.CachedNoLookupProvider,
               :mac
             )
    end
  end

  defp aad, do: AshVault.Vault.Runtime.build_aad("acme", ctx())

  defp attach(events) do
    ref = make_ref()
    test = self()
    id = {__MODULE__, ref}

    :telemetry.attach_many(
      id,
      events,
      fn event, measurements, metadata, _config ->
        send(test, {ref, event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(id) end)
    ref
  end
end
