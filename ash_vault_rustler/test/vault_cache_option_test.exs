defmodule AshVaultRustler.VaultCacheOptionTest do
  @moduledoc """
  The vault's `:cache` option is sugar. These tests assert the desugaring is real — that
  `cache: true` resolves to the same provider chain the explicit wrapper produces, and
  that leaving it off produces no wrapper at all.

  The default matters more than the sugar: a cache weakens crypto-erasure from immediate
  to eventual-within-a-TTL for any erasure that does not go through the vault, so opting
  in has to be deliberate.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory
  alias AshVaultRustler.Test.ObservableProvider

  defmodule PlainVault do
    @moduledoc false
    use AshVault.Vault, key_provider: AshVaultRustler.Test.ObservableProvider
  end

  defmodule ExplicitFalseVault do
    @moduledoc false
    use AshVault.Vault, key_provider: AshVaultRustler.Test.ObservableProvider, cache: false
  end

  defmodule SugarVault do
    @moduledoc false
    use AshVault.Vault, key_provider: AshVaultRustler.Test.ObservableProvider, cache: true
  end

  defmodule WrapperVault do
    @moduledoc false
    use AshVault.Vault,
      key_provider:
        {AshVault.KeyProviders.Cached, provider: AshVaultRustler.Test.ObservableProvider}
  end

  defmodule TunedVault do
    @moduledoc false
    use AshVault.Vault,
      key_provider: AshVaultRustler.Test.ObservableProvider,
      cipher: AshVaultRustler.Cipher,
      cache: [
        ttl: 5_000,
        max_entries: 64,
        max_bytes: 4_096,
        backend: AshVaultRustler.KeyCache
      ]
  end

  describe "the default" do
    test "no :cache option means no wrapper" do
      assert PlainVault.__ash_vault__(:key_provider) == ObservableProvider
      refute Code.ensure_loaded?(PlainVault.CachedKeyProvider)
    end

    test "cache: false means no wrapper" do
      assert ExplicitFalseVault.__ash_vault__(:key_provider) == ObservableProvider
      refute Code.ensure_loaded?(ExplicitFalseVault.CachedKeyProvider)
    end
  end

  describe "the desugaring is real" do
    test "cache: true produces a Cached wrapper over the configured provider" do
      wrapper = SugarVault.__ash_vault__(:key_provider)

      assert wrapper == SugarVault.CachedKeyProvider
      assert wrapper.__ash_vault_cached__().provider == ObservableProvider
    end

    test "cache: true and the explicit wrapper resolve to the same configuration" do
      sugar = SugarVault.__ash_vault__(:key_provider).__ash_vault_cached__()
      explicit = WrapperVault.__ash_vault__(:key_provider).__ash_vault_cached__()

      # The cache *name* is the generated module, which necessarily differs per vault.
      # Everything that describes behaviour must match exactly.
      assert Map.delete(sugar, :cache_name) == Map.delete(explicit, :cache_name)
      assert sugar.provider == explicit.provider
      assert sugar.ttl == AshVault.KeyProviders.Cached.default_ttl()
    end

    test "cache: true defaults to the pure-Elixir backend, never requiring the NIF" do
      assert SugarVault.__ash_vault__(:key_provider).__ash_vault_cached__().backend ==
               AshVault.KeyCaches.ETS
    end

    test "a keyword list is passed through, and :backend selects the implementation" do
      opts = TunedVault.__ash_vault__(:key_provider).__ash_vault_cached__()

      assert opts.provider == ObservableProvider
      assert opts.ttl == 5_000
      assert opts.historical_ttl == 5_000
      assert opts.max_entries == 64
      assert opts.max_bytes == 4_096
      assert opts.backend == AshVaultRustler.KeyCache
    end

    test "the generated wrapper is a working provider end to end" do
      start_supervised!(ObservableProvider)
      start_supervised!(TunedVault.CachedKeyProvider)

      scope = "acme_#{System.unique_integer([:positive])}"

      ctx = %AshVault.Context{
        resource: MyApp.User,
        field: :ssn,
        ash_context: %{tenant: scope}
      }

      blob = TunedVault.encrypt!("123-45-6789", ctx)
      assert TunedVault.decrypt!(blob, ctx) == "123-45-6789"

      # And the cache was actually used: the second operation asked the provider nothing.
      ObservableProvider.reset_calls()
      assert TunedVault.decrypt!(blob, ctx) == "123-45-6789"
      assert ObservableProvider.calls().get_key == 0
    end
  end

  describe "bad shapes are refused with a message that says what to do" do
    test "a non-boolean, non-keyword :cache" do
      assert_raise ArgumentError, ~r/must be `true`, `false`, or a keyword/, fn ->
        AshVault.Vault.resolve_cache!(SomeVault, ObservableProvider, cache: "yes")
      end
    end

    test "a :provider inside :cache, which belongs in :key_provider" do
      assert_raise ArgumentError, ~r/must not carry a `:provider`/, fn ->
        AshVault.Vault.resolve_cache!(SomeVault, ObservableProvider, cache: [provider: Memory])
      end
    end

    test "both an explicit wrapper and a :cache option" do
      assert_raise ArgumentError, ~r/They configure the same thing/, fn ->
        AshVault.Vault.resolve_cache!(
          SomeVault,
          {AshVault.KeyProviders.Cached, provider: ObservableProvider},
          cache: true
        )
      end
    end

    test "a tuple provider that is not Cached" do
      assert_raise ArgumentError, ~r/only supported for/, fn ->
        AshVault.Vault.resolve_cache!(SomeVault, {Memory, []}, [])
      end
    end

    test "an explicit wrapper with no :provider" do
      assert_raise ArgumentError, ~r/requires a `:provider` to wrap/, fn ->
        AshVault.Vault.resolve_cache!(SomeVault, {AshVault.KeyProviders.Cached, []}, [])
      end
    end
  end

  describe "caching Memory" do
    test "warns and does not wrap, producing the same chain as cache: false" do
      warning =
        ExUnit.CaptureIO.capture_io(:stderr, fn ->
          assert {Memory, nil} = AshVault.Vault.resolve_cache!(MemVault, Memory, cache: true)
        end)

      assert warning =~ "Memory is already an in-memory map"
      assert warning =~ "has not been enabled"
    end

    test "the resolved chain is identical to cache: false" do
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        assert AshVault.Vault.resolve_cache!(MemVault, Memory, cache: true) ==
                 AshVault.Vault.resolve_cache!(MemVault, Memory, cache: false)
      end)
    end
  end
end
