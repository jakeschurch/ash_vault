defmodule AshVaultRustler.CachedProviderTest do
  @moduledoc """
  The rules `AshVault.KeyProviders.Cached` exists to keep, asserted against a provider
  that counts its calls and can be taken offline.

  Every test here corresponds to a sentence in the module's own documentation. If one of
  them fails, the documentation has become a lie, which in this project's history is how
  four fail-open tombstone reads shipped.
  """

  use ExUnit.Case, async: false

  alias AshVaultRustler.Test.ObservableProvider

  defmodule Cached do
    @moduledoc false
    use AshVault.KeyProviders.Cached,
      provider: AshVaultRustler.Test.ObservableProvider,
      backend: AshVaultRustler.KeyCache,
      ttl: 60_000,
      historical_ttl: 60_000
  end

  defmodule ShortTTL do
    @moduledoc false
    use AshVault.KeyProviders.Cached,
      provider: AshVaultRustler.Test.ObservableProvider,
      backend: AshVaultRustler.KeyCache,
      ttl: 40,
      historical_ttl: 40
  end

  setup context do
    start_supervised!(ObservableProvider)
    provider = context[:cached] || Cached
    start_supervised!(provider)

    %{provider: provider, scope: "scope_#{System.unique_integer([:positive])}"}
  end

  describe "it actually caches" do
    test "repeated current_key calls hit the provider once", %{provider: provider, scope: scope} do
      ObservableProvider.reset_calls()

      assert {:ok, first} = provider.current_key(scope)
      for _ <- 1..20, do: assert({:ok, ^first} = provider.current_key(scope))

      assert ObservableProvider.calls().current_key == 1
    end

    test "a current_key fetch also seeds the version slot", %{provider: provider, scope: scope} do
      assert {:ok, %{version: version, key: key}} = provider.current_key(scope)

      ObservableProvider.reset_calls()

      assert {:ok, ^key} = provider.get_key(scope, version)
      assert ObservableProvider.calls().get_key == 0
    end

    test "N concurrent readers produce one provider fetch, not N",
         %{provider: provider, scope: scope} do
      # Warm the entry first: the interesting property is that a *populated* cache
      # absorbs concurrency. A thundering herd on a cold cache legitimately produces more
      # than one fetch, and this module does not claim otherwise — there is no in-flight
      # request coalescing here, and pretending there is would be the overclaim.
      assert {:ok, _} = provider.current_key(scope)
      ObservableProvider.reset_calls()

      1..50
      |> Enum.map(fn _ -> Task.async(fn -> provider.current_key(scope) end) end)
      |> Enum.each(fn task -> assert {:ok, _} = Task.await(task) end)

      assert ObservableProvider.calls().current_key == 0
    end

    @tag cached: ShortTTL
    test "an expired entry returns to the provider rather than serving stale",
         %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)
      ObservableProvider.reset_calls()

      Process.sleep(80)

      assert {:ok, _} = provider.current_key(scope)
      assert ObservableProvider.calls().current_key == 1
    end

    @tag cached: ShortTTL
    test "an expired entry during an outage fails rather than serving stale",
         %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)

      Process.sleep(80)
      ObservableProvider.outage(true)

      assert {:error, :provider_down} = provider.current_key(scope)

      ObservableProvider.outage(false)
    end
  end

  describe "the tombstone asymmetry" do
    test "destroy-then-read returns :destroyed, never a cached hit",
         %{provider: provider, scope: scope} do
      assert {:ok, %{version: version}} = provider.current_key(scope)
      assert {:ok, _} = provider.get_key(scope, version)

      assert :ok = provider.destroy(scope)

      assert {:error, :destroyed} = provider.current_key(scope)
      assert {:error, :destroyed} = provider.get_key(scope, version)
      assert {:error, :destroyed} = provider.get_key(scope, 99)
    end

    test "a cached tombstone keeps reads fail-closed through a provider outage",
         %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)
      assert :ok = provider.destroy(scope)

      ObservableProvider.outage(true)
      ObservableProvider.reset_calls()

      # The tombstone is cached, so this is answered without the provider at all — and
      # the answer is the fail-closed one, not `{:error, :provider_down}`.
      assert {:error, :destroyed} = provider.current_key(scope)
      assert ObservableProvider.calls().current_key == 0

      ObservableProvider.outage(false)
    end

    test "the ABSENCE of a tombstone is never cached", %{provider: provider, scope: scope} do
      # A live scope: read it enough times to populate everything the cache is willing to
      # hold, then destroy it *behind the cache's back* and evict only the key slots. If
      # "not destroyed" had been cached, the next read would still say so.
      assert {:ok, %{version: version}} = provider.current_key(scope)
      assert {:ok, _} = provider.get_key(scope, version)

      # Destroy at the wrapped provider directly, bypassing the wrapper's eviction, then
      # drop the cached key material by hand. A cached "not destroyed" marker would
      # survive this; there isn't one.
      assert :ok = ObservableProvider.destroy(scope)
      assert :ok = provider.evict_scope(scope)

      assert {:error, :destroyed} = provider.current_key(scope)
      assert {:error, :destroyed} = provider.get_key(scope, version)
    end

    test "a :not_found is not cached", %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)
      assert {:error, :not_found} = provider.get_key(scope, 5)

      ObservableProvider.reset_calls()
      assert {:error, :not_found} = provider.get_key(scope, 5)
      assert ObservableProvider.calls().get_key == 1

      # And a version that becomes real is served, rather than a cached absence.
      assert {:ok, 2} = provider.rotate(scope)
      assert {:ok, 3} = provider.rotate(scope)
      assert {:ok, 4} = provider.rotate(scope)
      assert {:ok, 5} = provider.rotate(scope)
      assert {:ok, key} = provider.get_key(scope, 5)
      assert byte_size(key) == 32
    end

    test "a provider outage is not cached in either direction",
         %{provider: provider, scope: scope} do
      ObservableProvider.outage(true)
      assert {:error, :provider_down} = provider.current_key(scope)
      ObservableProvider.outage(false)

      ObservableProvider.reset_calls()
      assert {:ok, _} = provider.current_key(scope)
      assert ObservableProvider.calls().current_key == 1
    end
  end

  describe "destroy evicts before it returns" do
    test "the cache is empty for that scope the instant destroy returns",
         %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)
      assert %{entries: entries} = AshVaultRustler.KeyCache.stats(provider)
      assert entries > 0

      assert :ok = provider.destroy(scope)

      # Only the tombstone survives, and it holds no key bytes.
      assert {:ok, :destroyed, _} = AshVaultRustler.KeyCache.fetch(provider, scope, :tombstone)
      assert {:miss, _} = AshVaultRustler.KeyCache.fetch(provider, scope, :current)
      assert :miss = AshVaultRustler.KeyCache.key_handle(provider, scope, :current)
    end

    test "destroying one scope leaves another's cache entry alone", %{provider: provider} do
      kept = "kept_#{System.unique_integer([:positive])}"
      erased = "erased_#{System.unique_integer([:positive])}"

      assert {:ok, %{key: kept_key}} = provider.current_key(kept)
      assert {:ok, _} = provider.current_key(erased)

      assert :ok = provider.destroy(erased)

      ObservableProvider.reset_calls()
      assert {:ok, %{key: ^kept_key}} = provider.current_key(kept)
      assert ObservableProvider.calls().current_key == 0
    end

    test "a failing provider destroy records no tombstone", %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)

      ObservableProvider.outage(true)
      assert {:error, :provider_down} = provider.destroy(scope)
      ObservableProvider.outage(false)

      assert {:miss, _} = AshVaultRustler.KeyCache.fetch(provider, scope, :tombstone)
      assert {:ok, _} = provider.current_key(scope)
    end

    test "evict_scope on a single node reports success", %{provider: provider, scope: scope} do
      assert {:ok, _} = provider.current_key(scope)
      assert :ok = provider.evict_scope(scope)
      assert {:miss, _} = AshVaultRustler.KeyCache.fetch(provider, scope, :current)
    end
  end

  describe "rotation" do
    test "rotate evicts the scope so the next read sees the new version",
         %{provider: provider, scope: scope} do
      assert {:ok, %{version: 1, key: v1}} = provider.current_key(scope)
      assert {:ok, 2} = provider.rotate(scope)

      assert {:ok, %{version: 2, key: v2}} = provider.current_key(scope)
      refute v1 == v2

      assert {:ok, ^v1} = provider.get_key(scope, 1)
      assert {:ok, ^v2} = provider.get_key(scope, 2)
    end
  end

  describe "configuration" do
    test "a missing :provider is refused with a message that says what to do" do
      assert_raise ArgumentError, ~r/requires a `:provider` to wrap/, fn ->
        AshVault.KeyProviders.Cached.build_opts!(NoProvider, [])
      end
    end

    test "a non-integer ttl is refused" do
      assert_raise ArgumentError, ~r/must be a\n\s*positive integer/, fn ->
        AshVault.KeyProviders.Cached.build_opts!(Bad, provider: ObservableProvider, ttl: :soon)
      end
    end

    test "the defaults are the documented ones" do
      opts = AshVault.KeyProviders.Cached.build_opts!(Defaults, provider: ObservableProvider)

      assert opts.ttl == 30_000
      assert opts.historical_ttl == 30_000
      assert opts.backend == AshVault.KeyCaches.ETS
      assert opts.cluster == true
      assert opts.max_entries == 1_024
      assert opts.max_bytes == 1_048_576
    end

    test ":historical_ttl defaults to :ttl, so the erasure SLA is one number" do
      opts =
        AshVault.KeyProviders.Cached.build_opts!(Tuned, provider: ObservableProvider, ttl: 5_000)

      assert opts.historical_ttl == 5_000
    end

    test "a non-binary scope is refused the same way every other provider refuses it",
         %{provider: provider} do
      for bad <- [:atom, 42, {:tuple, 1}, %{a: 1}, ["list"], nil] do
        assert_raise ArgumentError, ~r/must be binaries/, fn -> provider.current_key(bad) end
        assert_raise ArgumentError, ~r/must be binaries/, fn -> provider.get_key(bad, 1) end
        assert_raise ArgumentError, ~r/must be binaries/, fn -> provider.rotate(bad) end
        assert_raise ArgumentError, ~r/must be binaries/, fn -> provider.destroy(bad) end
      end
    end
  end
end
