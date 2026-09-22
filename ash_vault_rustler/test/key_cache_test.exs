defmodule AshVaultRustler.KeyCacheTest do
  @moduledoc """
  The `AshVault.KeyCache` contract, run against both shipped backends.

  Everything in here must hold for the pure-Elixir backend and the Rust one alike. The
  one thing that legitimately differs — whether eviction zeroes — is asserted separately
  at the bottom, because it is the entire reason this package exists.
  """

  use ExUnit.Case, async: true

  @backends [AshVault.KeyCaches.ETS, AshVaultRustler.KeyCache]

  setup context do
    name = :"cache_#{System.unique_integer([:positive])}"

    backend = context[:backend] || AshVaultRustler.KeyCache

    start_supervised!({backend, name: name, max_entries: 8, max_bytes: 4_096})

    %{name: name, backend: backend, key: :crypto.strong_rand_bytes(32)}
  end

  for backend <- @backends do
    describe "#{inspect(backend)}" do
      @describetag backend: backend

      test "a miss on an unknown scope reports generation 0", %{name: name, backend: backend} do
        assert {:miss, 0} = backend.fetch(name, "nobody", :current)
      end

      test "put then fetch round trips a key_info", %{name: name, backend: backend, key: key} do
        created = DateTime.utc_now()
        info = %{version: 3, key: key, created_at: created}

        assert :ok = backend.put(name, "acme", :current, {:key_info, info}, 60_000, 0)
        assert {:ok, {:key_info, fetched}, 0} = backend.fetch(name, "acme", :current)
        assert fetched.key == key
        assert fetched.version == 3
        assert DateTime.compare(fetched.created_at, created) == :eq
      end

      test "put then fetch round trips a raw key", %{name: name, backend: backend, key: key} do
        assert :ok = backend.put(name, "acme", 7, {:key, key}, 60_000, 0)
        assert {:ok, {:key, ^key}, 0} = backend.fetch(name, "acme", 7)
      end

      test "a tombstone round trips and never expires", %{name: name, backend: backend} do
        assert :ok = backend.put(name, "acme", :tombstone, :destroyed, :infinity, 0)
        assert {:ok, :destroyed, 0} = backend.fetch(name, "acme", :tombstone)
      end

      test "a zero TTL is already expired", %{name: name, backend: backend, key: key} do
        assert :ok = backend.put(name, "acme", :current, {:key, key}, 0, 0)
        assert {:miss, _} = backend.fetch(name, "acme", :current)
      end

      test "evict_scope is synchronous and complete", %{name: name, backend: backend, key: key} do
        backend.put(name, "acme", :current, {:key, key}, 60_000, 0)
        backend.put(name, "acme", 1, {:key, key}, 60_000, 0)
        backend.put(name, "other", :current, {:key, key}, 60_000, 0)

        assert :ok = backend.evict_scope(name, "acme")

        assert {:miss, 1} = backend.fetch(name, "acme", :current)
        assert {:miss, 1} = backend.fetch(name, "acme", 1)
        assert {:ok, _, 0} = backend.fetch(name, "other", :current)
      end

      test "evict_scope removes a tombstone too", %{name: name, backend: backend} do
        backend.put(name, "acme", :tombstone, :destroyed, :infinity, 0)
        assert :ok = backend.evict_scope(name, "acme")
        assert {:miss, 1} = backend.fetch(name, "acme", :tombstone)
      end

      @tag :generation_fence
      test "a put carrying a pre-eviction generation is dropped",
           %{name: name, backend: backend, key: key} do
        assert {:miss, generation} = backend.fetch(name, "acme", :current)

        assert :ok = backend.evict_scope(name, "acme")

        assert :stale = backend.put(name, "acme", :current, {:key, key}, 60_000, generation)
        assert {:miss, _} = backend.fetch(name, "acme", :current)
      end

      test "a put at the current generation is accepted after an eviction",
           %{name: name, backend: backend, key: key} do
        assert :ok = backend.evict_scope(name, "acme")
        assert {:miss, generation} = backend.fetch(name, "acme", :current)
        assert generation == 1
        assert :ok = backend.put(name, "acme", :current, {:key, key}, 60_000, generation)
        assert {:ok, _, 1} = backend.fetch(name, "acme", :current)
      end

      test "evict_all clears everything", %{name: name, backend: backend, key: key} do
        backend.put(name, "a", :current, {:key, key}, 60_000, 0)
        backend.put(name, "b", :current, {:key, key}, 60_000, 0)

        assert :ok = backend.evict_all(name)

        assert %{entries: 0, bytes: 0} = backend.stats(name)
        assert {:miss, _} = backend.fetch(name, "a", :current)
        assert {:miss, _} = backend.fetch(name, "b", :current)
      end

      test "the entry bound is enforced", %{name: name, backend: backend, key: key} do
        for i <- 1..20 do
          backend.put(name, "scope#{i}", :current, {:key, key}, 60_000, 0)
        end

        assert backend.stats(name).entries <= 8
      end

      test "the byte bound is enforced", %{name: name, backend: backend} do
        big = :crypto.strong_rand_bytes(1_024)

        for i <- 1..8 do
          backend.put(name, "scope#{i}", :current, {:key, big}, 60_000, 0)
        end

        assert backend.stats(name).bytes <= 4_096
      end

      test "a tombstone is never dropped to make room", %{name: name, backend: backend, key: key} do
        backend.put(name, "erased", :tombstone, :destroyed, :infinity, 0)

        for i <- 1..30 do
          backend.put(name, "scope#{i}", :current, {:key, key}, 60_000, 0)
        end

        assert {:ok, :destroyed, _} = backend.fetch(name, "erased", :tombstone)
      end

      test "an unstarted cache misses and accepts writes silently", %{backend: backend, key: key} do
        absent = :"never_started_#{System.unique_integer([:positive])}"

        assert {:miss, 0} = backend.fetch(absent, "acme", :current)
        assert :ok = backend.put(absent, "acme", :current, {:key, key}, 60_000, 0)
        assert {:miss, 0} = backend.fetch(absent, "acme", :current)
        assert :ok = backend.evict_scope(absent, "acme")
        assert %{entries: 0, bytes: 0} = backend.stats(absent)
      end

      test "concurrent readers and evictions do not corrupt the counters",
           %{name: name, backend: backend, key: key} do
        backend.put(name, "acme", :current, {:key, key}, 60_000, 0)

        readers =
          for _ <- 1..8 do
            Task.async(fn ->
              for _ <- 1..200, do: backend.fetch(name, "acme", :current)
            end)
          end

        for _ <- 1..50, do: backend.evict_scope(name, "acme")

        Enum.each(readers, &Task.await/1)

        assert %{entries: 0, bytes: 0} = backend.stats(name)
      end
    end
  end

  describe "the difference that matters" do
    @tag backend: AshVaultRustler.KeyCache
    test "the Rust backend zeroes on eviction", %{backend: backend} do
      assert backend.zeroes_on_evict?()
    end

    @tag backend: AshVault.KeyCaches.ETS
    test "the ETS backend says plainly that it does not", %{backend: backend} do
      refute backend.zeroes_on_evict?()
    end

    @tag backend: AshVaultRustler.KeyCache
    test "after evict_scope the key is gone from the Rust side's own accessor",
         %{name: name, key: key} do
      AshVaultRustler.KeyCache.put(name, "acme", :current, {:key, key}, 60_000, 0)

      # Before: the Rust cache will hand out a handle over the cached bytes, and a
      # constant-time comparison against the original key matches.
      assert {:ok, handle} = AshVaultRustler.KeyCache.key_handle(name, "acme", :current)
      assert AshVaultRustler.KeyProviders.Opaque.matches?(handle, key)

      assert :ok = AshVaultRustler.KeyCache.evict_scope(name, "acme")

      # After: the cache has nothing to hand out. Proving the *buffer* was overwritten is
      # not something Elixir can observe — that assertion lives in the Rust unit tests
      # (`secret::tests::drop_zeroes_the_allocation`). This is the observable contract.
      assert :miss = AshVaultRustler.KeyCache.key_handle(name, "acme", :current)
      assert {:miss, 1} = AshVaultRustler.KeyCache.fetch(name, "acme", :current)
    end

    @tag backend: AshVaultRustler.KeyCache
    test "the mlock counters actually move when a key is cached",
         %{name: name, key: key} do
      before = AshVaultRustler.mlock_status()

      AshVaultRustler.KeyCache.put(name, "acme", :current, {:key, key}, 60_000, 0)

      after_put = AshVaultRustler.mlock_status()

      # One of the two must have advanced: the allocation was either locked or it failed
      # to lock. If neither moved, the counters are dead and the warning that reads them
      # could never fire — which is the whole bug this asserts against.
      assert after_put.locked + after_put.failed > before.locked + before.failed
    end

    @tag backend: AshVaultRustler.KeyCache
    test "mlock status is reported rather than assumed" do
      status = AshVaultRustler.mlock_status()

      assert is_integer(status.locked)
      assert is_integer(status.failed)

      if status.failed > 0 do
        IO.warn(
          "mlock failed #{status.failed} time(s) on this host — RLIMIT_MEMLOCK is too " <>
            "low. The package continues, which is the documented behaviour."
        )
      end
    end
  end
end
