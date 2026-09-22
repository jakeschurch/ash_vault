defmodule AshVault.KeyCaches.ETSTest do
  @moduledoc """
  The bounds `AshVault.KeyCaches.ETS` promises, and the interaction between them and the
  inevictable `:tombstone` slot.
  """

  use ExUnit.Case, async: true

  alias AshVault.KeyCaches.ETS

  setup do
    name = Module.concat(__MODULE__, "Cache#{System.unique_integer([:positive])}")
    start_supervised!({ETS, name: name, max_entries: 4, max_bytes: 1_048_576})
    %{cache: name}
  end

  defp put_key!(cache, scope) do
    {:miss, generation} = ETS.fetch(cache, scope, :current)
    ETS.put(cache, scope, :current, {:key, :crypto.strong_rand_bytes(32)}, 60_000, generation)
  end

  defp put_tombstone!(cache, scope) do
    {:miss, generation} = ETS.fetch(cache, scope, :tombstone)
    ETS.put(cache, scope, :tombstone, :destroyed, :infinity, generation)
  end

  defp live_keys(cache, scopes) do
    Enum.count(scopes, &match?({:ok, _, _}, ETS.fetch(cache, &1, :current)))
  end

  describe "max_entries" do
    test "evicts the least recently used key entries", %{cache: cache} do
      scopes = for n <- 1..10, do: "scope-#{n}"
      Enum.each(scopes, &put_key!(cache, &1))

      assert live_keys(cache, scopes) == 4
    end

    test "counts only evictable entries towards the bound", %{cache: cache} do
      # Tombstones are never evicted for space, so counting them towards `:max_entries`
      # broke the bound in both directions at once: `trim/1` ran out of candidates with
      # the count still over the limit (so `stats/1` exceeded `:max_entries` for good),
      # and every key written after that was trimmed away immediately — a cache with
      # enough destroyed scopes stopped caching keys at all.
      for n <- 1..8, do: put_tombstone!(cache, "destroyed-#{n}")

      scopes = for n <- 1..3, do: "live-#{n}"
      Enum.each(scopes, &put_key!(cache, &1))

      assert live_keys(cache, scopes) == 3
    end

    test "keeps bounding keys when the cache is mostly tombstones", %{cache: cache} do
      for n <- 1..8, do: put_tombstone!(cache, "destroyed-#{n}")

      scopes = for n <- 1..10, do: "live-#{n}"
      Enum.each(scopes, &put_key!(cache, &1))

      assert live_keys(cache, scopes) == 4
    end

    test "never evicts a tombstone to make room for a key", %{cache: cache} do
      for n <- 1..8, do: put_tombstone!(cache, "destroyed-#{n}")
      for n <- 1..10, do: put_key!(cache, "live-#{n}")

      for n <- 1..8 do
        assert {:ok, :destroyed, _} = ETS.fetch(cache, "destroyed-#{n}", :tombstone)
      end
    end

    test "releases the tombstone allowance again when a scope is evicted", %{cache: cache} do
      for n <- 1..8, do: put_tombstone!(cache, "destroyed-#{n}")
      for n <- 1..8, do: :ok = ETS.evict_scope(cache, "destroyed-#{n}")

      assert %{entries: 0} = ETS.stats(cache)

      scopes = for n <- 1..10, do: "live-#{n}"
      Enum.each(scopes, &put_key!(cache, &1))

      assert live_keys(cache, scopes) == 4
    end
  end

  describe "the generation fence" do
    test "drops a put whose scope was evicted since the fetch", %{cache: cache} do
      {:miss, generation} = ETS.fetch(cache, "acme", :current)
      :ok = ETS.evict_scope(cache, "acme")

      assert :stale = ETS.put(cache, "acme", :current, {:key, <<0::256>>}, 60_000, generation)
      assert {:miss, _} = ETS.fetch(cache, "acme", :current)
    end
  end
end
