defmodule AshVault.KeyProviders.CachedTest do
  @moduledoc """
  The generation fence in `AshVault.KeyProviders.Cached`.

  The scenario is a peer node in a cluster: it never runs `destroy/2` itself, it only
  sees the two `evict_scope/2` fan-outs. A read that was already in flight when the first
  eviction landed must not be able to write its result back afterwards — through *any*
  slot.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyCaches.ETS
  alias AshVault.KeyProviders.Cached

  defmodule BlockingProvider do
    @moduledoc false
    @behaviour AshVault.KeyProvider

    @key :crypto.strong_rand_bytes(32)

    @doc false
    def key, do: @key

    @doc false
    def reset!, do: :persistent_term.put({__MODULE__, :destroyed}, false)

    defp destroyed?, do: :persistent_term.get({__MODULE__, :destroyed}, false)

    @impl AshVault.KeyProvider
    def current_key(_scope) do
      # The provider answers before the destroy reaches it, then the caller is
      # descheduled — a GC pause, a slow socket read, anything — for exactly as long as
      # the cluster-wide destroy takes.
      result =
        if destroyed?(),
          do: {:error, :destroyed},
          else: {:ok, %{version: 1, key: @key, created_at: DateTime.utc_now()}}

      send(:ash_vault_cached_test_runner, {:in_flight, self()})
      receive do: (:go -> :ok)
      result
    end

    @impl AshVault.KeyProvider
    def get_key(_scope, _version),
      do: if(destroyed?(), do: {:error, :destroyed}, else: {:ok, @key})

    @impl AshVault.KeyProvider
    def rotate(_scope), do: {:ok, 1}

    @impl AshVault.KeyProvider
    def destroy(_scope) do
      :persistent_term.put({__MODULE__, :destroyed}, true)
      :ok
    end
  end

  setup do
    BlockingProvider.reset!()
    Process.register(self(), :ash_vault_cached_test_runner)
    name = Module.concat(__MODULE__, "Cache#{System.unique_integer([:positive])}")
    start_supervised!({ETS, name: name, max_entries: 1024, max_bytes: 1_048_576})

    opts = %{
      provider: BlockingProvider,
      backend: ETS,
      cache_name: name,
      ttl: 30_000,
      historical_ttl: 30_000,
      max_entries: 1024,
      max_bytes: 1_048_576,
      cluster: false,
      evict_timeout: 5_000
    }

    on_exit(fn -> BlockingProvider.reset!() end)

    %{cache: name, opts: opts}
  end

  describe "a read in flight across a cluster-wide destroy" do
    test "cannot repopulate any slot afterwards", %{cache: cache, opts: opts} do
      scope = "acme"

      reader = Task.async(fn -> Cached.current_key(scope, opts) end)
      in_flight = receive do: ({:in_flight, pid} -> pid)

      # The destroy runs on another node. All this node sees is the fan-out.
      :ok = ETS.evict_scope(cache, scope)
      :ok = BlockingProvider.destroy(scope)
      :ok = ETS.evict_scope(cache, scope)

      send(in_flight, :go)
      _ = Task.await(reader)

      assert {:miss, _} = ETS.fetch(cache, scope, :current)

      # The regression: `cache_key_info/4` used to re-read the generation before seeding
      # the version slot, and a re-read generation is never stale, so this `put` always
      # landed — after both evictions.
      assert {:miss, _} = ETS.fetch(cache, scope, 1)

      assert {:error, :destroyed} = Cached.get_key(scope, 1, opts)
    end
  end

  describe "an ordinary miss" do
    test "seeds both the :current and the version slot", %{cache: cache, opts: opts} do
      scope = "seeded"

      reader = Task.async(fn -> Cached.current_key(scope, opts) end)
      in_flight = receive do: ({:in_flight, pid} -> pid)
      send(in_flight, :go)

      assert {:ok, %{version: 1}} = Task.await(reader)

      assert {:ok, {:key_info, %{version: 1}}, _} = ETS.fetch(cache, scope, :current)
      assert {:ok, {:key, key}, _} = ETS.fetch(cache, scope, 1)
      assert key == BlockingProvider.key()
    end
  end
end
