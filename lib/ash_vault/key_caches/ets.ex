defmodule AshVault.KeyCaches.ETS do
  @moduledoc """
  The default `AshVault.KeyCache` backend: a bounded, TTL'd, LRU ETS table.

  Pure Elixir, no native code, and the fallback `cache: true` resolves to when no other
  backend is named.

  > #### This backend cannot zero key material {: .warning}
  >
  > `zeroes_on_evict?/0` returns `false`, and that is not a detail to gloss over.
  > Deleting an ETS object drops a *reference*. A 32-byte key is small enough to be
  > copied onto the caller's heap rather than refcounted, so after an eviction the bytes
  > survive in however many process heaps read them, for however long the garbage
  > collector takes. The BEAM offers no way to overwrite them.
  >
  > What this backend does guarantee is the **observable** contract: after
  > `evict_scope/2` returns, no `fetch/3` on this node can see that scope again, and the
  > generation fence means an in-flight read cannot put it back. That is what bounds the
  > erasure window. `AshVaultRustler.KeyCache` additionally zeroes the authoritative
  > copy.

  ## Storage

  Two public ETS tables, owned by a `GenServer` named after the cache:

    * entries — `{{scope, slot}, entry, expires_at, generation, last_used, bytes}`
    * generations — `{scope, generation}`

  `fetch/3` reads ETS directly, so the hot path takes no lock and no message. `put/6`
  and `evict_scope/2` go through the owning process, which is what keeps the entry and
  byte bounds and the LRU order exact rather than eventually consistent. Puts only
  happen on a provider miss, so the serialisation point is off the hot path.

  ## Bounds

  `:max_entries` and `:max_bytes` are both enforced on every write; when either is
  exceeded the least-recently-used entries are dropped until both hold. `:tombstone`
  entries are never evicted for space — they carry no key material, they are the
  fail-closed answer, and dropping one to make room for a key would be precisely
  backwards.

  ## Not started?

  If the owning process is not running, `fetch/3` answers `{:miss, 0}` and `put/6` is a
  no-op. Every read then goes to the real provider: slower, and correct. A cache is
  allowed to fail to cache; it is never allowed to fail to serve.
  """

  @behaviour AshVault.KeyCache

  use GenServer

  @default_max_entries 1_024
  @default_max_bytes 1_048_576

  @doc """
  Start the cache.

  Options: `:name` (required), `:max_entries`, `:max_bytes`.
  """
  @impl AshVault.KeyCache
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc false
  @impl AshVault.KeyCache
  def child_spec(opts) do
    %{
      id: Keyword.fetch!(opts, :name),
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @doc """
  This backend drops references; it does not zero. Always `false`.
  """
  @impl AshVault.KeyCache
  @spec zeroes_on_evict?() :: boolean()
  def zeroes_on_evict?, do: false

  @doc """
  Read a slot, returning the generation observed so a later `put/6` can be fenced.
  """
  @impl AshVault.KeyCache
  @spec fetch(AshVault.KeyCache.name(), AshVault.KeyCache.scope(), AshVault.KeyCache.slot()) ::
          {:ok, AshVault.KeyCache.entry(), AshVault.KeyCache.generation()}
          | {:miss, AshVault.KeyCache.generation()}
  def fetch(name, scope, slot) when is_binary(scope) do
    entries = entries_table(name)

    if :ets.whereis(entries) == :undefined do
      {:miss, 0}
    else
      generation = generation(name, scope)

      case :ets.lookup(entries, {scope, slot}) do
        [{_key, entry, expires_at, ^generation, _last_used, _bytes}] ->
          if expired?(expires_at) do
            {:miss, generation}
          else
            touch(entries, {scope, slot})
            {:ok, entry, generation}
          end

        _other ->
          {:miss, generation}
      end
    end
  end

  @doc """
  Write a slot unless the scope's generation has advanced since `fetch/3` read it.
  """
  @impl AshVault.KeyCache
  @spec put(
          AshVault.KeyCache.name(),
          AshVault.KeyCache.scope(),
          AshVault.KeyCache.slot(),
          AshVault.KeyCache.entry(),
          AshVault.KeyCache.ttl(),
          AshVault.KeyCache.generation()
        ) :: :ok | :stale
  def put(name, scope, slot, entry, ttl, generation) when is_binary(scope) do
    if running?(name) do
      GenServer.call(name, {:put, scope, slot, entry, ttl, generation})
    else
      :ok
    end
  catch
    :exit, _reason -> :ok
  end

  @doc """
  Drop every entry for a scope and bump its generation. Synchronous.
  """
  @impl AshVault.KeyCache
  @spec evict_scope(AshVault.KeyCache.name(), AshVault.KeyCache.scope()) :: :ok | {:error, term()}
  def evict_scope(name, scope) when is_binary(scope) do
    if running?(name) do
      GenServer.call(name, {:evict_scope, scope})
    else
      # Nothing is cached because nothing is running. There is no key here to fail to
      # evict, so reporting success is honest — and reporting failure would make every
      # `destroy!` fail on a node that deliberately runs without a cache.
      :ok
    end
  catch
    :exit, reason -> {:error, {:cache_unavailable, reason}}
  end

  @doc """
  Drop everything, bumping the generation of every scope currently known.
  """
  @impl AshVault.KeyCache
  @spec evict_all(AshVault.KeyCache.name()) :: :ok | {:error, term()}
  def evict_all(name) do
    if running?(name), do: GenServer.call(name, :evict_all), else: :ok
  catch
    :exit, reason -> {:error, {:cache_unavailable, reason}}
  end

  @doc """
  Entry count and total cached key bytes.
  """
  @impl AshVault.KeyCache
  @spec stats(AshVault.KeyCache.name()) :: %{
          entries: non_neg_integer(),
          bytes: non_neg_integer()
        }
  def stats(name) do
    if running?(name), do: GenServer.call(name, :stats), else: %{entries: 0, bytes: 0}
  catch
    :exit, _reason -> %{entries: 0, bytes: 0}
  end

  @doc """
  The current generation for a scope, `0` if it has never been evicted.
  """
  @spec generation(AshVault.KeyCache.name(), AshVault.KeyCache.scope()) ::
          AshVault.KeyCache.generation()
  def generation(name, scope) do
    table = generations_table(name)

    if :ets.whereis(table) == :undefined do
      0
    else
      case :ets.lookup(table, scope) do
        [{^scope, generation}] -> generation
        _other -> 0
      end
    end
  end

  @doc false
  @spec entries_table(AshVault.KeyCache.name()) :: atom()
  def entries_table(name), do: Module.concat(name, "Entries")

  @doc false
  @spec generations_table(AshVault.KeyCache.name()) :: atom()
  def generations_table(name), do: Module.concat(name, "Generations")

  defp running?(name), do: is_pid(GenServer.whereis(name))

  defp expired?(:infinity), do: false
  defp expired?(expires_at), do: System.monotonic_time(:millisecond) >= expires_at

  defp touch(entries, key) do
    :ets.update_element(entries, key, {5, System.monotonic_time(:millisecond)})
  rescue
    ArgumentError -> false
  end

  @impl GenServer
  def init(opts) do
    name = Keyword.fetch!(opts, :name)

    entries =
      :ets.new(entries_table(name), [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    generations =
      :ets.new(generations_table(name), [
        :set,
        :public,
        :named_table,
        read_concurrency: true
      ])

    {:ok,
     %{
       name: name,
       entries: entries,
       generations: generations,
       count: 0,
       bytes: 0,
       max_entries: Keyword.get(opts, :max_entries, @default_max_entries),
       max_bytes: Keyword.get(opts, :max_bytes, @default_max_bytes)
     }}
  end

  @impl GenServer
  def handle_call({:put, scope, slot, entry, ttl, generation}, _from, state) do
    if generation == generation(state.name, scope) do
      {:reply, :ok, do_put(state, scope, slot, entry, ttl, generation)}
    else
      # The scope was evicted between the read that missed and this write. Dropping the
      # write is the whole point of the fence: without it, a read that began before a
      # `destroy` repopulates the cache after the eviction and the erased scope is
      # readable again for a full TTL.
      {:reply, :stale, state}
    end
  end

  def handle_call({:evict_scope, scope}, _from, state) do
    removed = :ets.match_object(state.entries, {{scope, :_}, :_, :_, :_, :_, :_})
    :ets.match_delete(state.entries, {{scope, :_}, :_, :_, :_, :_, :_})

    freed = Enum.reduce(removed, 0, fn {_k, _e, _x, _g, _l, bytes}, acc -> acc + bytes end)

    next = generation(state.name, scope) + 1
    :ets.insert(state.generations, {scope, next})

    {:reply, :ok, %{state | count: state.count - length(removed), bytes: state.bytes - freed}}
  end

  def handle_call(:evict_all, _from, state) do
    scopes =
      state.entries
      |> :ets.match({{:"$1", :_}, :_, :_, :_, :_, :_})
      |> List.flatten()
      |> Enum.concat(:ets.select(state.generations, [{{:"$1", :_}, [], [:"$1"]}]))
      |> Enum.uniq()

    :ets.delete_all_objects(state.entries)

    Enum.each(scopes, fn scope ->
      :ets.insert(state.generations, {scope, generation(state.name, scope) + 1})
    end)

    {:reply, :ok, %{state | count: 0, bytes: 0}}
  end

  def handle_call(:stats, _from, state) do
    {:reply, %{entries: state.count, bytes: state.bytes}, state}
  end

  # Key material lives in the ETS tables, not in the GenServer state, so a crash report
  # from this process carries no secrets. The table *names* are all that is here.
  @impl GenServer
  def format_status(status), do: status

  defp do_put(state, scope, slot, entry, ttl, generation) do
    now = System.monotonic_time(:millisecond)
    expires_at = if ttl == :infinity, do: :infinity, else: now + ttl
    bytes = AshVault.KeyCache.entry_bytes(entry)

    previous =
      case :ets.lookup(state.entries, {scope, slot}) do
        [{_k, _e, _x, _g, _l, old_bytes}] -> old_bytes
        _other -> nil
      end

    :ets.insert(state.entries, {{scope, slot}, entry, expires_at, generation, now, bytes})

    state =
      case previous do
        nil -> %{state | count: state.count + 1, bytes: state.bytes + bytes}
        old -> %{state | bytes: state.bytes - old + bytes}
      end

    trim(state)
  end

  defp trim(state) do
    if state.count <= state.max_entries and state.bytes <= state.max_bytes do
      state
    else
      # Tombstones are excluded: they hold no key material, they are the fail-closed
      # answer, and evicting one to make room for a key would be exactly backwards.
      candidates =
        state.entries
        |> :ets.select([
          {{{:"$1", :"$2"}, :_, :_, :_, :"$3", :"$4"}, [{:"/=", :"$2", :tombstone}],
           [{{:"$1", :"$2", :"$3", :"$4"}}]}
        ])
        |> Enum.sort_by(fn {_scope, _slot, last_used, _bytes} -> last_used end)

      Enum.reduce_while(candidates, state, fn {scope, slot, _last_used, bytes}, acc ->
        if acc.count <= acc.max_entries and acc.bytes <= acc.max_bytes do
          {:halt, acc}
        else
          :ets.delete(acc.entries, {scope, slot})
          {:cont, %{acc | count: acc.count - 1, bytes: acc.bytes - bytes}}
        end
      end)
    end
  end
end
