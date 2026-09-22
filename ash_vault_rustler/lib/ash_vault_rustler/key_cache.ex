defmodule AshVaultRustler.KeyCache do
  @moduledoc """
  An `AshVault.KeyCache` backend that holds key material outside the BEAM heap.

  Drop-in for `AshVault.KeyCaches.ETS`:

      use AshVault.Vault,
        key_provider: MyApp.Keys,
        cache: [backend: AshVaultRustler.KeyCache, ttl: :timer.seconds(30)]

  All the policy — what may be cached, the tombstone asymmetry, the synchronous
  cluster-wide eviction on destroy — stays in `AshVault.KeyProviders.Cached`. This module
  changes exactly one thing, and it is the thing the BEAM cannot do:

  > #### `zeroes_on_evict?/0` returns `true` {: .tip}
  >
  > Each cached key lives in a page-aligned allocation that this package owns, `mlock`ed
  > into RAM so it cannot reach swap, and **overwritten before it is freed**. Eviction is
  > a `Drop`, and the `Drop` zeroes. `AshVault.KeyProviders.Cached.evict_scope/1` returns
  > only after those writes have happened, which is what makes
  > `AshVault.destroy_keys!/2` immediate rather than eventual-within-a-TTL for this node.

  ## What it still does not buy

  `AshVault.KeyProviders.Cached.get_key/2` returns a **binary** to the BEAM, so a copy of
  the key lands on an Elixir process heap for every encrypt and decrypt, and that copy is
  the garbage collector's business, not ours. This backend bounds the lifetime of the
  *authoritative* copy; it does not eliminate the per-operation one.

  Eliminating it needs `AshVaultRustler.KeyProviders.Opaque` together with
  `AshVaultRustler.Cipher`, which pass a handle rather than bytes.

  ## `mlock` is best effort, and it is charged per page

  Each cached key gets its **own page**, because `mlock`/`munlock` operate on whole pages
  and locking a 32-byte buffer inside a shared page would unlock whatever else lives on
  that page when it is freed. The consequence is an accounting trap worth stating plainly:

  > A 32-byte key costs **4 KiB of locked memory**, and `:max_bytes` counts key bytes, not
  > pages. The defaults (`max_entries: 1_024`, `max_bytes: 1_048_576`) can lock up to
  > **4 MiB** while the reported byte total reads 32 KiB. With this backend, size
  > `:max_entries` against `RLIMIT_MEMLOCK`; `:max_bytes` is the secondary bound.

  A default container `ulimit -l` is often 64 KiB — sixteen pages — so locking starts
  failing after about sixteen cached keys on a stock host. That is not fatal: the failure
  is logged once, loudly, and caching continues, because a key that might reach swap still
  beats a node that refuses to decrypt. `AshVaultRustler.mlock_status/0` reports the
  running totals and is worth an alert in production.

  ## Storage

  The cache itself is a Rust `DashMap` behind a NIF resource. The resource is created by
  this module's `GenServer` and published to `:persistent_term`, so `fetch/3` is a
  `:persistent_term.get/1` plus a NIF call — no message, no lock on the Elixir side. The
  `GenServer` exists to own the resource's lifetime and to evict everything on shutdown.
  """

  @behaviour AshVault.KeyCache

  use GenServer

  require Logger

  alias AshVaultRustler.Native

  @default_max_entries 1_024
  @default_max_bytes 1_048_576

  # Mirrors `cache.rs`. Kept as literals rather than computed so that a change on either
  # side of the boundary shows up as a diff on both.
  @slot_current -1
  @slot_tombstone -2

  @meta_key <<0>>
  @meta_key_info <<1>>
  @meta_destroyed <<2>>

  @doc """
  Start the cache. Options: `:name` (required), `:max_entries`, `:max_bytes`.
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
  Eviction here overwrites the bytes before freeing them. Always `true`.
  """
  @impl AshVault.KeyCache
  @spec zeroes_on_evict?() :: boolean()
  def zeroes_on_evict?, do: true

  @doc """
  Read a slot, returning the generation observed so a later `put/6` can be fenced.
  """
  @impl AshVault.KeyCache
  @spec fetch(AshVault.KeyCache.name(), AshVault.KeyCache.scope(), AshVault.KeyCache.slot()) ::
          {:ok, AshVault.KeyCache.entry(), AshVault.KeyCache.generation()}
          | {:miss, AshVault.KeyCache.generation()}
  def fetch(name, scope, slot) when is_binary(scope) do
    case cache(name) do
      nil ->
        # Not started. A cache is allowed to fail to cache; it is never allowed to fail
        # to serve, and it must never answer "not destroyed" on its own initiative.
        {:miss, 0}

      cache ->
        case Native.cache_fetch(cache, scope, encode_slot(slot)) do
          {:ok, secret, meta, generation} -> {:ok, decode_entry(secret, meta), generation}
          {:miss, generation} -> {:miss, generation}
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
    case cache(name) do
      nil ->
        :ok

      cache ->
        {secret, meta} = encode_entry(entry)

        result =
          Native.cache_put(
            cache,
            scope,
            encode_slot(slot),
            secret,
            meta,
            encode_ttl(ttl),
            generation
          )

        # After the write, not at start: at start nothing has been allocated, so the
        # counters are always {0, 0} and a warning there could never fire.
        warn_if_mlock_unavailable(name)

        result
    end
  end

  @doc """
  Synchronously drop and **zero** every entry for a scope, bumping its generation.

  When this returns, the bytes are gone from this node's memory — not dereferenced, not
  queued for collection: overwritten.
  """
  @impl AshVault.KeyCache
  @spec evict_scope(AshVault.KeyCache.name(), AshVault.KeyCache.scope()) :: :ok | {:error, term()}
  def evict_scope(name, scope) when is_binary(scope) do
    case cache(name) do
      nil -> :ok
      cache -> Native.cache_evict_scope(cache, scope)
    end
  rescue
    error -> {:error, {:cache_unavailable, error}}
  end

  @doc """
  Drop and zero everything.
  """
  @impl AshVault.KeyCache
  @spec evict_all(AshVault.KeyCache.name()) :: :ok | {:error, term()}
  def evict_all(name) do
    case cache(name) do
      nil -> :ok
      cache -> Native.cache_evict_all(cache)
    end
  rescue
    error -> {:error, {:cache_unavailable, error}}
  end

  @doc """
  Entry count and total cached key bytes.
  """
  @impl AshVault.KeyCache
  @spec stats(AshVault.KeyCache.name()) :: %{entries: non_neg_integer(), bytes: non_neg_integer()}
  def stats(name) do
    case cache(name) do
      nil ->
        %{entries: 0, bytes: 0}

      cache ->
        {entries, bytes} = Native.cache_stats(cache)
        %{entries: entries, bytes: bytes}
    end
  end

  @doc """
  The current generation for a scope, `0` if it has never been evicted.
  """
  @spec generation(AshVault.KeyCache.name(), AshVault.KeyCache.scope()) ::
          AshVault.KeyCache.generation()
  def generation(name, scope) do
    case cache(name) do
      nil -> 0
      cache -> Native.cache_generation(cache, scope)
    end
  end

  @doc """
  An opaque `AshVault.Key` handle to a cached key, or `:miss`.

  The bytes are copied from the cache's allocation into the handle's own `mlock`ed,
  zero-on-drop allocation. That copy is native-to-native: the key still never becomes an
  Elixir term.
  """
  @spec key_handle(AshVault.KeyCache.name(), AshVault.KeyCache.scope(), AshVault.KeyCache.slot()) ::
          {:ok, AshVault.Key.opaque()} | :miss
  def key_handle(name, scope, slot) do
    case cache(name) do
      nil ->
        :miss

      cache ->
        case Native.cache_key_handle(cache, scope, encode_slot(slot)) do
          {:ok, ref} -> {:ok, %AshVault.Key{ref: ref, owner: __MODULE__}}
          :miss -> :miss
        end
    end
  end

  @doc """
  The raw NIF cache resource for a running instance, or `nil`.

  Public because `AshVaultRustler.Cipher` needs it to run the AEAD against a cached key
  without materialising it. Not useful otherwise.
  """
  @spec cache(AshVault.KeyCache.name()) :: reference() | nil
  def cache(name) do
    :persistent_term.get({__MODULE__, name}, nil)
  end

  # --- encoding -------------------------------------------------------------

  defp encode_slot(:current), do: @slot_current
  defp encode_slot(:tombstone), do: @slot_tombstone
  defp encode_slot(version) when is_integer(version) and version > 0, do: version

  defp encode_ttl(:infinity), do: -1
  defp encode_ttl(ms) when is_integer(ms) and ms >= 0, do: ms

  # The split is deliberate: the *secret* goes into Rust's zeroing allocation, and the
  # non-secret metadata (a version number and a timestamp) rides along as an ordinary
  # binary. `term_to_binary/1` is safe for the metadata precisely because it never
  # outlives the process — unlike the envelope on disk, where the encoding's stability
  # across OTP releases would matter.
  defp encode_entry({:key, key}) when is_binary(key), do: {key, @meta_key}

  defp encode_entry({:key_info, %{key: key} = info}) when is_binary(key) do
    {key, @meta_key_info <> :erlang.term_to_binary(Map.delete(info, :key))}
  end

  defp encode_entry(:destroyed), do: {<<>>, @meta_destroyed}

  defp decode_entry(secret, @meta_key), do: {:key, secret}

  defp decode_entry(secret, @meta_key_info <> rest) do
    # `:safe` is not needed — this binary was produced by this module a moment ago and
    # never left the node — but it costs nothing and keeps the habit.
    {:key_info, Map.put(:erlang.binary_to_term(rest, [:safe]), :key, secret)}
  end

  defp decode_entry(_secret, @meta_destroyed), do: :destroyed

  # --- GenServer ------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    Process.flag(:trap_exit, true)

    name = Keyword.fetch!(opts, :name)

    cache =
      Native.cache_new(
        Keyword.get(opts, :max_entries, @default_max_entries),
        Keyword.get(opts, :max_bytes, @default_max_bytes)
      )

    :persistent_term.put({__MODULE__, name}, cache)

    {:ok, %{name: name, cache: cache}}
  end

  @impl GenServer
  def terminate(_reason, state) do
    # Zero everything on the way out rather than leaving it to the resource destructor,
    # so an orderly shutdown has an orderly wipe. The destructor still runs and still
    # zeroes if we are killed instead.
    Native.cache_evict_all(state.cache)
    :persistent_term.erase({__MODULE__, state.name})
    :ok
  end

  # Key material never reaches this GenServer's state — only the resource reference does —
  # so a crash report from here carries no secrets.
  @impl GenServer
  def format_status(status), do: status

  # Checked after a write, not at start: at start nothing has been allocated yet, so the
  # counters are always `{0, 0}` and the warning could never fire. A warning that cannot
  # fire is exactly the "silently pretend" this is supposed to prevent.
  #
  # `:persistent_term` rather than a counter in the GenServer state because `put/6` is a
  # plain function call on the caller's process, not a message to this one.
  defp warn_if_mlock_unavailable(name) do
    flag = {__MODULE__, :mlock_warned, name}

    with false <- :persistent_term.get(flag, false),
         {_locked, failed} when failed > 0 <- Native.mlock_status() do
      :persistent_term.put(flag, true)

      Logger.warning(
        "AshVault: #{inspect(name)} could not mlock #{failed} key allocation(s), so key " <>
          "material may be written to swap or a hibernation image. This backend spends " <>
          "one locked PAGE per cached key, so RLIMIT_MEMLOCK has to cover " <>
          "`max_entries` pages, not `max_bytes`. Raise it with `ulimit -l`, or " <>
          "LimitMEMLOCK= in a systemd unit. Caching continues either way."
      )
    end

    :ok
  end
end
