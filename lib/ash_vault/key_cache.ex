defmodule AshVault.KeyCache do
  @moduledoc """
  Behaviour for the storage behind `AshVault.KeyProviders.Cached`.

  A key cache is a bounded, TTL'd, scope-partitioned map from `{scope, slot}` to a
  cached provider answer. `AshVault.KeyProviders.Cached` holds all of the *policy* —
  what may be cached, for how long, and the tombstone asymmetry — and a backend holds
  only the *mechanism*. That split is what lets the Rust backend
  (`AshVaultRustler.KeyCache`) drop in without restating any of the security rules.

  AshVault ships `AshVault.KeyCaches.ETS`, which is pure Elixir and is the default.

  ## What a backend must guarantee

    * `evict_scope/2` is **synchronous on the local node**. When it returns `:ok`, no
      subsequent `fetch/3` on that node can observe any entry for that scope that was
      written before the call. Cluster fan-out is the caller's job, not the backend's.
    * `evict_scope/2` **bumps the scope's generation**. Every `fetch/3` returns the
      generation it observed, and `put/6` is given that generation back and must drop
      the write if the generation has since advanced. Without this fence, a read that
      started before a `destroy` can re-populate the cache after the eviction and
      resurrect an erased scope for a full TTL.
    * `fetch/3` never invents an entry. A backend that cannot answer returns `:miss`,
      which sends the caller to the real provider. A cache is allowed to fail to
      cache; it is never allowed to fail to serve, and it is never allowed to answer
      "not destroyed" on its own initiative.
    * Entries expire. An expired entry is a `:miss`.

  ## Slots

  A scope's cache is partitioned by slot:

    * `:current` — the answer to `current_key/1`, a `key_info` map. Rotation-sensitive,
      so it takes the short TTL.
    * a positive integer — the answer to `get_key/2` for that version, a raw key binary.
    * `:tombstone` — a cached `{:error, :destroyed}`. Monotonic and fail-closed, so it
      may be cached without expiry. **Only** `:destroyed` is ever stored here; the
      absence of a tombstone is never cached, because caching "this scope is not
      destroyed" is exactly how a cache resurrects an erased tenant.

  ## Zeroing

  `zeroes_on_evict?/0` tells the truth about whether eviction actually clears the
  bytes. `AshVault.KeyCaches.ETS` returns `false` — the BEAM cannot securely zero
  memory, and an ETS delete drops a reference on a refcounted binary whose lifetime is
  then the garbage collector's business. `AshVaultRustler.KeyCache` returns `true`.
  `AshVault.KeyProviders.Cached` logs this once at start so the difference is never a
  surprise.
  """

  @typedoc "The backend instance name. The generated `Cached` provider module is used."
  @type name :: atom()

  @typedoc "A scope, already normalised to a binary."
  @type scope :: binary()

  @typedoc "Which answer for a scope is being cached."
  @type slot :: :current | :tombstone | pos_integer()

  @typedoc """
  A cached provider answer.

  `{:key_info, map}` for `:current`, `{:key, binary}` for a version slot, and
  `:destroyed` for `:tombstone`.
  """
  @type entry :: {:key_info, map()} | {:key, binary()} | :destroyed

  @typedoc "Monotonically increasing per-scope fence, bumped by every eviction."
  @type generation :: non_neg_integer()

  @typedoc "Milliseconds, or `:infinity` for a tombstone."
  @type ttl :: non_neg_integer() | :infinity

  @doc """
  Start the backend.

  Options always include `:name` (the atom the other callbacks are addressed by),
  `:max_entries` and `:max_bytes`.
  """
  @callback start_link(keyword()) :: GenServer.on_start()

  @doc """
  A child spec, so a cache can be placed in a supervision tree.
  """
  @callback child_spec(keyword()) :: Supervisor.child_spec()

  @doc """
  Read a slot, along with the generation observed.

  Returns `{:miss, generation}` for an absent, expired or evicted entry, and
  `{:miss, 0}` when the backend is not running at all.
  """
  @callback fetch(name(), scope(), slot()) ::
              {:ok, entry(), generation()} | {:miss, generation()}

  @doc """
  Write a slot, unless `generation` is stale.

  Returns `:stale` when the scope's generation has advanced since `fetch/3` observed
  it — the write is dropped, which is the fence that makes `evict_scope/2` durable
  against a concurrent read.
  """
  @callback put(name(), scope(), slot(), entry(), ttl(), generation()) :: :ok | :stale

  @doc """
  Synchronously drop every entry for a scope on this node and bump its generation.
  """
  @callback evict_scope(name(), scope()) :: :ok | {:error, term()}

  @doc "Drop everything. Used by tests and by an operator panic button."
  @callback evict_all(name()) :: :ok | {:error, term()}

  @doc "Current entry count and byte total, for tests and telemetry."
  @callback stats(name()) :: %{entries: non_neg_integer(), bytes: non_neg_integer()}

  @doc """
  Whether eviction actually zeroes the key bytes, or merely drops a reference.
  """
  @callback zeroes_on_evict?() :: boolean()

  @doc """
  The number of bytes an entry's key material occupies, used for the byte bound.
  """
  @spec entry_bytes(entry()) :: non_neg_integer()
  def entry_bytes({:key, key}) when is_binary(key), do: byte_size(key)
  def entry_bytes({:key_info, %{key: key}}) when is_binary(key), do: byte_size(key)
  def entry_bytes(_entry), do: 0
end
