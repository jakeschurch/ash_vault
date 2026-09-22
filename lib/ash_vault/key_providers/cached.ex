defmodule AshVault.KeyProviders.Cached do
  @moduledoc """
  An `AshVault.KeyProvider` that wraps another provider with a bounded, TTL'd key cache.

  Caching keys is a deliberate weakening of crypto-erasure, which is why it is off by
  default. Read this whole moduledoc before turning it on.

  ## Using it

  Almost always through the vault's `:cache` option, which desugars to this module:

      use AshVault.Vault, key_provider: MyApp.Keys, cache: true

      use AshVault.Vault,
        key_provider: MyApp.Keys,
        cache: [ttl: :timer.seconds(30), max_entries: 4_096,
                backend: AshVaultRustler.KeyCache]

  The wrapper is also public and supported, for when a provider needs to be shared
  between vaults or named explicitly:

      defmodule MyApp.CachedKeys do
        use AshVault.KeyProviders.Cached,
          provider: AshVault.KeyProviders.OpenBao,
          ttl: :timer.seconds(60)
      end

      use AshVault.Vault, key_provider: MyApp.CachedKeys

  Either way the generated module is an ordinary `AshVault.KeyProvider` and must be
  started, because it owns the cache:

      children = [MyApp.Vault.CachedKeyProvider]   # or MyApp.CachedKeys

  If it is *not* started, every read goes straight to the wrapped provider. Slower, and
  correct. A cache is allowed to fail to cache; it is never allowed to fail to serve.

  ## What this buys, exactly

  It removes the *long-lived* copy of a key from wherever the provider keeps it, and it
  removes one network round trip per operation. With `AshVaultRustler.KeyCache` as the
  backend, the authoritative copy lives outside the BEAM heap and eviction zeroes it.

  > #### What it does not buy {: .warning}
  >
  > `get_key/2` still returns a binary to the BEAM, so a transient copy of the key
  > exists on an Elixir process heap for every single encrypt and decrypt. This level
  > **bounds the window**; it does not eliminate the copy. Eliminating it needs the
  > opaque-handle path (`AshVault.Key` plus a cipher that can use one), which is a
  > separate, opt-in mechanism.
  >
  > The pure-Elixir backend (`AshVault.KeyCaches.ETS`, the default) additionally cannot
  > zero anything at all — an eviction drops a reference and the garbage collector
  > decides the rest. Its guarantee is the observable one: after `evict_scope/1`
  > returns, nothing can read that scope from the cache again.

  ## The TTL is your erasure SLA — but only for destroys routed through here

  This is the sentence to take away.

  `destroy/1` evicts the scope **synchronously on every connected node before it
  returns**, and fails if any node does not acknowledge. So an erasure performed through
  this provider — `AshVault.destroy_keys!/2`, the generic action, `mix
  ash_vault.destroy_keys` running in *this* BEAM — is immediate, not eventual.

  An erasure performed **out of band** is not. A `mix ash_vault.destroy_keys` in a
  separate node that is not clustered with the running app, an operator deleting a
  transit key in OpenBao by hand, another service revoking it — none of those call
  `evict_scope/1`, and this cache will keep serving the erased scope's key until the
  entry expires. For those, the TTL is the maximum time a destroyed tenant stays
  decryptable, with nothing underneath it. That number is what you can promise in a DPA.

  The default TTL is therefore **30 seconds**, for both the current key and historical
  versions. It is short enough to write down without qualification and long enough to
  collapse the per-operation round trip on any realistic request rate.

  Historical key *versions* are immutable in content, which tempts a long TTL — the
  spec that asked for this package suggests exactly that. They are not immutable in
  *existence*: a destroyed scope's v1 key must stop being served. The erasure SLA is
  `max(ttl, historical_ttl)`, so raising `:historical_ttl` raises the SLA. The default
  keeps them equal on purpose.

  ## The tombstone asymmetry

  The single most important rule in this module, stated as code would state it:

    * `{:error, :destroyed}` **is cached, without expiry.** Destruction is monotonic —
      a scope that is destroyed stays destroyed forever — so a cached tombstone can
      only ever be right, and caching it makes reads fail closed even when the provider
      is unreachable.
    * The **absence** of a tombstone is **never cached** as such. There is no "not
      destroyed" entry, ever.
    * `{:error, :not_found}` is never cached. A scope with no key at version N may have
      one at version N a moment later, and caching absence here would be the same
      mistake in a smaller costume.
    * Any other error — a transport failure, a provider outage — is never cached, in
      either direction. An outage is not an answer.

  Caching `{:ok, key}` is, strictly speaking, an implicit cache of "not destroyed", and
  pretending otherwise would be the fifth fail-open tombstone read in this project's
  history. What contains it is the two mechanisms above: synchronous cluster-wide
  eviction on the destroy path, and a short TTL as the floor for everything else.

  ## The generation fence

  A read that misses can race a `destroy/1` and repopulate the cache *after* the
  eviction, which would resurrect the scope for a full TTL. Every `fetch` returns the
  scope's generation; `evict_scope/1` bumps it; a `put` carrying a stale generation is
  dropped. `destroy/1` evicts both before and after the wrapped provider's destroy, so
  the only writes that can survive are ones that were already committed before the
  erasure began.

  ## Options

    * `:provider` — **required**, the wrapped `AshVault.KeyProvider`.
    * `:backend` — an `AshVault.KeyCache`, default `AshVault.KeyCaches.ETS`.
    * `:ttl` — milliseconds for the current key, default `30_000`.
    * `:historical_ttl` — milliseconds for a specific version, default `:ttl`.
    * `:max_entries` — default `1_024`. With `AshVaultRustler.KeyCache` this is the bound
      that matters operationally: that backend spends one **locked page** per cached key,
      so size it against `RLIMIT_MEMLOCK`, not against `:max_bytes`.
    * `:max_bytes` — default `1_048_576`. Counts key *bytes*, not pages.
    * `:cluster` — fan `evict_scope/1` out to `Node.list(:connected)`, default `true`.
    * `:evict_timeout` — milliseconds to wait for each node, default `5_000`.
  """

  require Logger

  @default_ttl 30_000
  @default_max_entries 1_024
  @default_max_bytes 1_048_576
  @default_evict_timeout 5_000

  @type opts :: %{
          provider: module(),
          backend: module(),
          cache_name: atom(),
          ttl: non_neg_integer(),
          historical_ttl: non_neg_integer(),
          max_entries: pos_integer(),
          max_bytes: pos_integer(),
          cluster: boolean(),
          evict_timeout: timeout()
        }

  @doc """
  The default TTL in milliseconds, `30_000`.

  Short on purpose: for an out-of-band erasure this is the whole erasure SLA. See the
  moduledoc.
  """
  @spec default_ttl() :: pos_integer()
  def default_ttl, do: @default_ttl

  @doc """
  Normalise and validate the wrapper's options into the map the runtime functions take.

  Raises `ArgumentError` with a message in the same voice as the vault's own option
  errors when the shape is wrong.
  """
  @spec build_opts!(module(), keyword()) :: opts()
  def build_opts!(cache_name, opts) when is_list(opts) do
    provider =
      Keyword.get(opts, :provider) ||
        raise ArgumentError, """
        `use AshVault.KeyProviders.Cached` requires a `:provider` to wrap.

            defmodule #{inspect(cache_name)} do
              use AshVault.KeyProviders.Cached, provider: MyApp.Keys
            end
        """

    unless is_atom(provider) do
      raise ArgumentError,
            "AshVault.KeyProviders.Cached `:provider` must be a module, got: #{inspect(provider)}"
    end

    ttl = positive_integer!(opts, :ttl, @default_ttl, cache_name)

    %{
      provider: provider,
      backend: Keyword.get(opts, :backend) || AshVault.KeyCaches.ETS,
      cache_name: cache_name,
      ttl: ttl,
      historical_ttl: positive_integer!(opts, :historical_ttl, ttl, cache_name),
      max_entries: positive_integer!(opts, :max_entries, @default_max_entries, cache_name),
      max_bytes: positive_integer!(opts, :max_bytes, @default_max_bytes, cache_name),
      cluster: Keyword.get(opts, :cluster, true),
      evict_timeout: positive_integer!(opts, :evict_timeout, @default_evict_timeout, cache_name)
    }
  end

  defp positive_integer!(opts, key, default, cache_name) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 ->
        value

      other ->
        raise ArgumentError, """
        #{inspect(cache_name)}: AshVault.KeyProviders.Cached `#{inspect(key)}` must be a
        positive integer of milliseconds, got: #{inspect(other)}
        """
    end
  end

  @doc false
  @spec child_spec_for(opts()) :: Supervisor.child_spec()
  def child_spec_for(opts) do
    opts.backend.child_spec(
      name: opts.cache_name,
      max_entries: opts.max_entries,
      max_bytes: opts.max_bytes
    )
  end

  @doc false
  @spec start_link(opts()) :: GenServer.on_start()
  def start_link(opts) do
    unless opts.backend.zeroes_on_evict?() do
      Logger.info(
        "AshVault: #{inspect(opts.cache_name)} is caching keys in " <>
          "#{inspect(opts.backend)}, which cannot zero key material on eviction — it " <>
          "drops a reference and the garbage collector decides the rest. Eviction is " <>
          "still synchronous and observable. Use AshVaultRustler.KeyCache for a backend " <>
          "that zeroes."
      )
    end

    opts.backend.start_link(
      name: opts.cache_name,
      max_entries: opts.max_entries,
      max_bytes: opts.max_bytes
    )
  end

  @doc """
  Fetch the current key for a scope, serving a live cache entry when there is one.
  """
  @spec current_key(AshVault.KeyProvider.scope(), opts()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope, opts) do
    scope = validate_scope!(scope)

    with :absent <- cached_tombstone(scope, opts),
         {:miss, generation} <- fetch(scope, :current, opts) do
      case opts.provider.current_key(scope) do
        {:ok, key_info} = ok ->
          cache_key_info(scope, key_info, generation, opts)
          ok

        {:error, :destroyed} = destroyed ->
          remember_tombstone(scope, opts)
          destroyed

        other ->
          other
      end
    else
      :destroyed -> {:error, :destroyed}
      {:ok, {:key_info, key_info}, _generation} -> {:ok, key_info}
    end
  end

  @doc """
  Fetch a specific key version for a scope.
  """
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version(), opts()) ::
          {:ok, binary()} | {:error, term()}
  def get_key(scope, version, opts) do
    scope = validate_scope!(scope)

    if cacheable_version?(version) do
      do_get_key(scope, version, opts)
    else
      # Never cached, in either direction: a bogus version is a caller bug, and the
      # wrapped provider owns the answer.
      opts.provider.get_key(scope, version)
    end
  end

  defp do_get_key(scope, version, opts) do
    with :absent <- cached_tombstone(scope, opts),
         {:miss, generation} <- fetch(scope, version, opts) do
      case opts.provider.get_key(scope, version) do
        {:ok, key} = ok when is_binary(key) ->
          put(scope, version, {:key, key}, opts.historical_ttl, generation, opts)
          ok

        {:error, :destroyed} = destroyed ->
          remember_tombstone(scope, opts)
          destroyed

        # `:not_found` is deliberately absent from this list. Caching "there is no key
        # at this version" is the same fail-open shape as caching "there is no
        # tombstone", one size down.
        other ->
          other
      end
    else
      :destroyed -> {:error, :destroyed}
      {:ok, {:key, key}, _generation} -> {:ok, key}
    end
  end

  @doc """
  Rotate the wrapped provider's key for a scope, then drop the scope from the cache.

  Eviction failures here are logged, not raised: a stale cached key after a rotation
  means writes keep using the previous version for up to one TTL, which is a
  performance and hygiene problem. Erasure is the case where a stale entry is a
  correctness failure, and `destroy/1` treats it as one.
  """
  @spec rotate(AshVault.KeyProvider.scope(), opts()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope, opts) do
    scope = validate_scope!(scope)

    case opts.provider.rotate(scope) do
      {:ok, version} ->
        case evict_scope(scope, opts) do
          :ok ->
            :ok

          {:error, reason} ->
            Logger.warning(
              "AshVault: #{inspect(opts.cache_name)} could not evict scope " <>
                "#{inspect(scope)} after rotation (#{inspect(reason)}); the previous key " <>
                "version may be used for up to #{opts.ttl}ms."
            )
        end

        {:ok, version}

      {:error, :destroyed} = destroyed ->
        remember_tombstone(scope, opts)
        destroyed

      other ->
        other
    end
  end

  @doc """
  Destroy the scope at the wrapped provider and evict it from every node's cache.

  Ordering, and why:

  1. Evict everywhere. Bumps the generation, so any read already in flight cannot write
     its result back.
  2. `provider.destroy/1`. If it fails, return the failure and cache nothing — no
     tombstone is recorded for an erasure that did not happen.
  3. Evict everywhere **again**, and require every node to acknowledge. A read that
     started between steps 1 and 2 saw a live key; this is what removes it. Returning
     `:ok` while a peer still holds the key is the worst outcome available, so a node
     that does not answer makes this return `{:error, {:cache_evict_failed, _}}` and
     `AshVault.Vault.Runtime.destroy!/2` raises.
  4. Only then record the tombstone locally, after the last eviction that would have
     wiped it. Peers have an empty cache and will read `:destroyed` from the provider.
  """
  @spec destroy(AshVault.KeyProvider.scope(), opts()) :: :ok | {:error, term()}
  def destroy(scope, opts) do
    scope = validate_scope!(scope)

    _ = evict_scope(scope, opts)

    case opts.provider.destroy(scope) do
      :ok ->
        case evict_scope(scope, opts) do
          :ok ->
            remember_tombstone(scope, opts)
            :ok

          {:error, reason} ->
            {:error, {:cache_evict_failed, reason}}
        end

      other ->
        other
    end
  end

  @doc """
  Synchronously drop a scope from this cache on every connected node.

  Returns `{:error, {:nodes_failed, [{node, reason}]}}` if any node does not
  acknowledge. Nodes that join *after* this returns have a cold cache and cannot hold a
  stale entry, so they need no handling.
  """
  @spec evict_scope(AshVault.KeyProvider.scope(), opts()) :: :ok | {:error, term()}
  def evict_scope(scope, opts) do
    scope = validate_scope!(scope)

    local = opts.backend.evict_scope(opts.cache_name, scope)

    remote =
      if opts.cluster do
        evict_remote(scope, opts)
      else
        []
      end

    failures =
      case local do
        :ok -> remote
        {:error, reason} -> [{node(), reason} | remote]
      end

    if failures == [], do: :ok, else: {:error, {:nodes_failed, failures}}
  end

  # `Node.list(:connected)` rather than `Node.list/0`: the latter omits hidden nodes,
  # and a hidden node running the same release holds exactly the same cache.
  defp evict_remote(scope, opts) do
    nodes = Node.list(:connected)

    if nodes == [] do
      []
    else
      results =
        :erpc.multicall(
          nodes,
          opts.backend,
          :evict_scope,
          [opts.cache_name, scope],
          opts.evict_timeout
        )

      classify_evictions(results, nodes)
    end
  end

  @doc """
  Turn `:erpc.multicall/5` results into a list of `{node, reason}` failures.

  Public because it is the branch that decides whether a `destroy!` is allowed to report
  success, and a single-node test suite never reaches it through `evict_scope/1` —
  `Node.list(:connected)` is empty, so the whole fan-out is skipped. Calling it directly
  with synthetic `:erpc` shapes is the only way to cover it without standing up a cluster.

  **Anything that is not a positive `{:ok, :ok}` is a failure.** Not "probably fine", not
  "the node is probably down anyway": a node that did not say it evicted the key is a node
  that may still be serving it.
  """
  @spec classify_evictions([term()], [node()]) :: [{node(), term()}]
  def classify_evictions(results, nodes) do
    results
    |> Enum.zip(nodes)
    |> Enum.flat_map(fn
      {{:ok, :ok}, _node} -> []
      {{:ok, {:error, reason}}, node} -> [{node, reason}]
      {{:ok, other}, node} -> [{node, {:unexpected, other}}]
      {{kind, reason}, node} -> [{node, {kind, reason}}]
      {{kind, reason, _stack}, node} -> [{node, {kind, reason}}]
      {other, node} -> [{node, {:unexpected, other}}]
    end)
  end

  @doc """
  The key size the wrapped provider mints.
  """
  @spec key_bytes(opts()) :: pos_integer()
  def key_bytes(opts), do: AshVault.KeyProvider.key_bytes(opts.provider)

  defp fetch(scope, slot, opts), do: opts.backend.fetch(opts.cache_name, scope, slot)

  defp put(scope, slot, entry, ttl, generation, opts) do
    opts.backend.put(opts.cache_name, scope, slot, entry, ttl, generation)
  end

  # Returns `:destroyed` for a cached tombstone and `:absent` otherwise. `:absent` means
  # "this cache has nothing to say", never "this scope is not destroyed" — the wrapped
  # provider is always consulted.
  defp cached_tombstone(scope, opts) do
    case fetch(scope, :tombstone, opts) do
      {:ok, :destroyed, _generation} -> :destroyed
      _other -> :absent
    end
  end

  defp remember_tombstone(scope, opts) do
    {_result, generation} =
      case fetch(scope, :tombstone, opts) do
        {:ok, entry, generation} -> {entry, generation}
        {:miss, generation} -> {nil, generation}
      end

    # `:infinity`: destruction is monotonic, so this entry can only ever be right, and
    # keeping it means reads stay fail-closed even if the provider goes away.
    put(scope, :tombstone, :destroyed, :infinity, generation, opts)
    :ok
  end

  defp cache_key_info(scope, key_info, generation, opts) do
    if is_binary(Map.get(key_info, :key)) do
      put(scope, :current, {:key_info, key_info}, opts.ttl, generation, opts)

      # The same bytes are also the answer to `get_key(scope, version)`, so seed that
      # slot too rather than making the next decrypt pay a round trip for a key the
      # cache already holds.
      case key_info do
        %{version: version, key: key} when is_integer(version) and version > 0 ->
          {_, version_generation} =
            case fetch(scope, version, opts) do
              {:ok, entry, gen} -> {entry, gen}
              {:miss, gen} -> {nil, gen}
            end

          put(scope, version, {:key, key}, opts.historical_ttl, version_generation, opts)

        _other ->
          :ok
      end
    end

    :ok
  end

  defp cacheable_version?(version), do: is_integer(version) and version > 0

  defp validate_scope!(scope) when is_binary(scope), do: scope

  defp validate_scope!(scope) do
    raise ArgumentError, """
    #{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}.

    Scopes reach a key provider already normalised to a binary by the vault's
    `AshVault.Scope` implementation.
    """
  end

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour AshVault.KeyProvider

      @ash_vault_cached_opts AshVault.KeyProviders.Cached.build_opts!(__MODULE__, opts)

      @doc "Start this provider's key cache."
      @spec start_link(keyword()) :: GenServer.on_start()
      def start_link(_opts \\ []),
        do: AshVault.KeyProviders.Cached.start_link(@ash_vault_cached_opts)

      @doc false
      @spec child_spec(term()) :: Supervisor.child_spec()
      def child_spec(_opts \\ []),
        do: AshVault.KeyProviders.Cached.child_spec_for(@ash_vault_cached_opts)

      @doc "Fetch the current key for a scope, through the cache."
      @impl AshVault.KeyProvider
      @spec current_key(AshVault.KeyProvider.scope()) ::
              {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
      def current_key(scope),
        do: AshVault.KeyProviders.Cached.current_key(scope, @ash_vault_cached_opts)

      @doc "Fetch a specific key version for a scope, through the cache."
      @impl AshVault.KeyProvider
      @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
              {:ok, binary()} | {:error, term()}
      def get_key(scope, version),
        do: AshVault.KeyProviders.Cached.get_key(scope, version, @ash_vault_cached_opts)

      @doc "Rotate the wrapped provider's key and evict the scope."
      @impl AshVault.KeyProvider
      @spec rotate(AshVault.KeyProvider.scope()) ::
              {:ok, AshVault.KeyProvider.version()} | {:error, term()}
      def rotate(scope), do: AshVault.KeyProviders.Cached.rotate(scope, @ash_vault_cached_opts)

      @doc """
      Destroy the scope, evicting it cluster-wide before reporting success.
      """
      @impl AshVault.KeyProvider
      @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
      def destroy(scope), do: AshVault.KeyProviders.Cached.destroy(scope, @ash_vault_cached_opts)

      @doc "The key size the wrapped provider mints."
      @impl AshVault.KeyProvider
      @spec key_bytes() :: pos_integer()
      def key_bytes, do: AshVault.KeyProviders.Cached.key_bytes(@ash_vault_cached_opts)

      @doc """
      Synchronously evict a scope from this cache on every connected node.
      """
      @spec evict_scope(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
      def evict_scope(scope),
        do: AshVault.KeyProviders.Cached.evict_scope(scope, @ash_vault_cached_opts)

      @doc "This provider's resolved cache configuration."
      @spec __ash_vault_cached__() :: map()
      def __ash_vault_cached__, do: @ash_vault_cached_opts
    end
  end
end
