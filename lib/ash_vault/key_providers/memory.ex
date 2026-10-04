defmodule AshVault.KeyProviders.Memory do
  @moduledoc """
  An in-memory `AshVault.KeyProvider`, backed by a `GenServer`.

  > #### Development and test only {: .warning}
  >
  > Every key lives in process memory and dies with the process. There is no
  > persistence, no replication and no protection of the key material at rest.
  > **Never use this provider in production** — losing the process means losing every
  > key, which means losing every encrypted value.

  ## Adding it to your supervision tree

  AshVault deliberately does **not** start this provider for you: applications opt in.
  Add it to your own supervisor, usually only outside production:

      # config/dev.exs and config/test.exs
      config :my_app, start_memory_key_provider?: true

      # lib/my_app/application.ex — a runtime flag, not `Mix.env/0`, because `Mix` is
      # not available in a release.
      children =
        [MyApp.Repo] ++
          if Application.get_env(:my_app, :start_memory_key_provider?, false) do
            [AshVault.KeyProviders.Memory]
          else
            []
          end

      Supervisor.start_link(children, strategy: :one_for_one)

  It registers under its own module name by default. Pass `name:` to run several
  instances (for example one per test):

      start_supervised!({AshVault.KeyProviders.Memory, name: :my_provider})

  Note that the `AshVault.KeyProvider` callbacks take no process name, so a vault always
  talks to the default-named instance.

  ## Configuration

      config :ash_vault, AshVault.KeyProviders.Memory, key_bytes: 32

  ## Destruction semantics

  `destroy/1` wipes the scope's key material — the `:data` and `:mac` keyrings and the
  lookup key alike — and records a permanent tombstone. Every `current_key`, `get_key`
  and `rotate`, for either purpose, and `lookup_key/1` return `{:error, :destroyed}`
  afterwards, for the life of the process. Destroying twice is idempotent.

  ## Purposes

  Serves both `:data` and `:mac` (see *Purposes* in `AshVault.KeyProvider`). The two
  keyrings are separate maps of separately drawn random bytes, rotated independently.

  ## Scopes

  Scopes must be binaries, matching `AshVault.KeyProviders.Local` and
  `AshVault.KeyProviders.OpenBao`. A non-binary scope raises `ArgumentError`: a provider
  that silently accepted arbitrary terms would let a custom `AshVault.Scope` pass tests
  here and then behave differently — or unsafely — in production.

  ## Key material never reaches a crash report

  `format_status/1` redacts the key table. Without it, any crash in this `GenServer`
  emits a SASL report containing every scope's raw key bytes, straight into the log
  aggregator and any APM handler attached to it.
  """

  @behaviour AshVault.KeyProvider

  use GenServer

  @default_key_bytes 32

  @doc """
  Start the provider.

  Accepts `:name` (defaults to this module) and `:key_bytes`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  The key size in bytes this provider mints, from config, defaulting to 32.
  """
  @impl AshVault.KeyProvider
  @spec key_bytes() :: pos_integer()
  def key_bytes do
    __MODULE__
    |> AshVault.KeyProvider.config()
    |> Keyword.get(:key_bytes, @default_key_bytes)
  end

  @doc """
  The purposes this provider serves: `[:data, :mac]`.
  """
  @impl AshVault.KeyProvider
  @spec purposes() :: [AshVault.KeyProvider.purpose()]
  def purposes, do: [:data, :mac]

  @doc """
  Fetch the current `:data` key for a scope, minting version 1 on first use.
  """
  @impl AshVault.KeyProvider
  @spec current_key(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope), do: call(__MODULE__, {:current_key, validate_scope!(scope), :data})

  @doc """
  Two forms, told apart by the first argument — a scope is always a binary, a server
  never is:

    * `current_key(scope, purpose)` — the `c:AshVault.KeyProvider.current_key/2`
      callback, against the default-named instance;
    * `current_key(server, scope)` — `current_key/1` against an explicitly named
      instance.
  """
  @impl AshVault.KeyProvider
  @spec current_key(
          AshVault.KeyProvider.scope() | GenServer.server(),
          AshVault.KeyProvider.purpose() | AshVault.KeyProvider.scope()
        ) :: {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope, purpose) when is_binary(scope),
    do: call(__MODULE__, {:current_key, scope, validate_purpose!(purpose)})

  def current_key(server, scope),
    do: call(server, {:current_key, validate_server_scope!(server, scope), :data})

  @doc """
  Same as `current_key/2` for a purpose, against an explicitly named instance.
  """
  @spec current_key(
          GenServer.server(),
          AshVault.KeyProvider.scope(),
          AshVault.KeyProvider.purpose()
        ) :: {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(server, scope, purpose),
    do: call(server, {:current_key, validate_scope!(scope), validate_purpose!(purpose)})

  @doc """
  Fetch a specific `:data` key version for a scope.
  """
  @impl AshVault.KeyProvider
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version),
    do: call(__MODULE__, {:get_key, validate_scope!(scope), version, :data})

  @doc """
  Two forms, told apart by the first argument:

    * `get_key(scope, version, purpose)` — the `c:AshVault.KeyProvider.get_key/3`
      callback, against the default-named instance;
    * `get_key(server, scope, version)` — `get_key/2` against a named instance.
  """
  @impl AshVault.KeyProvider
  @spec get_key(term(), term(), term()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version, purpose) when is_binary(scope),
    do: call(__MODULE__, {:get_key, scope, version, validate_purpose!(purpose)})

  def get_key(server, scope, version),
    do: call(server, {:get_key, validate_scope!(scope), version, :data})

  @doc """
  Same as `get_key/3` for a purpose, against an explicitly named instance.
  """
  @spec get_key(
          GenServer.server(),
          AshVault.KeyProvider.scope(),
          AshVault.KeyProvider.version(),
          AshVault.KeyProvider.purpose()
        ) :: {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(server, scope, version, purpose),
    do: call(server, {:get_key, validate_scope!(scope), version, validate_purpose!(purpose)})

  @doc """
  Mint the next `:data` key version for a scope, keeping previous versions fetchable.
  """
  @impl AshVault.KeyProvider
  @spec rotate(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope), do: call(__MODULE__, {:rotate, validate_scope!(scope), :data})

  @doc """
  Two forms, told apart by the first argument:

    * `rotate(scope, purpose)` — the `c:AshVault.KeyProvider.rotate/2` callback;
    * `rotate(server, scope)` — `rotate/1` against a named instance.
  """
  @impl AshVault.KeyProvider
  @spec rotate(term(), term()) :: {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope, purpose) when is_binary(scope),
    do: call(__MODULE__, {:rotate, scope, validate_purpose!(purpose)})

  def rotate(server, scope),
    do: call(server, {:rotate, validate_server_scope!(server, scope), :data})

  @doc """
  Same as `rotate/2` for a purpose, against an explicitly named instance.
  """
  @spec rotate(GenServer.server(), AshVault.KeyProvider.scope(), AshVault.KeyProvider.purpose()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(server, scope, purpose),
    do: call(server, {:rotate, validate_scope!(scope), validate_purpose!(purpose)})

  @doc """
  Irreversibly destroy every key for a scope — every purpose, and the lookup key — and
  tombstone it.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope), do: call(__MODULE__, {:destroy, validate_scope!(scope)})

  @doc """
  Fetch the scope's stable lookup key, minting it on first use.

  A separate map, never touched by `rotate/1` and wiped by `destroy/1`. See
  `c:AshVault.KeyProvider.lookup_key/1` for why it must not move.
  """
  @impl AshVault.KeyProvider
  @spec lookup_key(AshVault.KeyProvider.scope()) :: {:ok, binary()} | {:error, term()}
  def lookup_key(scope), do: call(__MODULE__, {:lookup_key, validate_scope!(scope)})

  @doc """
  Same as `destroy/1`, against an explicitly named instance.
  """
  @spec destroy(GenServer.server(), AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(server, scope), do: call(server, {:destroy, validate_scope!(scope)})

  @doc """
  Same as `lookup_key/1`, against an explicitly named instance.
  """
  @spec lookup_key(GenServer.server(), AshVault.KeyProvider.scope()) ::
          {:ok, binary()} | {:error, term()}
  def lookup_key(server, scope), do: call(server, {:lookup_key, validate_scope!(scope)})

  defp call(server, message) do
    GenServer.call(server, message)
  catch
    :exit, reason -> {:error, {:provider_unavailable, reason}}
  end

  defp validate_scope!(scope) when is_binary(scope), do: scope

  defp validate_scope!(scope) do
    raise ArgumentError, """
    #{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}.

    Scopes reach a key provider already normalised to a binary by the vault's
    `AshVault.Scope` implementation.
    """
  end

  # `current_key(:not_a_scope, :mac)` lands in the named-server clause, because its first
  # argument is not a binary. Report the term the caller meant as a scope, not the purpose.
  defp validate_server_scope!(server, scope) when scope in [:data, :mac],
    do: validate_scope!(server)

  defp validate_server_scope!(_server, scope), do: validate_scope!(scope)

  defp validate_purpose!(purpose) when purpose in [:data, :mac], do: purpose

  defp validate_purpose!(purpose) do
    raise ArgumentError,
          "#{inspect(__MODULE__)} purposes are :data and :mac, got: #{inspect(purpose)}"
  end

  @impl GenServer
  def init(opts) do
    {:ok,
     %{
       keys: %{},
       current: %{},
       mac_keys: %{},
       mac_current: %{},
       lookup: %{},
       destroyed: MapSet.new(),
       key_bytes: Keyword.get(opts, :key_bytes, key_bytes())
     }}
  end

  @impl GenServer
  def handle_call({:current_key, scope, purpose}, _from, state) do
    if destroyed?(state, scope) do
      {:reply, {:error, :destroyed}, state}
    else
      {keys, current} = fields(purpose)

      case Map.fetch(Map.fetch!(state, current), scope) do
        {:ok, version} ->
          {:reply, {:ok, key_info(state, keys, scope, version)}, state}

        :error ->
          {state, version} = mint(state, purpose, scope, 1)
          {:reply, {:ok, key_info(state, keys, scope, version)}, state}
      end
    end
  end

  def handle_call({:get_key, scope, version, purpose}, _from, state) do
    {keys, _current} = fields(purpose)

    cond do
      destroyed?(state, scope) ->
        {:reply, {:error, :destroyed}, state}

      not (is_integer(version) and version > 0) ->
        {:reply, {:error, :not_found}, state}

      true ->
        case get_in(Map.fetch!(state, keys), [scope, version]) do
          %{key: key} -> {:reply, {:ok, key}, state}
          nil -> {:reply, {:error, :not_found}, state}
        end
    end
  end

  def handle_call({:rotate, scope, purpose}, _from, state) do
    if destroyed?(state, scope) do
      {:reply, {:error, :destroyed}, state}
    else
      {_keys, current} = fields(purpose)
      next = Map.get(Map.fetch!(state, current), scope, 0) + 1
      {state, version} = mint(state, purpose, scope, next)
      {:reply, {:ok, version}, state}
    end
  end

  # `rotate/1` deliberately has no clause here: the lookup key is minted once and never
  # moves. Rotating it would make every token already in the database stop matching,
  # with nothing raised anywhere.
  def handle_call({:lookup_key, scope}, _from, state) do
    if destroyed?(state, scope) do
      {:reply, {:error, :destroyed}, state}
    else
      case Map.fetch(state.lookup, scope) do
        {:ok, key} ->
          {:reply, {:ok, key}, state}

        :error ->
          key = :crypto.strong_rand_bytes(state.key_bytes)
          {:reply, {:ok, key}, %{state | lookup: Map.put(state.lookup, scope, key)}}
      end
    end
  end

  def handle_call({:destroy, scope}, _from, state) do
    state = %{
      state
      | keys: Map.delete(state.keys, scope),
        current: Map.delete(state.current, scope),
        mac_keys: Map.delete(state.mac_keys, scope),
        mac_current: Map.delete(state.mac_current, scope),
        lookup: Map.delete(state.lookup, scope),
        destroyed: MapSet.put(state.destroyed, scope)
    }

    {:reply, :ok, state}
  end

  # Without this, a crash in this process emits a SASL report carrying every scope's
  # raw key bytes into the logs and into any APM handler attached to them.
  @impl GenServer
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{} = state -> %{state | keys: :redacted, mac_keys: :redacted, lookup: :redacted}
      other -> other
    end)
  end

  defp destroyed?(state, scope), do: MapSet.member?(state.destroyed, scope)

  # Two keyrings, two pairs of maps. A `:mac` key is minted from its own random bytes at
  # the fixed MAC key size — never the data key, never derived from it.
  defp fields(:data), do: {:keys, :current}
  defp fields(:mac), do: {:mac_keys, :mac_current}

  defp key_size(state, :data), do: state.key_bytes
  defp key_size(_state, :mac), do: AshVault.KeyProvider.mac_key_bytes()

  defp mint(state, purpose, scope, version) do
    {keys, current} = fields(purpose)

    entry = %{
      key: :crypto.strong_rand_bytes(key_size(state, purpose)),
      created_at: DateTime.utc_now()
    }

    ring =
      state
      |> Map.fetch!(keys)
      |> Map.update(scope, %{version => entry}, &Map.put(&1, version, entry))

    state =
      state
      |> Map.put(keys, ring)
      |> Map.put(current, Map.put(Map.fetch!(state, current), scope, version))

    {state, version}
  end

  defp key_info(state, keys, scope, version) do
    %{key: key, created_at: created_at} = get_in(Map.fetch!(state, keys), [scope, version])
    %{version: version, key: key, created_at: created_at}
  end
end
