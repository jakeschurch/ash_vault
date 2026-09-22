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

  `destroy/1` wipes the scope's key material and records a permanent tombstone. Both
  `current_key/1` and `get_key/2` return `{:error, :destroyed}` afterwards, for the life
  of the process. Destroying twice is idempotent.

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
    :ash_vault
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:key_bytes, @default_key_bytes)
  end

  @doc """
  Fetch the current key for a scope, minting version 1 on first use.
  """
  @impl AshVault.KeyProvider
  @spec current_key(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope), do: call(__MODULE__, {:current_key, validate_scope!(scope)})

  @doc """
  Fetch a specific key version for a scope.
  """
  @impl AshVault.KeyProvider
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version), do: call(__MODULE__, {:get_key, validate_scope!(scope), version})

  @doc """
  Mint the next key version for a scope, keeping previous versions fetchable.
  """
  @impl AshVault.KeyProvider
  @spec rotate(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope), do: call(__MODULE__, {:rotate, validate_scope!(scope)})

  @doc """
  Irreversibly destroy every key for a scope and tombstone it.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope), do: call(__MODULE__, {:destroy, validate_scope!(scope)})

  @doc """
  Same as `current_key/1`, against an explicitly named instance.
  """
  @spec current_key(GenServer.server(), AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(server, scope), do: call(server, {:current_key, validate_scope!(scope)})

  @doc """
  Same as `get_key/2`, against an explicitly named instance.
  """
  @spec get_key(GenServer.server(), AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(server, scope, version),
    do: call(server, {:get_key, validate_scope!(scope), version})

  @doc """
  Same as `rotate/1`, against an explicitly named instance.
  """
  @spec rotate(GenServer.server(), AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(server, scope), do: call(server, {:rotate, validate_scope!(scope)})

  @doc """
  Same as `destroy/1`, against an explicitly named instance.
  """
  @spec destroy(GenServer.server(), AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(server, scope), do: call(server, {:destroy, validate_scope!(scope)})

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

  @impl GenServer
  def init(opts) do
    {:ok,
     %{
       keys: %{},
       current: %{},
       destroyed: MapSet.new(),
       key_bytes: Keyword.get(opts, :key_bytes, key_bytes())
     }}
  end

  @impl GenServer
  def handle_call({:current_key, scope}, _from, state) do
    if destroyed?(state, scope) do
      {:reply, {:error, :destroyed}, state}
    else
      case Map.fetch(state.current, scope) do
        {:ok, version} ->
          {:reply, {:ok, key_info(state, scope, version)}, state}

        :error ->
          {state, version} = mint(state, scope, 1)
          {:reply, {:ok, key_info(state, scope, version)}, state}
      end
    end
  end

  def handle_call({:get_key, scope, version}, _from, state) do
    cond do
      destroyed?(state, scope) ->
        {:reply, {:error, :destroyed}, state}

      not (is_integer(version) and version > 0) ->
        {:reply, {:error, :not_found}, state}

      true ->
        case get_in(state.keys, [scope, version]) do
          %{key: key} -> {:reply, {:ok, key}, state}
          nil -> {:reply, {:error, :not_found}, state}
        end
    end
  end

  def handle_call({:rotate, scope}, _from, state) do
    if destroyed?(state, scope) do
      {:reply, {:error, :destroyed}, state}
    else
      next = Map.get(state.current, scope, 0) + 1
      {state, version} = mint(state, scope, next)
      {:reply, {:ok, version}, state}
    end
  end

  def handle_call({:destroy, scope}, _from, state) do
    state = %{
      state
      | keys: Map.delete(state.keys, scope),
        current: Map.delete(state.current, scope),
        destroyed: MapSet.put(state.destroyed, scope)
    }

    {:reply, :ok, state}
  end

  # Without this, a crash in this process emits a SASL report carrying every scope's
  # raw key bytes into the logs and into any APM handler attached to them.
  @impl GenServer
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{} = state -> %{state | keys: :redacted}
      other -> other
    end)
  end

  defp destroyed?(state, scope), do: MapSet.member?(state.destroyed, scope)

  defp mint(state, scope, version) do
    entry = %{key: :crypto.strong_rand_bytes(state.key_bytes), created_at: DateTime.utc_now()}

    keys =
      Map.update(state.keys, scope, %{version => entry}, &Map.put(&1, version, entry))

    {%{state | keys: keys, current: Map.put(state.current, scope, version)}, version}
  end

  defp key_info(state, scope, version) do
    %{key: key, created_at: created_at} = get_in(state.keys, [scope, version])
    %{version: version, key: key, created_at: created_at}
  end
end
