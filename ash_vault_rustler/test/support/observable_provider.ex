defmodule AshVaultRustler.Test.ObservableProvider do
  @moduledoc """
  An `AshVault.KeyProvider` for tests that counts its calls and can be made to fail.

  `AshVault.KeyProviders.Memory` is a fine provider but it tells you nothing about how
  often it was asked, which is exactly the thing a cache test needs to assert. This one
  counts every call and can be put into an "outage" so the TTL-expiry-during-an-outage
  case can be written honestly.

  Backed by a single named `Agent`, because the `AshVault.KeyProvider` callbacks take no
  server name and a vault always talks to the default-named instance. Tests using it are
  therefore `async: false`.
  """

  @behaviour AshVault.KeyProvider

  use Agent

  @doc "Start the provider. `:key_bytes` defaults to 32."
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts \\ []) do
    Agent.start_link(
      fn ->
        %{
          keys: %{},
          current: %{},
          destroyed: MapSet.new(),
          calls: %{current_key: 0, get_key: 0, rotate: 0, destroy: 0},
          outage: false,
          key_bytes: Keyword.get(opts, :key_bytes, 32)
        }
      end,
      name: __MODULE__
    )
  end

  @doc "How many times each callback has been invoked."
  @spec calls() :: map()
  def calls, do: Agent.get(__MODULE__, & &1.calls)

  @doc "Reset the call counters."
  @spec reset_calls() :: :ok
  def reset_calls do
    Agent.update(__MODULE__, fn state ->
      %{state | calls: %{current_key: 0, get_key: 0, rotate: 0, destroy: 0}}
    end)
  end

  @doc "Make every call fail with `{:error, :provider_down}` until turned off."
  @spec outage(boolean()) :: :ok
  def outage(down?), do: Agent.update(__MODULE__, &%{&1 | outage: down?})

  @impl AshVault.KeyProvider
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: Agent.get(__MODULE__, & &1.key_bytes)

  @impl AshVault.KeyProvider
  def current_key(scope) do
    scope = validate_scope!(scope)

    Agent.get_and_update(__MODULE__, fn state ->
      state = count(state, :current_key)

      cond do
        state.outage ->
          {{:error, :provider_down}, state}

        MapSet.member?(state.destroyed, scope) ->
          {{:error, :destroyed}, state}

        true ->
          case Map.fetch(state.current, scope) do
            {:ok, version} ->
              {{:ok, info(state, scope, version)}, state}

            :error ->
              state = mint(state, scope, 1)
              {{:ok, info(state, scope, 1)}, state}
          end
      end
    end)
  end

  @impl AshVault.KeyProvider
  def get_key(scope, version) do
    scope = validate_scope!(scope)

    Agent.get_and_update(__MODULE__, fn state ->
      state = count(state, :get_key)

      cond do
        state.outage ->
          {{:error, :provider_down}, state}

        MapSet.member?(state.destroyed, scope) ->
          {{:error, :destroyed}, state}

        not (is_integer(version) and version > 0) ->
          {{:error, :not_found}, state}

        true ->
          case get_in(state.keys, [scope, version]) do
            %{key: key} -> {{:ok, key}, state}
            nil -> {{:error, :not_found}, state}
          end
      end
    end)
  end

  @impl AshVault.KeyProvider
  def rotate(scope) do
    scope = validate_scope!(scope)

    Agent.get_and_update(__MODULE__, fn state ->
      state = count(state, :rotate)

      cond do
        state.outage ->
          {{:error, :provider_down}, state}

        MapSet.member?(state.destroyed, scope) ->
          {{:error, :destroyed}, state}

        true ->
          next = Map.get(state.current, scope, 0) + 1
          {{:ok, next}, mint(state, scope, next)}
      end
    end)
  end

  @impl AshVault.KeyProvider
  def destroy(scope) do
    scope = validate_scope!(scope)

    Agent.get_and_update(__MODULE__, fn state ->
      state = count(state, :destroy)

      if state.outage do
        {{:error, :provider_down}, state}
      else
        {:ok,
         %{
           state
           | keys: Map.delete(state.keys, scope),
             current: Map.delete(state.current, scope),
             destroyed: MapSet.put(state.destroyed, scope)
         }}
      end
    end)
  end

  defp count(state, call), do: %{state | calls: Map.update!(state.calls, call, &(&1 + 1))}

  defp mint(state, scope, version) do
    entry = %{key: :crypto.strong_rand_bytes(state.key_bytes), created_at: DateTime.utc_now()}
    keys = Map.update(state.keys, scope, %{version => entry}, &Map.put(&1, version, entry))
    %{state | keys: keys, current: Map.put(state.current, scope, version)}
  end

  defp info(state, scope, version) do
    %{key: key, created_at: created_at} = get_in(state.keys, [scope, version])
    %{version: version, key: key, created_at: created_at}
  end

  defp validate_scope!(scope) when is_binary(scope), do: scope

  defp validate_scope!(scope) do
    raise ArgumentError, "#{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}"
  end
end
