defmodule AshVault.Test.Support.KeyProviderCases do
  @moduledoc """
  The shared `AshVault.KeyProvider` contract suite.

  Every provider — `AshVault.KeyProviders.Memory`, and later the filesystem and OpenBao
  providers — must satisfy exactly these cases, so they live here once instead of being
  re-written per provider.

  ## Usage

      defmodule MyProviderTest do
        use ExUnit.Case, async: true
        use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_provider/1

        def start_provider(_context) do
          name = :"provider_\#{System.unique_integer([:positive])}"
          start_supervised!({MyProvider, name: name})

          %{
            provider: {MyProvider, name},
            scope: fn -> "scope_\#{System.unique_integer([:positive])}" end
          }
        end
      end

  The setup callback receives the ExUnit context and must return a map with:

    * `:provider` — the provider module, or `{module, server}` when the started instance
      is not the default-named one. The `AshVault.KeyProvider` callbacks take no server
      name, so the tuple form is dispatched to the provider's `name`-taking variants.
    * `:scope` — a zero-arity function generating a fresh, unused scope.
    * `:key_bytes` — optional, the key size the provider mints. Defaults to 32.
  """

  @doc false
  defmacro __using__(opts) do
    setup_fun = Keyword.fetch!(opts, :setup)

    quote do
      import AshVault.Test.Support.KeyProviderCases,
        only: [current_key: 2, get_key: 3, rotate: 2, destroy: 2]

      setup context do
        unquote(setup_fun).(context)
      end

      describe "key provider contract" do
        test "first current_key mints version 1", %{provider: provider, scope: scope} = context do
          scope = scope.()
          key_bytes = Map.get(context, :key_bytes, 32)

          assert {:ok, key_info} = current_key(provider, scope)
          assert key_info.version == 1
          assert is_binary(key_info.key)
          assert byte_size(key_info.key) == key_bytes
          assert %DateTime{} = key_info.created_at
        end

        test "current_key is stable across calls", %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, first} = current_key(provider, scope)
          assert {:ok, second} = current_key(provider, scope)
          assert first == second
        end

        test "different scopes get different keys", %{provider: provider, scope: scope} do
          assert {:ok, a} = current_key(provider, scope.())
          assert {:ok, b} = current_key(provider, scope.())
          assert a.key != b.key
        end

        test "rotate mints v2 and v1 stays fetchable", %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, %{version: 1, key: v1_key}} = current_key(provider, scope)
          assert {:ok, 2} = rotate(provider, scope)
          assert {:ok, %{version: 2, key: v2_key}} = current_key(provider, scope)
          assert v1_key != v2_key

          assert {:ok, ^v1_key} = get_key(provider, scope, 1)
          assert {:ok, ^v2_key} = get_key(provider, scope, 2)
        end

        test "get_key for an unknown version returns :not_found",
             %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, _} = current_key(provider, scope)
          assert {:error, :not_found} = get_key(provider, scope, 99)
        end

        test "get_key on an unknown scope returns :not_found",
             %{provider: provider, scope: scope} do
          assert {:error, :not_found} = get_key(provider, scope.(), 1)
        end

        test "destroy makes current_key and get_key both :destroyed",
             %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, %{version: 1}} = current_key(provider, scope)
          assert :ok = destroy(provider, scope)

          assert {:error, :destroyed} = current_key(provider, scope)
          assert {:error, :destroyed} = get_key(provider, scope, 1)
          assert {:error, :destroyed} = get_key(provider, scope, 99)
        end

        test "destroy is idempotent", %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, _} = current_key(provider, scope)
          assert :ok = destroy(provider, scope)
          assert :ok = destroy(provider, scope)
          assert {:error, :destroyed} = current_key(provider, scope)
        end

        test "destroy works on a scope that never had a key",
             %{provider: provider, scope: scope} do
          scope = scope.()

          assert :ok = destroy(provider, scope)
          assert {:error, :destroyed} = current_key(provider, scope)
        end

        test "a destroyed scope never re-mints", %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, _} = current_key(provider, scope)
          assert :ok = destroy(provider, scope)

          for _ <- 1..5 do
            assert {:error, :destroyed} = current_key(provider, scope)
          end

          assert {:error, :destroyed} = rotate(provider, scope)
        end

        test "destroying one scope leaves others untouched",
             %{provider: provider, scope: scope} do
          destroyed = scope.()
          kept = scope.()

          assert {:ok, _} = current_key(provider, destroyed)
          assert {:ok, %{key: kept_key}} = current_key(provider, kept)
          assert :ok = destroy(provider, destroyed)

          assert {:error, :destroyed} = current_key(provider, destroyed)
          assert {:ok, %{key: ^kept_key}} = current_key(provider, kept)
        end
      end
    end
  end

  @doc "Call `current_key/1` on a provider module or `{module, server}` pair."
  @spec current_key(module() | {module(), GenServer.server()}, term()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key({module, server}, scope), do: module.current_key(server, scope)
  def current_key(module, scope), do: module.current_key(scope)

  @doc "Call `get_key/2` on a provider module or `{module, server}` pair."
  @spec get_key(module() | {module(), GenServer.server()}, term(), non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def get_key({module, server}, scope, version), do: module.get_key(server, scope, version)
  def get_key(module, scope, version), do: module.get_key(scope, version)

  @doc "Call `rotate/1` on a provider module or `{module, server}` pair."
  @spec rotate(module() | {module(), GenServer.server()}, term()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def rotate({module, server}, scope), do: module.rotate(server, scope)
  def rotate(module, scope), do: module.rotate(scope)

  @doc "Call `destroy/1` on a provider module or `{module, server}` pair."
  @spec destroy(module() | {module(), GenServer.server()}, term()) :: :ok | {:error, term()}
  def destroy({module, server}, scope), do: module.destroy(server, scope)
  def destroy(module, scope), do: module.destroy(scope)
end
