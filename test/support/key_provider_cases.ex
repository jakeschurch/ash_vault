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
    * `:opaque_keys?` — optional, `true` for a provider that serves `AshVault.Key`
      handles rather than raw bytes (`AshVault.KeyProviders.OpenBaoTransit`). Defaults
      to `false`.

  The `use` itself takes `mac: false` for a provider that serves only the `:data`
  purpose; by default the `:mac` purpose contract runs too, and every provider AshVault
  ships passes it.

  ## Non-exporting providers

  Exactly **one** case in this suite is about raw bytes: "first current_key mints
  version 1" asserts `is_binary/1` and the key size. `opaque_keys?: true` swaps that
  assertion for `AshVault.Key.opaque?/1` and leaves every other case running verbatim —
  including the three that compare keys for equality, which a non-exporting provider
  still satisfies because its handles are deterministic functions of scope and version.

  Nothing else in the contract is waived. A provider that never exports key material
  still has to mint at v1, stay stable across calls, differ per scope, keep old versions
  fetchable after a rotation, refuse unknown and non-integer versions, reject non-binary
  scopes, tombstone on destroy, and never re-mint behind a tombstone.
  """

  @doc false
  defmacro __using__(opts) do
    setup_fun = Keyword.fetch!(opts, :setup)
    mac? = Keyword.get(opts, :mac, true)

    quote do
      import AshVault.Test.Support.KeyProviderCases,
        only: [
          module_of: 1,
          current_key: 2,
          current_key: 3,
          get_key: 3,
          get_key: 4,
          rotate: 2,
          rotate: 3,
          destroy: 2
        ]

      setup context do
        unquote(setup_fun).(context)
      end

      describe "key provider contract" do
        test "first current_key mints version 1", %{provider: provider, scope: scope} = context do
          scope = scope.()
          key_bytes = Map.get(context, :key_bytes, 32)

          assert {:ok, key_info} = current_key(provider, scope)
          assert key_info.version == 1
          assert %DateTime{} = key_info.created_at

          # The one assertion a non-exporting provider cannot make. It has no bytes to
          # hand over — that is the entire point — so it is held to "this is a usable
          # opaque handle" instead. Every other case in this suite runs unchanged.
          if Map.get(context, :opaque_keys?, false) do
            assert AshVault.Key.opaque?(key_info.key)
            assert AshVault.Key.key?(key_info.key)
            refute is_binary(key_info.key)
          else
            assert is_binary(key_info.key)
            assert byte_size(key_info.key) == key_bytes
          end
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

        # Finding 9. Local raised, Memory accepted any term, and OpenBao ran
        # `:erlang.term_to_binary/1` — making BOTH the transit key name and the
        # tombstone path functions of the OTP external term format. An OTP encoding
        # change relocates the tombstone (scope resurrects with a fresh key) and the
        # key name (every existing ciphertext becomes KeyNotFound).
        test "a non-binary scope is rejected identically by every provider",
             %{provider: provider} do
          for bad <- [:atom, 42, {:tuple, 1}, %{a: 1}, ["list"], nil] do
            assert_raise ArgumentError, ~r/must be binaries/, fn ->
              current_key(provider, bad)
            end

            assert_raise ArgumentError, ~r/must be binaries/, fn ->
              get_key(provider, bad, 1)
            end

            assert_raise ArgumentError, ~r/must be binaries/, fn -> rotate(provider, bad) end
            assert_raise ArgumentError, ~r/must be binaries/, fn -> destroy(provider, bad) end
          end
        end

        test "rotate on a scope that has never been used returns {:ok, 1}",
             %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, 1} = rotate(provider, scope)
          assert {:ok, %{version: 1}} = current_key(provider, scope)
          assert {:ok, 2} = rotate(provider, scope)
        end

        # Finding 15 / P2 #18: version is part of the public API, and a provider must
        # not read a file (or an endpoint) named by an unvalidated term.
        test "a zero, negative or non-integer version is :not_found",
             %{provider: provider, scope: scope} do
          scope = scope.()
          assert {:ok, _} = current_key(provider, scope)

          for version <- [0, -1, -99, :one, 1.5, "1", "../../etc/passwd"] do
            assert {:error, :not_found} = get_key(provider, scope, version),
                   "expected :not_found for version #{inspect(version)}"
          end
        end

        # Finding 11. OpenBao fabricated `created_at: DateTime.utc_now()` when the
        # metadata was missing. A key that is always "created now" is never older than
        # a `max_age`, so age-based rotation silently never fires.
        test "created_at is stable across calls and never moves backwards on rotate",
             %{provider: provider, scope: scope} do
          scope = scope.()

          assert {:ok, %{created_at: %DateTime{} = first}} = current_key(provider, scope)
          assert {:ok, %{created_at: %DateTime{} = second}} = current_key(provider, scope)
          assert DateTime.compare(first, second) == :eq

          assert {:ok, 2} = rotate(provider, scope)

          assert {:ok, %{version: 2, created_at: %DateTime{} = rotated}} =
                   current_key(provider, scope)

          # Not `:gt`: OpenBao's transit metadata is in whole unix seconds, so two
          # rotations inside one second legitimately share a timestamp.
          assert DateTime.compare(rotated, first) != :lt
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

      if unquote(mac?) do
        describe "key provider contract: the :mac purpose" do
          test "declares :mac", %{provider: provider} do
            assert :mac in AshVault.KeyProvider.purposes(module_of(provider))
            assert AshVault.KeyProvider.supports_purpose?(module_of(provider), :mac)
          end

          test "first current_key(:mac) mints version 1",
               %{provider: provider, scope: scope} = context do
            scope = scope.()

            assert {:ok, key_info} = current_key(provider, scope, :mac)
            assert key_info.version == 1
            assert %DateTime{} = key_info.created_at

            if Map.get(context, :opaque_keys?, false) do
              assert AshVault.Key.opaque?(key_info.key)
              assert AshVault.Key.key?(key_info.key)
            else
              assert is_binary(key_info.key)
              assert byte_size(key_info.key) == AshVault.KeyProvider.mac_key_bytes()
            end
          end

          test "current_key(:mac) is stable across calls", %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, first} = current_key(provider, scope, :mac)
            assert {:ok, second} = current_key(provider, scope, :mac)
            assert first == second
          end

          # The separation the whole purpose dimension exists for. A MAC key that was the
          # data key (or the lookup key) would let one primitive's output be replayed as
          # the other's, and rotating one would silently move the other.
          test "the :mac key is never the :data key, nor the lookup key",
               %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, %{version: 1, key: data_key}} = current_key(provider, scope)
            assert {:ok, %{version: 1, key: mac_key}} = current_key(provider, scope, :mac)
            refute mac_key == data_key
            assert {:ok, ^data_key} = get_key(provider, scope, 1)
            assert {:ok, ^mac_key} = get_key(provider, scope, 1, :mac)

            module = module_of(provider)

            if is_binary(mac_key) and AshVault.KeyProvider.supports_lookup?(module) and
                 not is_tuple(provider) do
              assert {:ok, lookup_key} = AshVault.KeyProvider.lookup_key(module, scope)
              refute lookup_key == mac_key
            end
          end

          test "different scopes get different :mac keys", %{provider: provider, scope: scope} do
            assert {:ok, a} = current_key(provider, scope.(), :mac)
            assert {:ok, b} = current_key(provider, scope.(), :mac)
            assert a.key != b.key
          end

          test "rotate(:mac) mints v2, keeps v1 fetchable, and leaves :data alone",
               %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, %{version: 1, key: data_v1} = data_before} = current_key(provider, scope)
            assert {:ok, %{version: 1, key: mac_v1}} = current_key(provider, scope, :mac)

            assert {:ok, 2} = rotate(provider, scope, :mac)
            assert {:ok, %{version: 2, key: mac_v2}} = current_key(provider, scope, :mac)
            refute mac_v1 == mac_v2

            assert {:ok, ^mac_v1} = get_key(provider, scope, 1, :mac)
            assert {:ok, ^mac_v2} = get_key(provider, scope, 2, :mac)

            assert {:ok, ^data_before} = current_key(provider, scope)
            assert {:ok, ^data_v1} = get_key(provider, scope, 1)
            assert {:error, :not_found} = get_key(provider, scope, 2)
          end

          test "rotate(:data) leaves :mac alone", %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, %{version: 1}} = current_key(provider, scope)
            assert {:ok, %{version: 1} = mac_before} = current_key(provider, scope, :mac)
            assert {:ok, 2} = rotate(provider, scope)
            assert {:ok, 3} = rotate(provider, scope)

            assert {:ok, ^mac_before} = current_key(provider, scope, :mac)
            assert {:error, :not_found} = get_key(provider, scope, 2, :mac)
          end

          test "rotate(:mac) on a scope that has never been used returns {:ok, 1}",
               %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, 1} = rotate(provider, scope, :mac)
            assert {:ok, %{version: 1}} = current_key(provider, scope, :mac)
            assert {:ok, 2} = rotate(provider, scope, :mac)
          end

          test "get_key(:mac) for unknown, zero, negative or non-integer versions is :not_found",
               %{provider: provider, scope: scope} do
            fresh = scope.()
            assert {:error, :not_found} = get_key(provider, fresh, 1, :mac)

            scope = scope.()
            assert {:ok, _} = current_key(provider, scope, :mac)

            for version <- [99, 0, -1, :one, 1.5, "1", "../../etc/passwd"] do
              assert {:error, :not_found} = get_key(provider, scope, version, :mac),
                     "expected :not_found for :mac version #{inspect(version)}"
            end
          end

          test "destroy tombstones the :mac keyring, and it never re-mints",
               %{provider: provider, scope: scope} do
            scope = scope.()

            assert {:ok, %{version: 1, key: mac_key}} = current_key(provider, scope, :mac)
            assert {:ok, 2} = rotate(provider, scope, :mac)
            assert :ok = destroy(provider, scope)

            for _ <- 1..3 do
              assert {:error, :destroyed} = current_key(provider, scope, :mac)
              assert {:error, :destroyed} = get_key(provider, scope, 1, :mac)
              assert {:error, :destroyed} = get_key(provider, scope, 2, :mac)
              assert {:error, :destroyed} = get_key(provider, scope, 99, :mac)
              assert {:error, :destroyed} = rotate(provider, scope, :mac)
            end

            refute match?({:ok, %{key: ^mac_key}}, current_key(provider, scope, :mac))
            assert {:error, :destroyed} = current_key(provider, scope)
          end

          test "one tombstone covers every purpose, whichever purpose was used",
               %{provider: provider, scope: scope} do
            mac_only = scope.()
            assert {:ok, _} = current_key(provider, mac_only, :mac)
            assert :ok = destroy(provider, mac_only)
            assert {:error, :destroyed} = current_key(provider, mac_only)
            assert {:error, :destroyed} = current_key(provider, mac_only, :mac)

            never_used = scope.()
            assert :ok = destroy(provider, never_used)
            assert {:error, :destroyed} = current_key(provider, never_used, :mac)
            assert {:error, :destroyed} = rotate(provider, never_used, :mac)
          end

          test "destroying one scope leaves another scope's :mac keyring untouched",
               %{provider: provider, scope: scope} do
            destroyed = scope.()
            kept = scope.()

            assert {:ok, _} = current_key(provider, destroyed, :mac)
            assert {:ok, %{key: kept_key}} = current_key(provider, kept, :mac)
            assert :ok = destroy(provider, destroyed)

            assert {:ok, %{key: ^kept_key}} = current_key(provider, kept, :mac)
          end

          test "a non-binary scope is rejected for the :mac purpose too", %{provider: provider} do
            for bad <- [:atom, 42, {:tuple, 1}, %{a: 1}, ["list"], nil] do
              assert_raise ArgumentError, ~r/must be binaries/, fn ->
                current_key(provider, bad, :mac)
              end

              assert_raise ArgumentError, ~r/must be binaries/, fn ->
                get_key(provider, bad, 1, :mac)
              end

              assert_raise ArgumentError, ~r/must be binaries/, fn ->
                rotate(provider, bad, :mac)
              end
            end
          end
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

  @doc "Call `current_key/2` for a purpose, on a provider module or `{module, server}` pair."
  @spec current_key(module() | {module(), GenServer.server()}, term(), atom()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key({module, server}, scope, purpose),
    do: module.current_key(server, scope, purpose)

  def current_key(module, scope, purpose),
    do: AshVault.KeyProvider.current_key(module, scope, purpose)

  @doc "Call `get_key/3` for a purpose, on a provider module or `{module, server}` pair."
  @spec get_key(module() | {module(), GenServer.server()}, term(), term(), atom()) ::
          {:ok, AshVault.Key.t()} | {:error, term()}
  def get_key({module, server}, scope, version, purpose),
    do: module.get_key(server, scope, version, purpose)

  def get_key(module, scope, version, purpose),
    do: AshVault.KeyProvider.get_key(module, scope, version, purpose)

  @doc "Call `rotate/2` for a purpose, on a provider module or `{module, server}` pair."
  @spec rotate(module() | {module(), GenServer.server()}, term(), atom()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def rotate({module, server}, scope, purpose), do: module.rotate(server, scope, purpose)
  def rotate(module, scope, purpose), do: AshVault.KeyProvider.rotate(module, scope, purpose)

  @doc "The provider module of a provider module or `{module, server}` pair."
  @spec module_of(module() | {module(), GenServer.server()}) :: module()
  def module_of({module, _server}), do: module
  def module_of(module), do: module
end
