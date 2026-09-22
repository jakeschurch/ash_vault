defmodule AshVault.Vault do
  @moduledoc """
  Defines a vault: the bundle of key provider, cipher, envelope, scope and rotation
  policy that an application encrypts with.

      defmodule MyApp.Vault do
        use AshVault.Vault, key_provider: MyApp.KeyProvider
      end

      MyApp.Vault.encrypt!("secret", %AshVault.Context{
        resource: MyApp.User,
        field: :ssn,
        ash_context: %{tenant: "acme"}
      })

  ## Options

    * `:key_provider` — **required**, an `AshVault.KeyProvider`
    * `:cipher` — an `AshVault.Cipher`, defaults to `AshVault.Ciphers.AES.GCM`
    * `:envelope` — an `AshVault.Envelope`, defaults to `AshVault.Envelope.V1`
    * `:scope` — an `AshVault.Scope`, defaults to `AshVault.Scopes.AshTenant`
    * `:rotation_policy` — an `AshVault.RotationPolicy`, defaults to
      `AshVault.RotationPolicies.Manual`
    * `:cache` — wrap the key provider in `AshVault.KeyProviders.Cached`. **Defaults to
      `false`** and should stay that way unless you mean it; see below.

  The generated module is a thin set of delegations to `AshVault.Vault.Runtime`.

  ## Caching keys

  A key cache weakens crypto-erasure from immediate to eventual-within-a-TTL for any
  erasure that does not go through this vault, so it is opt-in:

      # safe defaults: 30s TTL, 1024 entries, the pure-Elixir ETS backend
      use AshVault.Vault, key_provider: MyApp.Keys, cache: true

      # tuned
      use AshVault.Vault,
        key_provider: MyApp.Keys,
        cache: [ttl: :timer.seconds(10), max_entries: 4_096,
                backend: AshVaultRustler.KeyCache]

      # the wrapper itself, when a cached provider needs to be named and shared
      use AshVault.Vault,
        key_provider: {AshVault.KeyProviders.Cached,
                       provider: AshVault.KeyProviders.OpenBao, ttl: 10_000}

  All three forms desugar to the same thing: a module named
  `MyApp.Vault.CachedKeyProvider`, generated here, implementing `AshVault.KeyProvider`
  and wrapping yours. `__ash_vault__(:key_provider)` reports that wrapper, and it must
  be added to your supervision tree because it owns the cache:

      children = [MyApp.Vault.CachedKeyProvider]

  `:backend` selects the cache implementation. The default,
  `AshVault.KeyCaches.ETS`, is pure Elixir and needs nothing installed, but **cannot
  zero key material on eviction** — it drops a reference and the garbage collector
  decides the rest. `AshVaultRustler.KeyCache` keeps the authoritative copy outside the
  BEAM heap and zeroes it on `Drop`. `cache: true` never requires the NIF.

  Read `AshVault.KeyProviders.Cached` before enabling this. The short version: the TTL
  is the maximum time a destroyed tenant stays decryptable when the erasure happened
  out of band, and erasures routed through this vault are evicted synchronously on every
  connected node before `destroy!/1` returns.

  Caching `AshVault.KeyProviders.Memory` is refused with a warning — it is already an
  in-memory map, so a cache in front of it is a second copy and a second eviction path
  for no benefit.
  """

  @doc "Encrypt a plaintext for a context, returning an encoded envelope."
  @callback encrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Decrypt an encoded envelope for a context, returning the plaintext."
  @callback decrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Rotate the key for a scope."
  @callback rotate!(scope :: term()) :: {:ok, non_neg_integer()}

  @doc "Crypto-erase every key for a scope."
  @callback destroy!(scope :: term()) :: :ok

  @doc "Introspect the vault's compile-time configuration."
  @callback __ash_vault__(:key_provider | :cipher | :envelope | :scope | :rotation_policy) ::
              module()

  @doc """
  Compile-time guard: the key provider's key size must match the cipher's.

  Called from the `use AshVault.Vault` macro. `AshVault.KeyProvider.key_bytes/1` had
  zero callers, so a `key_bytes: 16` in config, an OpenBao `key_type: "aes128-gcm96"`,
  or a truncated key file on disk all reached the cipher unchecked — and were then
  reported as two different lies: `AshVault.Errors.AuthenticationFailed` on decrypt
  ("your data was tampered with", for a config typo) and a retryable
  `AshVault.Errors.ProviderUnavailable` naming the *cipher* as the provider on encrypt.

  The check is deliberately conservative. It fires only when it can positively
  determine a mismatch: both modules must already be compiled and both must export
  `key_bytes/0`. A provider whose size depends on runtime configuration —
  `AshVault.KeyProviders.OpenBao` reads `:key_type` from `Application.get_env/3`, which
  operators set in `runtime.exs` — cannot be settled at compile time, and a provider
  module may not even be compiled yet when the vault macro expands. Anything
  unresolvable passes here; `AshVault.Vault.Runtime` raises
  `AshVault.Errors.KeySizeMismatch` at the point of use, which is what actually carries
  the guarantee.
  """
  @spec verify_key_sizes!(module(), map()) :: :ok
  def verify_key_sizes!(vault, %{key_provider: provider, cipher: cipher}) do
    with {:module, _} <- Code.ensure_compiled(provider),
         {:module, _} <- Code.ensure_compiled(cipher),
         true <- function_exported?(provider, :key_bytes, 0),
         true <- function_exported?(cipher, :key_bytes, 0),
         provider_bytes when is_integer(provider_bytes) <- safe_key_bytes(provider),
         cipher_bytes when is_integer(cipher_bytes) <- safe_key_bytes(cipher),
         true <- provider_bytes != cipher_bytes do
      raise ArgumentError, """
      #{inspect(vault)} is misconfigured: its key provider and cipher disagree on key size.

        #{inspect(provider)}.key_bytes() == #{provider_bytes}
        #{inspect(cipher)}.key_bytes()   == #{cipher_bytes}

      Every encryption would fail with AshVault.Errors.KeySizeMismatch. Either configure
      the provider to mint #{cipher_bytes}-byte keys, or choose a cipher that takes
      #{provider_bytes}-byte keys.
      """
    end

    :ok
  end

  defp safe_key_bytes(module) do
    module.key_bytes()
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc """
  Resolve the `:cache` option (and the `{Cached, opts}` wrapper form) into
  `{inner_provider, cache_opts | nil}`.

  Returning the *inner* provider separately matters: `verify_key_sizes!/2` has to keep
  seeing the provider the user actually configured. Pointing it at the generated wrapper
  would aim a compile-time check at a module that is mid-definition, and the wrapper's
  `key_bytes/0` is a delegation anyway.

  `nil` for the second element means no wrapping at all — which is what `cache: false`,
  an omitted `:cache`, and `cache: true` over `AshVault.KeyProviders.Memory` all produce,
  so those three are indistinguishable downstream.
  """
  @spec resolve_cache!(module(), term(), keyword(), keyword()) :: {module(), keyword() | nil}
  def resolve_cache!(vault, key_provider, opts, location \\ []) do
    case {key_provider, Keyword.get(opts, :cache, false)} do
      {{AshVault.KeyProviders.Cached, wrapper_opts}, cache} when is_list(wrapper_opts) ->
        if cache not in [false, nil] do
          raise ArgumentError, """
          #{inspect(vault)} passes both an explicit `AshVault.KeyProviders.Cached`
          wrapper and a `:cache` option. They configure the same thing. Keep one.
          """
        end

        inner =
          Keyword.get(wrapper_opts, :provider) ||
            raise ArgumentError, """
            #{inspect(vault)}: the `{AshVault.KeyProviders.Cached, opts}` key provider
            requires a `:provider` to wrap.

                key_provider: {AshVault.KeyProviders.Cached, provider: MyApp.Keys}
            """

        {inner, wrapper_opts}

      {{other, _opts}, _cache} ->
        raise ArgumentError, """
        #{inspect(vault)}: a tuple `:key_provider` is only supported for
        `AshVault.KeyProviders.Cached`, got: #{inspect(other)}.

        Pass a plain module, or use the `:cache` option.
        """

      {provider, cache} when cache in [false, nil] ->
        {provider, nil}

      {provider, cache} when cache == true or is_list(cache) ->
        cache_opts = if cache == true, do: [], else: cache

        cond do
          not is_atom(provider) or is_nil(provider) ->
            raise ArgumentError,
                  "#{inspect(vault)}: `:cache` requires a module `:key_provider`, got: " <>
                    inspect(provider)

          Keyword.has_key?(cache_opts, :provider) ->
            raise ArgumentError, """
            #{inspect(vault)}: `:cache` must not carry a `:provider`. The provider comes
            from `:key_provider`. Use the `{AshVault.KeyProviders.Cached, opts}` form if
            you want to name it there instead.
            """

          provider == AshVault.KeyProviders.Memory ->
            IO.warn(
              """
              #{inspect(vault)} sets `cache: true` over AshVault.KeyProviders.Memory.

              Memory is already an in-memory map of keys, so a cache in front of it is a
              second copy of every key and a second eviction path, for no benefit. The
              cache has not been enabled; the vault uses AshVault.KeyProviders.Memory
              directly.
              """,
              location
            )

            {provider, nil}

          true ->
            {provider, Keyword.put(cache_opts, :provider, provider)}
        end

      {_provider, cache} ->
        raise ArgumentError, """
        #{inspect(vault)}: `:cache` must be `true`, `false`, or a keyword list of
        `AshVault.KeyProviders.Cached` options, got: #{inspect(cache)}.

            use AshVault.Vault, key_provider: MyApp.Keys, cache: true
            use AshVault.Vault, key_provider: MyApp.Keys, cache: [ttl: :timer.seconds(10)]
        """
    end
  end

  @doc """
  Define the vault's `CachedKeyProvider` module, or return the provider unchanged.

  Generating a real module (rather than teaching `AshVault.Vault.Runtime` to dispatch on
  a `{module, opts}` tuple) keeps the runtime's four provider call sites exactly as they
  are: a cached provider is an ordinary `AshVault.KeyProvider` module like any other.
  """
  @spec define_cache_module!(module(), module(), keyword() | nil, keyword()) :: module()
  def define_cache_module!(_vault, provider, nil, _location), do: provider

  def define_cache_module!(vault, _provider, cache_opts, location) do
    module = Module.concat(vault, "CachedKeyProvider")

    Module.create(
      module,
      quote do
        @moduledoc """
        The `AshVault.KeyProviders.Cached` provider generated for `#{inspect(unquote(vault))}`.

        Add it to your supervision tree; it owns the key cache.
        """
        use AshVault.KeyProviders.Cached, unquote(Macro.escape(cache_opts))
      end,
      location
    )

    module
  end

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour AshVault.Vault

      key_provider =
        opts[:key_provider] ||
          raise ArgumentError, """
          `use AshVault.Vault` requires a `:key_provider`.

              defmodule #{inspect(__MODULE__)} do
                use AshVault.Vault, key_provider: MyApp.KeyProvider
              end

          AshVault ships `AshVault.KeyProviders.Memory` for development and test.
          """

      ash_vault_location = Macro.Env.location(__ENV__)

      {ash_vault_inner_provider, ash_vault_cache_opts} =
        AshVault.Vault.resolve_cache!(__MODULE__, key_provider, opts, ash_vault_location)

      # Deliberately the *inner* provider: the generated wrapper's `key_bytes/0` is a
      # delegation to exactly this module, and the wrapper does not exist yet.
      AshVault.Vault.verify_key_sizes!(__MODULE__, %{
        key_provider: ash_vault_inner_provider,
        cipher: opts[:cipher] || AshVault.Ciphers.AES.GCM
      })

      @ash_vault_opts %{
        key_provider:
          AshVault.Vault.define_cache_module!(
            __MODULE__,
            ash_vault_inner_provider,
            ash_vault_cache_opts,
            ash_vault_location
          ),
        cipher: opts[:cipher] || AshVault.Ciphers.AES.GCM,
        envelope: opts[:envelope] || AshVault.Envelope.V1,
        scope: opts[:scope] || AshVault.Scopes.AshTenant,
        rotation_policy: opts[:rotation_policy] || AshVault.RotationPolicies.Manual
      }

      @doc "Encrypt a plaintext for a context, returning an encoded envelope."
      @impl AshVault.Vault
      @spec encrypt!(binary(), AshVault.Context.t()) :: binary()
      def encrypt!(plaintext, ctx),
        do: AshVault.Vault.Runtime.encrypt!(plaintext, ctx, @ash_vault_opts)

      @doc "Decrypt an encoded envelope for a context, returning the plaintext."
      @impl AshVault.Vault
      @spec decrypt!(binary(), AshVault.Context.t()) :: binary()
      def decrypt!(blob, ctx), do: AshVault.Vault.Runtime.decrypt!(blob, ctx, @ash_vault_opts)

      @doc "Rotate the key for a scope."
      @impl AshVault.Vault
      @spec rotate!(term()) :: {:ok, non_neg_integer()}
      def rotate!(scope), do: AshVault.Vault.Runtime.rotate!(scope, @ash_vault_opts)

      @doc "Crypto-erase every key for a scope."
      @impl AshVault.Vault
      @spec destroy!(term()) :: :ok
      def destroy!(scope), do: AshVault.Vault.Runtime.destroy!(scope, @ash_vault_opts)

      @doc "Introspect this vault's compile-time configuration."
      @impl AshVault.Vault
      @spec __ash_vault__(:key_provider | :cipher | :envelope | :scope | :rotation_policy) ::
              module()
      def __ash_vault__(key)
          when key in [:key_provider, :cipher, :envelope, :scope, :rotation_policy],
          do: Map.fetch!(@ash_vault_opts, key)
    end
  end
end
