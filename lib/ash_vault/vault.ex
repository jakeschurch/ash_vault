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
    * `:mac` — an `AshVault.Mac` for `mac!/2` and `verify_mac!/4`. Defaults to
      `AshVault.Macs.OpenBaoTransit` when the key provider is
      `AshVault.KeyProviders.OpenBaoTransit` (whose keys never leave OpenBao), and to
      `AshVault.Macs.HmacSha256` otherwise. See [Key purposes and MACs](key-purposes-and-macs.md).
    * `:envelope` — an `AshVault.Envelope`, defaults to `AshVault.Envelope.V1`
    * `:scope` — an `AshVault.Scope`, defaults to `AshVault.Scopes.AshTenant`
    * `:rotation_policy` — an `AshVault.RotationPolicy`, defaults to
      `AshVault.RotationPolicies.Manual`
    * `:otp_app` — the OTP application whose config key this vault's key provider may be
      configured under. Defaults to the application the vault module is compiled into,
      which is almost always what you want; see below.
    * `:cache` — wrap the key provider in `AshVault.KeyProviders.Cached`. **Defaults to
      `false`** and should stay that way unless you mean it; see below.

  The generated module is a thin set of delegations to `AshVault.Vault.Runtime`.

  ## MACs

  Besides encrypting, a vault authenticates: `mac!/2` returns `{key_version, tag}` under
  the scope's `:mac` keyring, `verify_mac!/4` checks one, and `rotate!(scope, purpose:
  :mac)` rotates that keyring without touching the data keys. `destroy!/1` revokes every
  tag the scope ever issued, because it destroys the `:mac` keyring with everything else.

      {version, tag} = MyApp.Vault.mac!("payload", ctx)
      :ok = MyApp.Vault.verify_mac!("payload", version, tag, ctx)

  The `:mac` keyring needs a provider that serves it (`c:AshVault.KeyProvider.purposes/0`).
  Every provider AshVault ships does. With an explicit `mac:` option, a provider that is
  already compiled and does not is a compile error here; without one, a vault over such
  a provider still compiles — it never MACs until asked to — and `mac!/2` raises
  `AshVault.Errors.PurposeUnsupported`.

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

  ## Starting and setting up the key provider

  Providers differ in what they need before they can serve a key —
  `AshVault.KeyProviders.Local` wants a supervised process *and* an initialised key
  root, `AshVault.KeyProviders.OpenBao` wants no process and a mounted KV engine,
  `AshVault.KeyProviders.Memory` wants a process and nothing else — and a host
  application should not have to know which. The vault does, so it answers for its
  provider:

      # lib/my_app/application.ex
      children = [MyApp.Repo] ++ MyApp.Vault.child_specs()

      # a deploy step, a release command, or `mix my_app.setup`
      :ok = MyApp.Vault.setup()

  `child_specs/0` includes the generated `CachedKeyProvider` when `cache:` is set, and
  the provider underneath it when that one is supervised too, innermost first.
  `setup/0` returns `:ok` for a provider that needs none. Neither is a `case` you write.

  Both rest on optional `AshVault.KeyProvider` callbacks — `c:AshVault.KeyProvider.child_spec/1`
  and `c:AshVault.KeyProvider.setup/0` — so a third-party provider that defines neither
  keeps working unchanged and simply contributes nothing.

  ## Where provider configuration lives

  Key provider configuration is per provider **module**, and may be written under your
  own OTP application:

      config :my_app, AshVault.KeyProviders.OpenBao, address: "http://127.0.0.1:8200"

  `use AshVault.Vault` records the OTP application this vault module is compiled into
  and registers it when the module loads, which is what lets
  `AshVault.KeyProvider.config/1` find that key. Pass `otp_app:` to name a different
  one. The original form, `config :ash_vault, AshVault.KeyProviders.OpenBao, ...`, still
  works and is the base the host application's config is merged over.

  ## One vault per application

  A vault is resolved at compile time, deliberately: it is what makes
  `verify_key_sizes!/2` possible at all, and it keeps the four provider call sites in
  `AshVault.Vault.Runtime` to a plain module call. There is no runtime provider switch,
  and one vault per application is the shape this is built for.

  When you genuinely need two — demonstrating two providers, or migrating between
  them — define two vault modules and resolve between them with the `fun/2` vault form
  the DSL already accepts. See
  [Two vaults in one application](two-vaults.md) for the worked pattern and the one
  hazard it carries.
  """

  @doc "Encrypt a plaintext for a context, returning an encoded envelope."
  @callback encrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Decrypt an encoded envelope for a context, returning the plaintext."
  @callback decrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Rotate the `:data` key for a scope."
  @callback rotate!(scope :: term()) :: {:ok, non_neg_integer()}

  @doc "Rotate a scope's keyring for a purpose: `rotate!(scope, purpose: :mac)`."
  @callback rotate!(scope :: term(), opts :: keyword()) :: {:ok, non_neg_integer()}

  @doc "Compute a MAC over `data` for a context, returning `{key_version, tag}`."
  @callback mac!(binary(), AshVault.Context.t()) :: {pos_integer(), binary()}

  @doc "Verify a tag from `c:mac!/2`, returning `:ok` or raising."
  @callback verify_mac!(binary(), term(), term(), AshVault.Context.t()) :: :ok

  @doc "Crypto-erase every key for a scope."
  @callback destroy!(scope :: term()) :: :ok

  @doc "Introspect the vault's compile-time configuration."
  @callback __ash_vault__(:key_provider | :cipher | :mac | :envelope | :scope | :rotation_policy) ::
              module()

  @doc "The child specifications this vault's key provider needs supervised."
  @callback child_specs() :: [module()]

  @doc "Run the operator setup step this vault's key provider needs, if it has one."
  @callback setup() :: :ok | {:error, term()}

  @doc """
  Compile-time guard: the key provider's key size must match the cipher's.

  Called from the `use AshVault.Vault` macro. `AshVault.KeyProvider.key_bytes/1` had
  zero callers, so a `key_bytes: 16` in config, an OpenBao `key_type: "aes128-gcm96"`,
  or a truncated key file on disk all reached the cipher unchecked — and were then
  reported as two different lies: `AshVault.Errors.CiphertextIntegrityFailed` on decrypt
  ("your data was tampered with", for a config typo) and a retryable
  `AshVault.Errors.ProviderUnavailable` naming the *cipher* as the provider on encrypt.

  The check is deliberately conservative. It fires only when it can positively
  determine a mismatch: both modules must already be compiled and both must export
  `key_bytes/0`. A provider whose size depends on runtime configuration —
  `AshVault.KeyProviders.OpenBao` reads `:key_type` through
  `AshVault.KeyProvider.config/1`, which operators set in `runtime.exs` — cannot be
  settled at compile time, and a provider
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

  @doc """
  The default `AshVault.Mac` for a key provider: `AshVault.Macs.OpenBaoTransit` over
  `AshVault.KeyProviders.OpenBaoTransit`, whose `:mac` keys are opaque handles, and
  `AshVault.Macs.HmacSha256` over everything else.
  """
  @spec default_mac(module()) :: module()
  def default_mac(provider) do
    if AshVault.KeyProvider.unwrap_cached(provider) == AshVault.KeyProviders.OpenBaoTransit,
      do: AshVault.Macs.OpenBaoTransit,
      else: AshVault.Macs.HmacSha256
  end

  @doc """
  Compile-time guard for an **explicitly** configured `mac:`.

  Fires only when it can positively determine a fault, like `verify_key_sizes!/2`:

    * the provider is compiled and its `c:AshVault.KeyProvider.purposes/0` does not list
      `:mac`;
    * `AshVault.Macs.OpenBaoTransit` over any provider but
      `AshVault.KeyProviders.OpenBaoTransit`, or `AshVault.Macs.HmacSha256` over it — the
      handle and the MAC would not understand each other.

  A vault with no `mac:` option is never checked here: existing vaults over third-party
  providers keep compiling, and `AshVault.Errors.PurposeUnsupported` is the runtime
  answer if one of them is ever asked to MAC.
  """
  @spec verify_mac_pairing!(module(), map()) :: :ok
  def verify_mac_pairing!(_vault, %{mac: nil}), do: :ok

  def verify_mac_pairing!(vault, %{key_provider: provider, mac: mac}) do
    unless AshVault.KeyProvider.supports_purpose?(provider, :mac) do
      raise ArgumentError, """
      #{inspect(vault)} configures `mac: #{inspect(mac)}`, but its key provider
      #{inspect(provider)} cannot serve :mac keys — its `purposes/0` does not list :mac.

      Implement the optional `AshVault.KeyProvider` callbacks `purposes/0`,
      `current_key/2`, `get_key/3` and `rotate/2`, or use a provider that ships them.
      """
    end

    transit_provider? =
      AshVault.KeyProvider.unwrap_cached(provider) == AshVault.KeyProviders.OpenBaoTransit

    cond do
      mac == AshVault.Macs.OpenBaoTransit and not transit_provider? ->
        raise ArgumentError, """
        #{inspect(vault)}: AshVault.Macs.OpenBaoTransit computes MACs inside OpenBao from
        the key handles AshVault.KeyProviders.OpenBaoTransit serves, but the key provider
        is #{inspect(provider)}. Use AshVault.Macs.HmacSha256, or that provider.
        """

      mac == AshVault.Macs.HmacSha256 and transit_provider? ->
        raise ArgumentError, """
        #{inspect(vault)}: AshVault.KeyProviders.OpenBaoTransit never exports key
        material, so AshVault.Macs.HmacSha256 has no bytes to MAC with. Use
        `mac: AshVault.Macs.OpenBaoTransit` (the default for this provider).
        """

      true ->
        :ok
    end
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

  @doc """
  The purpose a `rotate!/2` keyword list names: `:data` unless `purpose:` says otherwise.

  Raises `ArgumentError` for anything but `:data` or `:mac`, and for unknown options, so a
  typo such as `purpos: :mac` cannot quietly rotate the data key instead.
  """
  @spec purpose!(keyword()) :: AshVault.KeyProvider.purpose()
  def purpose!(opts) when is_list(opts) do
    case Keyword.split(opts, [:purpose]) do
      {purpose_opts, []} ->
        case Keyword.get(purpose_opts, :purpose, :data) do
          purpose when purpose in [:data, :mac] ->
            purpose

          other ->
            raise ArgumentError,
                  "rotate!/2 `:purpose` must be :data or :mac, got: #{inspect(other)}"
        end

      {_purpose_opts, unknown} ->
        raise ArgumentError,
              "rotate!/2 accepts only `:purpose`, got: #{inspect(Keyword.keys(unknown))}"
    end
  end

  @doc """
  The OTP application a vault module is being compiled into.

  Used as the default for the `:otp_app` option, so that
  `config :my_app, AshVault.KeyProviders.OpenBao, ...` works with no further ceremony.
  Returns `nil` outside a Mix build — in which case only
  `config :ash_vault, AshVault.KeyProviders.OpenBao, ...` and an explicit
  `config :ash_vault, otp_app: :my_app` are consulted.
  """
  @spec compiling_otp_app() :: atom() | nil
  def compiling_otp_app do
    if Code.ensure_loaded?(Mix.Project) and function_exported?(Mix.Project, :config, 0) do
      Mix.Project.config()[:app]
    end
  rescue
    _error -> nil
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

      AshVault.Vault.verify_mac_pairing!(__MODULE__, %{
        key_provider: ash_vault_inner_provider,
        mac: opts[:mac]
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
        mac: opts[:mac] || AshVault.Vault.default_mac(ash_vault_inner_provider),
        vault: __MODULE__,
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

      @doc """
      Rotate a scope's keyring: the `:data` key by default, or another purpose with
      `purpose: :mac`.
      """
      @impl AshVault.Vault
      @spec rotate!(term(), keyword()) :: {:ok, non_neg_integer()}
      def rotate!(scope, rotate_opts \\ []) do
        AshVault.Vault.Runtime.rotate!(
          scope,
          AshVault.Vault.purpose!(rotate_opts),
          @ash_vault_opts
        )
      end

      @doc """
      Compute a MAC over `data` for a context, returning `{key_version, tag}`.

      See `AshVault.Vault.Runtime.mac!/3`.
      """
      @impl AshVault.Vault
      @spec mac!(binary(), AshVault.Context.t()) :: {pos_integer(), binary()}
      def mac!(data, ctx), do: AshVault.Vault.Runtime.mac!(data, ctx, @ash_vault_opts)

      @doc """
      Verify a tag from `mac!/2`. Returns `:ok` or raises; see
      `AshVault.Vault.Runtime.verify_mac!/5` for which error means what.
      """
      @impl AshVault.Vault
      @spec verify_mac!(binary(), term(), term(), AshVault.Context.t()) :: :ok
      def verify_mac!(data, key_version, tag, ctx),
        do: AshVault.Vault.Runtime.verify_mac!(data, key_version, tag, ctx, @ash_vault_opts)

      @doc "Crypto-erase every key for a scope."
      @impl AshVault.Vault
      @spec destroy!(term()) :: :ok
      def destroy!(scope), do: AshVault.Vault.Runtime.destroy!(scope, @ash_vault_opts)

      @ash_vault_otp_app opts[:otp_app] || AshVault.Vault.compiling_otp_app()

      # A provider config read is only ever reached by way of a vault, and reaching a
      # vault loads it — so registering here is enough for `AshVault.KeyProvider.config/1`
      # to know which application key to look under, with no boot-order requirement on
      # the host.
      @on_load :__ash_vault_register_otp_app__

      @doc false
      @spec __ash_vault_register_otp_app__() :: :ok
      def __ash_vault_register_otp_app__ do
        AshVault.KeyProvider.register_otp_app(@ash_vault_otp_app)
      rescue
        _error -> :ok
      end

      @doc """
      The child specifications this vault's key provider needs supervised.

          children = [MyApp.Repo] ++ #{inspect(__MODULE__)}.child_specs()

      Empty for a provider that owns no process.
      """
      @impl AshVault.Vault
      @spec child_specs() :: [module()]
      def child_specs, do: AshVault.KeyProvider.children(__MODULE__)

      @doc """
      Run the operator setup step this vault's key provider needs.

      `:ok` for a provider that needs none, so this is safe to call unconditionally from
      a deploy step.
      """
      @impl AshVault.Vault
      @spec setup() :: :ok | {:error, term()}
      def setup, do: AshVault.KeyProvider.setup(__MODULE__)

      @doc "Introspect this vault's compile-time configuration."
      @impl AshVault.Vault
      @spec __ash_vault__(:key_provider | :cipher | :mac | :envelope | :scope | :rotation_policy) ::
              module()
      def __ash_vault__(key)
          when key in [:key_provider, :cipher, :mac, :envelope, :scope, :rotation_policy],
          do: Map.fetch!(@ash_vault_opts, key)
    end
  end
end
