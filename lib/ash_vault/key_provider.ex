defmodule AshVault.KeyProvider do
  @moduledoc """
  Behaviour for key providers: the components that mint, serve, rotate and destroy
  the symmetric keys AshVault encrypts with.

  A provider is addressed by *scope* — an opaque term (normalised to a binary by
  `AshVault.Scope` implementations) identifying the blast radius of a key, typically a
  tenant id.

  Two rules every implementation must honour:

    * `current_key/1` mints the scope's key material on first use, at version 1. Callers
      never create a scope's key explicitly.
    * `destroy/1` is a **tombstone**, not a delete. After destroying a scope, both
      `current_key/1` and `get_key/2` must return `{:error, :destroyed}` forever — never
      `{:error, :not_found}`, and never a freshly minted key. Silently re-minting would
      turn crypto-erasure into silent data loss.

  ## Purposes

  A scope can hold more than one **keyring**, one per *purpose*:

    * `:data` — the keys `AshVault.Cipher` encrypts with. The arity forms every
      provider has always had (`current_key/1`, `get_key/2`, `rotate/1`) are this
      purpose, and always will be.
    * `:mac` — the keys `AshVault.Mac` authenticates with: `current_key/2`,
      `get_key/3` and `rotate/2` with `:mac` as the last argument.

  A provider declares what it can serve with `c:purposes/0`; one that does not define it
  serves `:data` only, and every provider written before purposes existed keeps working
  unchanged. Call sites never dispatch on arity themselves — they go through
  `current_key/3`, `get_key/4` and `rotate/3` in this module, which route `:data` to the
  original callbacks and refuse a purpose the provider has not declared.

  The rules for a `:mac` keyring are the `:data` rules, plus separation:

    * minted on first use at version 1, rotated independently — rotating `:mac` never
      moves `:data`, and rotating `:data` never moves `:mac`;
    * old versions stay fetchable after a rotation, so tags minted under them still
      verify;
    * `c:destroy/1` destroys **every** purpose under the one tombstone, and afterwards
      each purpose answers `{:error, :destroyed}` forever and never re-mints;
    * a `:mac` key is never a `:data` key, never the lookup key, and never derived from
      either. It is minted at `mac_key_bytes/0` bytes regardless of the provider's data
      `c:key_bytes/0`.
  """

  @type scope :: term()

  @typedoc """
  The key material a provider serves.

  A raw binary for every provider AshVault ships. The union with `AshVault.Key` is the
  opt-in extension point for a provider that keeps key material outside the BEAM heap
  and hands out an opaque handle instead; see `AshVault.Key`.
  """
  @type key :: AshVault.Key.t()
  @type version :: non_neg_integer()
  @type key_info :: %{version: version(), key: AshVault.Key.t(), created_at: DateTime.t()}

  @typedoc "Which keyring of a scope a key belongs to. See *Purposes* above."
  @type purpose :: :data | :mac

  @doc "Fetch (minting on first use) the current key for a scope."
  @callback current_key(scope()) :: {:ok, key_info()} | {:error, term()}

  @doc "Fetch a specific historical key version for a scope."
  @callback get_key(scope(), version()) ::
              {:ok, AshVault.Key.t()}
              | {:error, :not_found}
              | {:error, :destroyed}
              | {:error, term()}

  @doc "Mint a new key version for a scope, retaining history."
  @callback rotate(scope()) :: {:ok, version()} | {:error, term()}

  @doc "Irreversibly destroy all key material for a scope and record a tombstone."
  @callback destroy(scope()) :: :ok | {:error, term()}

  @doc "The key size, in bytes, this provider mints. Defaults to 32."
  @callback key_bytes() :: pos_integer()

  @doc """
  The scope's **lookup key**: the secret that searchable fields derive HMAC tokens from.

  Optional. A provider that does not implement it makes `searchable?: true` a
  compile-time DSL error naming the provider, rather than a runtime surprise.

  Three rules, and all three are load-bearing:

    * it is **stable**. `c:rotate/1` MUST NOT change it. A lookup key that rotates
      silently invalidates every token already stored: existing rows stop matching, and
      nothing raises. Mint it once per scope and return the same bytes forever.
    * it is **per scope**, like every other key here, so the equality a token leaks never
      leaks across tenants.
    * `c:destroy/1` destroys it along with everything else, and the same tombstone gates
      it afterwards — erasure still erases, and a destroyed scope's `lookup_key/1`
      returns `{:error, :destroyed}` rather than a fresh secret.

  It must not be the key `c:current_key/1` serves, nor derived from it. Per-field
  separation is HKDF's job (`AshVault.Lookup`), not the provider's.
  """
  @callback lookup_key(scope()) :: {:ok, binary()} | {:error, term()}

  @doc """
  A `Supervisor` child specification for this provider, when it needs to be supervised.

  Optional. A provider that owns no process — `AshVault.KeyProviders.OpenBao` is a pile
  of stateless HTTP calls — simply does not define it, and
  `AshVault.KeyProvider.children/1` reports no children for it.

  `AshVault.KeyProviders.Local`, `AshVault.KeyProviders.Memory` and the generated
  `AshVault.KeyProviders.Cached` wrappers all satisfy this callback for free, through
  `use GenServer` and their own `child_spec/1`.

  Do not call this callback directly to build a supervision tree. Call
  `MyApp.Vault.child_specs/0`, which knows about the cache wrapper as well as the
  provider underneath it.
  """
  @callback child_spec(term()) :: Supervisor.child_spec()

  @doc """
  The **operator** setup step this provider needs before it can serve keys.

  Optional, and deliberately separate from `c:child_spec/1`: it is a one-shot,
  privileged, occasionally destructive-adjacent action (creating a key root, mounting a
  secrets engine), not something a supervisor should be doing on every boot of every
  node.

  Implementations must be idempotent — `AshVault.KeyProviders.OpenBao.setup/0` is a
  no-op against an already-mounted KV engine, and `AshVault.KeyProviders.Local.setup/0`
  is a no-op against an already-initialised root.

  A provider that needs no setup does not define it; `AshVault.KeyProvider.setup/1`
  returns `:ok` for it.
  """
  @callback setup() :: :ok | {:error, term()}

  @doc """
  The purposes this provider can serve keys for. Optional; `[:data]` when absent.

  A provider listing `:mac` must implement `c:current_key/2`, `c:get_key/3` and
  `c:rotate/2`, and its `c:destroy/1` must destroy the `:mac` keyring too.
  """
  @callback purposes() :: [purpose()]

  @doc """
  `c:current_key/1` for a purpose. Only called with a purpose `c:purposes/0` lists.
  """
  @callback current_key(scope(), purpose()) :: {:ok, key_info()} | {:error, term()}

  @doc """
  `c:get_key/2` for a purpose. Only called with a purpose `c:purposes/0` lists.
  """
  @callback get_key(scope(), version(), purpose()) ::
              {:ok, AshVault.Key.t()}
              | {:error, :not_found}
              | {:error, :destroyed}
              | {:error, term()}

  @doc """
  `c:rotate/1` for a purpose. Only called with a purpose `c:purposes/0` lists.
  """
  @callback rotate(scope(), purpose()) :: {:ok, version()} | {:error, term()}

  @optional_callbacks key_bytes: 0,
                      lookup_key: 1,
                      child_spec: 1,
                      setup: 0,
                      purposes: 0,
                      current_key: 2,
                      get_key: 3,
                      rotate: 2

  @default_key_bytes 32
  @mac_key_bytes 32
  @purposes [:data, :mac]

  @doc """
  Every purpose AshVault knows, `[:data, :mac]`.
  """
  @spec all_purposes() :: [purpose()]
  def all_purposes, do: @purposes

  @doc """
  The size, in bytes, of every `:mac` key a shipped provider mints: `32`.

  Fixed, and deliberately independent of a provider's data `c:key_bytes/0` — an
  `aes128-gcm96` data keyring must not quietly halve the MAC key.
  """
  @spec mac_key_bytes() :: pos_integer()
  def mac_key_bytes, do: @mac_key_bytes

  @doc """
  The purposes a provider serves: its `c:purposes/0`, or `[:data]` when it has none.
  """
  @spec purposes(module()) :: [purpose()]
  def purposes(provider) when is_atom(provider) do
    if exports?(provider, :purposes, 0), do: provider.purposes(), else: [:data]
  end

  @doc """
  Whether a provider can serve keys for `purpose`.

  `:data` is always `true`. For any other purpose this fails **open** for a module that
  is not compiled yet, exactly like `supports_lookup?/1` and for the same reason: it is
  called from compile-time checks, and `AshVault.Errors.PurposeUnsupported` is the clean
  runtime backstop. `AshVault.KeyProviders.Cached` is unwrapped to the provider it wraps.

  Purpose support is read from `c:purposes/0` and never inferred from arity:
  `AshVault.KeyProviders.Memory` and `AshVault.KeyProviders.Local` have long exported a
  `current_key/2` that takes a *server* and a scope, and a provider that copied that
  pattern must not be mistaken for one that understands purposes.
  """
  @spec supports_purpose?(module(), purpose()) :: boolean()
  def supports_purpose?(_provider, :data), do: true

  def supports_purpose?(provider, purpose) when is_atom(provider) and purpose in @purposes do
    with {:module, ^provider} <- Code.ensure_compiled(provider),
         inner = unwrap_cached(provider),
         {:module, ^inner} <- Code.ensure_compiled(inner) do
      purpose in purposes(inner)
    else
      _not_compiled -> true
    end
  end

  def supports_purpose?(_provider, _purpose), do: false

  @doc """
  Fetch (minting on first use) a scope's current key for `purpose`.

  `:data` calls `c:current_key/1`, exactly as AshVault always has. Any other purpose the
  provider does not list in `c:purposes/0` is `{:error, {:purpose_unsupported, purpose}}`
  — a configuration fault, which `AshVault.Vault.Runtime` reports as
  `AshVault.Errors.PurposeUnsupported`, never as an outage.
  """
  @spec current_key(module(), scope(), purpose()) :: {:ok, key_info()} | {:error, term()}
  def current_key(provider, scope, :data), do: provider.current_key(scope)

  def current_key(provider, scope, purpose) do
    with :ok <- check_purpose(provider, purpose), do: provider.current_key(scope, purpose)
  end

  @doc """
  Fetch one key version of a scope's `purpose` keyring. See `current_key/3`.
  """
  @spec get_key(module(), scope(), version(), purpose()) ::
          {:ok, AshVault.Key.t()} | {:error, term()}
  def get_key(provider, scope, version, :data), do: provider.get_key(scope, version)

  def get_key(provider, scope, version, purpose) do
    with :ok <- check_purpose(provider, purpose), do: provider.get_key(scope, version, purpose)
  end

  @doc """
  Rotate a scope's `purpose` keyring. See `current_key/3`.
  """
  @spec rotate(module(), scope(), purpose()) :: {:ok, version()} | {:error, term()}
  def rotate(provider, scope, :data), do: provider.rotate(scope)

  def rotate(provider, scope, purpose) do
    with :ok <- check_purpose(provider, purpose), do: provider.rotate(scope, purpose)
  end

  defp check_purpose(provider, purpose) do
    Code.ensure_loaded(provider)

    if purpose in @purposes and purpose in purposes(provider) do
      :ok
    else
      {:error, {:purpose_unsupported, purpose}}
    end
  end

  @doc """
  The key size a provider mints, falling back to 32 bytes when it does not say.
  """
  @spec key_bytes(module()) :: pos_integer()
  def key_bytes(provider) when is_atom(provider) do
    if function_exported?(provider, :key_bytes, 0) do
      provider.key_bytes()
    else
      @default_key_bytes
    end
  end

  @doc """
  The default key size in bytes, `32`.
  """
  @spec default_key_bytes() :: pos_integer()
  def default_key_bytes, do: @default_key_bytes

  @doc """
  Fetch a scope's lookup key, or `{:error, :lookup_unsupported}` when the provider has
  no `c:lookup_key/1`.

  Every caller goes through here rather than calling the optional callback directly, so
  "this provider cannot do searchable fields" is one tagged value instead of an
  `UndefinedFunctionError` from inside a `before_action` hook.
  """
  @spec lookup_key(module(), scope()) :: {:ok, binary()} | {:error, term()}
  def lookup_key(provider, scope) when is_atom(provider) do
    if supports_lookup?(provider) do
      provider.lookup_key(scope)
    else
      {:error, :lookup_unsupported}
    end
  end

  @doc """
  Whether a provider can serve lookup keys.

  Fails **open**: a provider module that is not compiled yet answers `true`. This is
  called from `AshVault.Verifiers.VerifyVault`, and a compile-order-dependent DSL error
  is worse than the clean runtime `AshVault.Errors.LookupUnsupported` the same path
  produces later. `AshVault.Verifiers.VerifyVault` treats an uncompiled vault the same way.

  `AshVault.KeyProviders.Cached` is unwrapped to the provider it caches: the generated
  wrapper delegates `lookup_key/1` unconditionally, so asking the wrapper directly would
  always answer `true` and defeat the compile-time check.
  """
  @spec supports_lookup?(module()) :: boolean()
  def supports_lookup?(provider) when is_atom(provider) do
    with {:module, ^provider} <- Code.ensure_compiled(provider),
         inner = unwrap_cached(provider),
         {:module, ^inner} <- Code.ensure_compiled(inner) do
      function_exported?(inner, :lookup_key, 1)
    else
      _not_compiled -> true
    end
  end

  def supports_lookup?(_provider), do: false

  @doc """
  The provider a `AshVault.KeyProviders.Cached` wrapper wraps, or the module itself.
  """
  @spec unwrap_cached(module()) :: module()
  def unwrap_cached(provider) when is_atom(provider) do
    if function_exported?(provider, :__ash_vault_cached__, 0) do
      Map.get(provider.__ash_vault_cached__(), :provider, provider)
    else
      provider
    end
  end

  @doc """
  The child specifications a vault's (or a provider's) key material needs supervised.

  This is the one line a host application's `Application.start/2` writes:

      children = [MyApp.Repo] ++ MyApp.Vault.child_specs()

  Pass a **vault** rather than a provider. A vault built with `cache: true` supervises
  two things — the generated `CachedKeyProvider`, which owns the cache, and the provider
  underneath it if that one owns a process too — and only the vault knows about both.
  Passing a provider module works and returns that provider's own children.

  A provider with no `c:child_spec/1` contributes nothing, which is why
  `AshVault.KeyProviders.OpenBao` needs no `case` in your Application module.
  """
  @spec children(module()) :: [module()]
  def children(vault_or_provider) when is_atom(vault_or_provider) do
    vault_or_provider
    |> chain()
    |> Enum.filter(&exports?(&1, :child_spec, 1))
  end

  @doc """
  Run the operator setup step for a vault's (or a provider's) key provider.

  The counterpart to `children/1`, and the other line a host writes — in a release
  task, a `mix` task, or a one-shot deploy step:

      MyApp.Vault.setup()

  Returns `:ok` when the provider has no `c:setup/0`, so a host does not need a `case`
  over provider modules to know whether there is anything to do. Stops at the first
  error when a cache wrapper and the provider it wraps both define one.
  """
  @spec setup(module()) :: :ok | {:error, term()}
  def setup(vault_or_provider) when is_atom(vault_or_provider) do
    vault_or_provider
    |> chain()
    |> Enum.filter(&exports?(&1, :setup, 0))
    |> Enum.reduce_while(:ok, fn provider, :ok ->
      case provider.setup() do
        :ok -> {:cont, :ok}
        other -> {:halt, other}
      end
    end)
  end

  # A vault resolves to its key provider; a cache wrapper is accompanied by the provider
  # it wraps, innermost first so a supervised provider starts before the cache over it.
  defp chain(module) do
    provider =
      if exports?(module, :__ash_vault__, 1) do
        module.__ash_vault__(:key_provider)
      else
        module
      end

    Code.ensure_loaded(provider)

    Enum.uniq([unwrap_cached(provider), provider])
  end

  defp exports?(module, fun, arity) do
    Code.ensure_loaded?(module) and function_exported?(module, fun, arity)
  end

  @otp_apps_key {__MODULE__, :otp_apps}

  @doc """
  The configuration for a provider, from the host application's OTP app key first and
  `:ash_vault`'s second.

  Every provider AshVault ships reads its configuration through here, so all of them
  accept both of these, with the host application's winning on a key-by-key merge:

      # your application's own OTP app key — preferred
      config :my_app, AshVault.KeyProviders.OpenBao, address: "http://127.0.0.1:8200"

      # AshVault's OTP app key — the original form, still supported
      config :ash_vault, AshVault.KeyProviders.OpenBao, address: "http://127.0.0.1:8200"

  The host application is learned from your vault: `use AshVault.Vault` records the OTP
  application the vault module is compiled into (override it with `otp_app:`), and
  registers it the first time the vault module is loaded. You can also name it
  explicitly, which is what a library with no vault of its own would do:

      config :ash_vault, otp_app: :my_app

  ### Why this is not simply a keyword list on the vault

  A `AshVault.KeyProvider` callback takes a scope and nothing else — `current_key/1`,
  `get_key/2`, `rotate/1`, `destroy/1` — so there is no argument on any provider call
  site through which a vault could hand its provider a configuration. Provider
  configuration is therefore per **provider module**, globally, exactly as it was; the
  only thing that changed is which OTP application key it may be written under.
  """
  @spec config(module()) :: keyword()
  def config(provider) when is_atom(provider) do
    base = Application.get_env(:ash_vault, provider, [])

    Enum.reduce(otp_apps(), base, fn app, acc ->
      Keyword.merge(acc, Application.get_env(app, provider, []))
    end)
  end

  @doc """
  The host OTP applications provider configuration may be written under.

  `config :ash_vault, otp_app: :my_app` (an atom or a list) comes first, then whatever
  the loaded vault modules registered through `register_otp_app/1`.
  """
  @spec otp_apps() :: [atom()]
  def otp_apps do
    configured =
      case Application.get_env(:ash_vault, :otp_app) do
        nil -> []
        app when is_atom(app) -> [app]
        apps when is_list(apps) -> apps
      end

    Enum.uniq(configured ++ :persistent_term.get(@otp_apps_key, []))
  end

  @doc """
  Record `app` as an OTP application whose config `config/1` should consult.

  Called from a vault module's `@on_load`, so a vault's own application is registered
  before anything can reach a provider through that vault — a provider call site is only
  ever reached by way of a vault, and calling a vault loads it.

  `:ash_vault` itself is ignored: it is already `config/1`'s base.
  """
  @spec register_otp_app(atom() | nil) :: :ok
  def register_otp_app(app) when app in [nil, :ash_vault], do: :ok

  def register_otp_app(app) when is_atom(app) do
    apps = :persistent_term.get(@otp_apps_key, [])

    if app in apps do
      :ok
    else
      :persistent_term.put(@otp_apps_key, apps ++ [app])
      :ok
    end
  end
end
