defmodule AshVaultRustler.KeyProviders.Opaque do
  @moduledoc """
  Wraps a key provider so that it hands out `%AshVault.Key{}` handles instead of binaries.

  This is the level-2 path: with `AshVaultRustler.Cipher` as the vault's cipher, the key
  never becomes an Elixir term during an encrypt or a decrypt.

      defmodule MyApp.OpaqueKeys do
        use AshVaultRustler.KeyProviders.Opaque, provider: AshVault.KeyProviders.OpenBao
      end

      use AshVault.Vault,
        key_provider: MyApp.OpaqueKeys,
        cipher: AshVaultRustler.Cipher

  ## The honest boundary

  The wrapped provider returns a binary — it has to, that is its contract — so the key
  bytes *do* pass through the BEAM once, on the way into the handle. What this removes is
  the per-operation copy: every subsequent encrypt and decrypt against that handle touches
  native memory only. Combined with `AshVault.KeyProviders.Cached`, which collapses many
  operations onto one provider fetch, the number of times key bytes exist as an Elixir
  term goes from "once per encrypted field read" to "once per cache miss".

  Removing even that last copy would need a provider that speaks to the key store from
  Rust. That is not this package.

  ## Misconfiguration is loud

  If the vault's cipher cannot take a handle — `AshVault.Ciphers.AES.GCM`, for instance —
  it returns `{:error, :opaque_key_unsupported}` and `AshVault.Vault.Runtime` raises
  `AshVault.Errors.OpaqueKeyUnsupported`, naming both modules. There is deliberately no
  fallback that unwraps the handle: doing so would put the key back on the BEAM heap,
  which is the one thing the handle exists to prevent, and would do it silently.

  ## Options

    * `:provider` — **required**, the wrapped `AshVault.KeyProvider`.
  """

  alias AshVaultRustler.Native

  @type opts :: %{provider: module()}

  @doc false
  @spec build_opts!(module(), keyword()) :: opts()
  def build_opts!(module, opts) do
    provider =
      Keyword.get(opts, :provider) ||
        raise ArgumentError, """
        `use AshVaultRustler.KeyProviders.Opaque` requires a `:provider` to wrap.

            defmodule #{inspect(module)} do
              use AshVaultRustler.KeyProviders.Opaque, provider: MyApp.Keys
            end
        """

    unless is_atom(provider) do
      raise ArgumentError,
            "AshVaultRustler.KeyProviders.Opaque `:provider` must be a module, got: " <>
              inspect(provider)
    end

    %{provider: provider}
  end

  @doc """
  Fetch the current key as a `key_info` whose `:key` is an opaque handle.
  """
  @spec current_key(AshVault.KeyProvider.scope(), opts()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope, opts) do
    case opts.provider.current_key(scope) do
      {:ok, %{key: key} = info} when is_binary(key) ->
        case handle(key) do
          {:ok, opaque} -> {:ok, %{info | key: opaque}}
          {:error, _reason} = error -> error
        end

      other ->
        other
    end
  end

  @doc """
  Fetch a specific key version as an opaque handle.
  """
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version(), opts()) ::
          {:ok, AshVault.Key.opaque()} | {:error, term()}
  def get_key(scope, version, opts) do
    case opts.provider.get_key(scope, version) do
      {:ok, key} when is_binary(key) -> handle(key)
      other -> other
    end
  end

  defp handle(key) do
    case Native.key_handle_new(key) do
      ref when is_reference(ref) ->
        {:ok, %AshVault.Key{ref: ref, owner: __MODULE__}}

      # A wrong-sized key is a configuration fault, and the vault has a distinct,
      # non-retryable error for exactly that — so report the size rather than a generic
      # failure that an operator would retry forever.
      {:error, :invalid_key_size} ->
        {:error, {:invalid_key_size, byte_size(key)}}
    end
  rescue
    ArgumentError -> {:error, {:invalid_key_size, byte_size(key)}}
  end

  @doc """
  Whether a handle's pages are locked into RAM.
  """
  @spec mlocked?(AshVault.Key.opaque()) :: boolean()
  def mlocked?(%AshVault.Key{ref: ref}), do: Native.key_handle_mlocked(ref)

  @doc """
  Constant-time comparison of a handle against candidate key bytes.

  For tests. The result of this comparison is a fact about key material, so it is
  constant time even though only a test should ever ask.
  """
  @spec matches?(AshVault.Key.opaque(), binary()) :: boolean()
  def matches?(%AshVault.Key{ref: ref}, candidate), do: Native.key_handle_matches(ref, candidate)

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour AshVault.KeyProvider

      @ash_vault_opaque_opts AshVaultRustler.KeyProviders.Opaque.build_opts!(__MODULE__, opts)

      @doc "Fetch the current key for a scope as an opaque handle."
      @impl AshVault.KeyProvider
      @spec current_key(AshVault.KeyProvider.scope()) ::
              {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
      def current_key(scope),
        do: AshVaultRustler.KeyProviders.Opaque.current_key(scope, @ash_vault_opaque_opts)

      @doc "Fetch a specific key version for a scope as an opaque handle."
      @impl AshVault.KeyProvider
      @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
              {:ok, AshVault.Key.opaque()} | {:error, term()}
      def get_key(scope, version),
        do: AshVaultRustler.KeyProviders.Opaque.get_key(scope, version, @ash_vault_opaque_opts)

      @doc "Rotate the wrapped provider's key for a scope."
      @impl AshVault.KeyProvider
      @spec rotate(AshVault.KeyProvider.scope()) ::
              {:ok, AshVault.KeyProvider.version()} | {:error, term()}
      def rotate(scope), do: @ash_vault_opaque_opts.provider.rotate(scope)

      @doc "Destroy every key for a scope at the wrapped provider."
      @impl AshVault.KeyProvider
      @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
      def destroy(scope), do: @ash_vault_opaque_opts.provider.destroy(scope)

      @doc "The key size the wrapped provider mints."
      @impl AshVault.KeyProvider
      @spec key_bytes() :: pos_integer()
      def key_bytes, do: AshVault.KeyProvider.key_bytes(@ash_vault_opaque_opts.provider)

      @doc "The wrapped provider."
      @spec __ash_vault_opaque__() :: map()
      def __ash_vault_opaque__, do: @ash_vault_opaque_opts
    end
  end
end
