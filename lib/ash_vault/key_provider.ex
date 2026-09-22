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

  @optional_callbacks key_bytes: 0

  @default_key_bytes 32

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
end
