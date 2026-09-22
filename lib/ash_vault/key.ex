defmodule AshVault.Key do
  @moduledoc """
  An opaque handle to key material that may live outside the BEAM heap.

  This is the type a key provider hands to a cipher. It is deliberately a *union*:

      @type t :: binary() | %AshVault.Key{ref: reference(), owner: module()}

  A raw 32-byte binary is a perfectly valid `AshVault.Key.t()` and always will be. Every
  provider AshVault ships returns binaries, `AshVault.Ciphers.AES.GCM` takes binaries,
  and nothing about the struct form is required of anyone. The union exists so that a
  provider *may* return a handle whose key material never becomes an Elixir term at all.

  ## Why a handle

  `AshVault.KeyProviders.Cached` bounds how long a key is resident, but `get_key/2`
  still returns a binary, so a copy lands on an Elixir process heap for every encrypt
  and decrypt. The BEAM cannot zero that copy — the garbage collector owns its lifetime,
  and a refcounted binary can be referenced from heaps you never see.

  A handle closes that: the `:ref` is a `rustler::ResourceArc` (or any other NIF
  resource), the bytes live in native memory that can be `mlock`ed and zeroed on `Drop`,
  and the AEAD runs against the resource. The key is never an Elixir term, so there is
  nothing for the garbage collector to be late about.

  ## The contract

    * A provider MAY return `%AshVault.Key{}` from `get_key/2` or as the `:key` of
      `current_key/1`'s `key_info`.
    * A cipher MUST accept either. A cipher that cannot use an opaque key returns
      `{:error, :opaque_key_unsupported}`, and `AshVault.Vault.Runtime` raises
      `AshVault.Errors.OpaqueKeyUnsupported` naming the cipher — never a silent fallback
      to some other key, which would defeat the entire point.
    * `:owner` names the module that produced the handle, so that error can say who to
      talk to.

  ## Inspect is redacted

  The struct derives a redacted `Inspect`. A handle carries no bytes to leak, but a
  `#Reference<>` in a log line is still an invitation to correlate.
  """

  @derive {Inspect, only: [:owner]}
  defstruct [:ref, :owner]

  @typedoc """
  A key: either raw bytes, or an opaque handle to bytes held outside the BEAM heap.
  """
  @type t :: binary() | opaque()

  @typedoc "The handle form."
  @type opaque :: %__MODULE__{ref: reference(), owner: module()}

  @doc """
  Whether a key is an opaque handle rather than raw bytes.

  ## Examples

      iex> AshVault.Key.opaque?(<<0::256>>)
      false

  """
  @spec opaque?(t()) :: boolean()
  def opaque?(%__MODULE__{}), do: true
  def opaque?(_key), do: false

  @doc """
  The module that produced a handle, or `nil` for a raw binary key.

  ## Examples

      iex> AshVault.Key.owner(<<0::256>>)
      nil

  """
  @spec owner(t()) :: module() | nil
  def owner(%__MODULE__{owner: owner}), do: owner
  def owner(_key), do: nil

  @doc """
  Whether a term is a usable key at all.

  ## Examples

      iex> AshVault.Key.key?(<<0::256>>)
      true

      iex> AshVault.Key.key?(:nope)
      false

  """
  @spec key?(term()) :: boolean()
  def key?(key) when is_binary(key), do: true
  def key?(%__MODULE__{ref: ref}) when is_reference(ref), do: true
  def key?(_key), do: false
end
