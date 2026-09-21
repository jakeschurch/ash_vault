defmodule AshVault do
  @moduledoc """
  Documentation for `AshVault`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> AshVault.hello()
      :world

  """
  def hello do
    :world
  end

  @doc """
  Rotate the key for `scope` in `vault`, minting a new key version.

  Existing values keep decrypting with their original key version; new writes use the
  new one.
  """
  @spec rotate_key!(module(), term()) :: {:ok, non_neg_integer()}
  def rotate_key!(vault, scope), do: vault.rotate!(scope)

  @doc """
  Crypto-erase `scope` in `vault`: destroy every key version and tombstone the scope.

  This is irreversible. Every value encrypted under `scope` becomes permanently
  unrecoverable, and later reads raise `AshVault.Errors.KeyDestroyed`.
  """
  @spec destroy_keys!(module(), term()) :: :ok
  def destroy_keys!(vault, scope), do: vault.destroy!(scope)
end
