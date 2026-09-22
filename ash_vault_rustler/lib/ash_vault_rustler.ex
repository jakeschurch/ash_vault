defmodule AshVaultRustler do
  @moduledoc """
  A Rust-backed key cache and AES-256-GCM cipher for AshVault.

  Three things live here, and they are independent — take one, two or all three:

    * `AshVaultRustler.KeyCache` — an `AshVault.KeyCache` backend whose eviction
      **zeroes** the key bytes, rather than dropping a reference and hoping. Plugs into
      `AshVault.KeyProviders.Cached` (and therefore into the vault's `cache:` option).
    * `AshVaultRustler.Cipher` — AES-256-GCM in Rust, wire-compatible with
      `AshVault.Ciphers.AES.GCM` in both directions, and able to work against an opaque
      key handle.
    * `AshVaultRustler.KeyProviders.Opaque` — wraps any provider so it hands out
      `%AshVault.Key{}` handles, so the key never becomes an Elixir term during an encrypt
      or a decrypt.

  See the README for what this does and does not buy, and for the distribution story.

  The parent `ash_vault` has no Rust dependency and never will; this package is optional.
  """

  alias AshVaultRustler.Native

  @doc """
  Whether the NIF loaded.

      iex> is_boolean(AshVaultRustler.available?())
      true

  """
  @spec available?() :: boolean()
  def available? do
    _ = Native.mlock_status()
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  @doc """
  `%{locked: n, failed: n}` — how many secret allocations were locked into RAM, and how
  many could not be.

  A non-zero `:failed` means `RLIMIT_MEMLOCK` is too low and some key material may reach
  swap or a hibernation image. Raise it with `ulimit -l`, or `LimitMEMLOCK=` in a systemd
  unit. Worth an alert in production.
  """
  @spec mlock_status() :: %{locked: non_neg_integer(), failed: non_neg_integer()}
  def mlock_status do
    {locked, failed} = Native.mlock_status()
    %{locked: locked, failed: failed}
  end
end
