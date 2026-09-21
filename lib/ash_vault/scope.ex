defmodule AshVault.Scope do
  @moduledoc """
  Behaviour for resolving the *encryption scope* of an operation.

  A scope is the blast radius of a key: everything sharing a scope shares key material,
  and destroying a scope's key crypto-erases everything in it. For a multitenant
  application the scope is the tenant; for a single-tenant application it is a constant.

  Implementations must return a value that is **stable across processes and releases** —
  in practice a binary. Never derive a scope from `:erlang.term_to_binary/1` of a struct:
  the term encoding is not guaranteed stable between OTP releases, and stored ciphertext
  has to outlive OTP upgrades.

  Built-in implementations: `AshVault.Scopes.AshTenant` and `AshVault.Scopes.Global`.
  """

  @doc """
  Resolve the scope for an operation, raising `AshVault.Errors.MissingScope` when it
  cannot be determined.
  """
  @callback resolve!(AshVault.Context.t()) :: term()
end
