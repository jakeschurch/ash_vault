defmodule AshVault.RotationPolicies.Manual do
  @moduledoc """
  The default rotation policy: never rotate automatically.

  Keys are rotated only by an explicit `rotate!/1` call on a vault (or
  `AshVault.rotate_key!/2`).
  """

  @behaviour AshVault.RotationPolicy

  alias AshVault.RotationPolicy

  @policy %RotationPolicy{strategy: :manual}

  @doc """
  Always returns `%AshVault.RotationPolicy{strategy: :manual}`.
  """
  @impl AshVault.RotationPolicy
  @spec policy(term(), AshVault.Context.t()) :: RotationPolicy.t()
  def policy(_scope, _context), do: @policy
end
