defmodule AshVault.Macaroon.Rotation.Definition do
  @moduledoc """
  The target of the `rotation` entity nested in a `macaroon`. See `AshVault.Dsl` and
  [Macaroon rotation](macaroon-rotation.md).

  It holds wiring only. What a rotated credential grants, how long it lives and who
  receives it are per credential and come from the `source` at runtime
  (`AshVault.Macaroon.Rotation.Spec`).
  """

  defstruct [
    :source,
    :delivery,
    :issue_action,
    :revoke_action,
    :rotate_action,
    expires_at_attribute: :expires_at,
    last_used_at_attribute: :last_used_at,
    quiet_period: 3600,
    __identifier__: nil,
    __spark_metadata__: nil
  ]

  @type t :: %__MODULE__{
          source: module(),
          delivery: module(),
          issue_action: atom(),
          revoke_action: atom(),
          rotate_action: atom() | nil,
          expires_at_attribute: atom(),
          last_used_at_attribute: atom(),
          quiet_period: pos_integer()
        }

  @doc "The generated rotate action's name: `rotate_action`, or `:rotate_<macaroon>`."
  @spec rotate_action(t(), atom()) :: atom()
  def rotate_action(%__MODULE__{rotate_action: nil}, macaroon), do: :"rotate_#{macaroon}"
  def rotate_action(%__MODULE__{rotate_action: action}, _macaroon), do: action
end
