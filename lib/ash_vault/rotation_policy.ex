defmodule AshVault.RotationPolicy do
  @moduledoc """
  Describes when a scope's key should be rotated, and the behaviour that supplies it.

  A policy is a plain struct:

    * `:strategy` — `:manual` (rotate only when asked), `:age` (rotate once the current
      key is older than `:max_age`), or `:provider` (the key provider decides, e.g. a KMS
      with its own rotation schedule)
    * `:max_age` — an `Elixir.Duration`, only meaningful for `:age`
    * `:rotate_on_write?` — whether a write should opportunistically trigger rotation

  Rotation triggered by a write is always best-effort: a failing rotation must never fail
  the write.
  """

  defstruct strategy: :manual, max_age: nil, rotate_on_write?: false

  @type strategy :: :manual | :age | :provider

  @type t :: %__MODULE__{
          strategy: strategy(),
          max_age: Duration.t() | nil,
          rotate_on_write?: boolean()
        }

  @doc """
  Return the rotation policy in force for a scope and operation.
  """
  @callback policy(scope :: term(), AshVault.Context.t()) :: t()

  @doc """
  Whether the given key is due for rotation under this policy.

  `:manual` and `:provider` are never due — rotation is driven from outside. `:age` is
  due once `key_info.created_at` is older than `now` minus `:max_age`.

  ## Examples

      policy = %AshVault.RotationPolicy{strategy: :manual}
      AshVault.RotationPolicy.due?(policy, key_info)
      #=> false

  """
  @spec due?(t(), AshVault.KeyProvider.key_info(), DateTime.t()) :: boolean()
  def due?(policy, key_info, now \\ DateTime.utc_now())

  def due?(
        %__MODULE__{strategy: :age, max_age: %Duration{} = max_age},
        %{created_at: created_at},
        now
      )
      when not is_nil(created_at) do
    cutoff = DateTime.shift(now, Duration.negate(max_age))
    DateTime.compare(created_at, cutoff) == :lt
  end

  def due?(%__MODULE__{}, _key_info, _now), do: false
end
