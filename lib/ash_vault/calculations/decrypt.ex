defmodule AshVault.Calculations.Decrypt do
  @moduledoc """
  Decrypts the `encrypted_<field>` attribute back into a value of the original type.

  `load/3` returning `[:"encrypted_<field>"]` is the *entire* dependency declaration. Ash
  then auto-selects that attribute even though it is `public?: false` — `ensure_selected/2`
  does not consult `public?` — records it in `query.context[:private][:depended_on_fields]`,
  and strips it from the returned record, so ciphertext never leaks into results the caller
  did not ask for.

  ## Errors are values

  This calculation returns `{:error, %AshVault.Errors.*{}}` and never raises. That is a
  deliberate departure from ash_cloak, which raises throughout its crypto path because
  Cloak's API is bang-only. AshVault's errors are Splode errors with `class: :invalid`, so
  Ash wraps them correctly and a destroyed tenant comes out of `Ash.read/2` as a clean
  `AshVault.Errors.KeyDestroyed` rather than a 500.

  It never returns `:unknown` either — to Ash that means "fall back to the data layer",
  which for an encrypted field would silently produce ciphertext or nil.

  ## Field policies

  A field policy denying the backing attribute makes `Map.get/2` return
  `%Ash.ForbiddenField{}`, which is passed through untouched. AshVault does not
  re-implement authorization: if a read reaches this calculation, Ash already authorized it.
  """

  use Ash.Resource.Calculation

  @doc false
  @impl Ash.Resource.Calculation
  def load(_query, opts, _context), do: [opts[:field]]

  @doc false
  @impl Ash.Resource.Calculation
  def calculate([], _opts, _context), do: {:ok, []}

  def calculate([%resource{} | _] = records, opts, context) do
    plain_field = opts[:plain_field]
    encrypted_field = opts[:field]

    %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(resource, plain_field)
    ctx = AshVault.Context.Builder.from_calculation(resource, plain_field, context)
    # Always resolve the vault against the *normalized* ash_context, so a `fun/2` or MFA
    # vault sees the same shape on the read path as it does on the write path.
    vault = AshVault.Info.vault!(resource, ctx.ash_context)

    records
    |> Enum.reduce_while({:ok, []}, fn record, {:ok, acc} ->
      case Map.get(record, encrypted_field) do
        nil ->
          {:cont, {:ok, [nil | acc]}}

        %Ash.ForbiddenField{} = forbidden ->
          {:cont, {:ok, [forbidden | acc]}}

        blob ->
          case AshVault.decrypt_value(vault, blob, ctx, type, constraints) do
            {:ok, value} -> {:cont, {:ok, [value | acc]}}
            {:error, error} -> {:halt, {:error, error}}
          end
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      {:error, error} -> {:error, error}
    end
  end
end
