defmodule AshVault.DecryptFor do
  @moduledoc """
  Evaluates an `encrypt ..., decrypt_for: [...]` list against an actor.

  Entries:

    * an `Ash.Policy.SimpleCheck` module — `match?(actor, %{action: action}, [])`
    * `{check, opts}` — the same, with `opts` passed to the check
    * `{check, only: [action_name]}` (`:only` may be combined with check opts) — matches
      only on those actions. On the decrypt calculation, where no action is known, such
      an entry never matches.
    * `&Mod.fun/1` — a remote actor predicate (the DSL cannot hold anonymous functions)

  A `nil` actor never matches. Unset (`nil`) `decrypt_for` admits everyone.
  """

  @type entry ::
          module()
          | {module(), keyword()}
          | (term() -> boolean())

  @doc "Whether `actor` may have the field decrypted on `action` (`nil` when unknown)."
  @spec allowed?([entry()] | nil, term(), term()) :: boolean()
  def allowed?(nil, _actor, _action), do: true
  def allowed?(_entries, nil, _action), do: false

  def allowed?(entries, actor, action) do
    Enum.any?(entries, &match_entry?(&1, actor, action_name(action)))
  end

  defp action_name(%{name: name}), do: name
  defp action_name(name) when is_atom(name), do: name
  defp action_name(_action), do: nil

  defp match_entry?(fun, actor, _action) when is_function(fun, 1), do: fun.(actor) == true

  defp match_entry?({check, opts}, actor, action) when is_atom(check) and is_list(opts) do
    case Keyword.pop(opts, :only) do
      {nil, check_opts} ->
        check_matches?(check, actor, action, check_opts)

      {only, check_opts} ->
        not is_nil(action) and action in List.wrap(only) and
          check_matches?(check, actor, action, check_opts)
    end
  end

  defp match_entry?(check, actor, action) when is_atom(check),
    do: check_matches?(check, actor, action, [])

  defp match_entry?(_entry, _actor, _action), do: false

  defp check_matches?(check, actor, action, opts) do
    check.match?(actor, %{action: action}, opts) == true
  end
end
