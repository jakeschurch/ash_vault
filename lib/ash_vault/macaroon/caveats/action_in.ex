defmodule AshVault.Macaroon.Caveats.ActionIn do
  @moduledoc """
  An `:authorize`-phase caveat check: admits the request only if the action being
  authorized is named in the caveat's list.

      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn

  With `qualified?: true` the names are `"Resource.action"` (`inspect(resource) <> "." <>
  action`), for tokens that must be limited across resources.

  In the `:verify` phase there is no action yet, so it refuses: declare it
  `phase: :authorize`.
  """

  @behaviour AshVault.Macaroon.Caveat

  @impl AshVault.Macaroon.Caveat
  def check(allowed, %AshVault.Macaroon.CheckContext{action: %{name: name}} = context, opts)
      when is_list(allowed) do
    candidate =
      if Keyword.get(opts, :qualified?, false),
        do: inspect(subject_resource(context)) <> "." <> to_string(name),
        else: to_string(name)

    candidate in allowed
  end

  def check(_allowed, _context, _opts), do: false

  defp subject_resource(%{subject: %{resource: resource}}), do: resource
  defp subject_resource(%{resource: resource}), do: resource
end
