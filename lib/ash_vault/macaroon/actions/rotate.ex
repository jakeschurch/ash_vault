defmodule AshVault.Macaroon.Actions.Rotate do
  @moduledoc """
  Backs the generated rotate action (`rotate_action`, default `:rotate_<macaroon>`) of a
  macaroon with a `rotation`: one `AshVault.Macaroon.Rotation.run/3` as the action's
  actor. Returns `true` when the source listed its credentials (each credential's own
  failures are in its state and telemetry), `false` when it could not.

  Schedule it, e.g. with AshOban:

      oban do
        scheduled_actions do
          schedule :rotate, "* * * * *" do
            action :rotate
            default_actor %MyApp.Operator{}
            max_attempts 1
          end
        end
      end

  The resource's policies apply to the action and to every action rotation runs (issue,
  mint, read, revoke) with the same actor.
  """

  use Ash.Resource.Actions.Implementation

  @impl Ash.Resource.Actions.Implementation
  def run(input, opts, context) do
    case AshVault.Macaroon.Rotation.run(input.resource, Keyword.fetch!(opts, :macaroon),
           actor: context.actor
         ) do
      :ok -> {:ok, true}
      {:error, _reason} -> {:ok, false}
    end
  end
end
