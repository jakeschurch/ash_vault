defmodule AshVault.Checks.MacaroonAllows do
  @moduledoc """
  A policy check: true when the actor was authenticated by a macaroon and every
  `phase: :authorize` caveat that macaroon carries admits the action being authorized.

      policies do
        policy always() do
          forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api}
          authorize_if actor_present()
        end
      end

  The actor is the record returned by a verifying read (`:<name>_by_token`, or your
  own action using `AshVault.Macaroon.Preparations.Verify`), which carries
  `__metadata__.macaroon`. The check evaluates the authorize-phase caveats against an
  `AshVault.Macaroon.CheckContext` whose `:action` and `:subject` are the action and
  query/changeset being authorized.

  ## Options

    * `:macaroon` — only accept this macaroon (any macaroon when omitted)
    * `:when_absent` — the answer for an actor without a verified macaroon: `false`
      (default) or `true`. Use `true` to let session-authenticated actors through a
      `forbid_unless`, while macaroon actors are held to their caveats.

  > #### Authorize-phase caveats are enforced only here {: .warning}
  >
  > The verifying read runs `phase: :verify` checks. A `phase: :authorize` caveat is
  > enforced by this check and nowhere else: a resource whose policies never use it
  > does not restrict a macaroon actor by those caveats. A token holder — or a third
  > party handed an attenuated token — cannot tell which resources enforce them, so an
  > `actions: ["read"]` caveat is a promise only as good as your policy coverage.
  > `AshVault.Verifiers.VerifyMacaroons` warns when the declaring resource itself never
  > uses this check; `require_authorize_enforcement? true` on the macaroon refuses such
  > tokens unless the verifying caller asserts enforcement.

  > #### `when_absent: true` and reloaded actors {: .warning}
  >
  > The macaroon lives in the actor's `__metadata__`. Anything that re-reads the actor —
  > `Ash.reload/2`, `Ash.get/3`, a session that stores only the id and loads the record
  > per request — returns a record **without** it, and with `when_absent: true` that
  > record passes as an actor that never used a macaroon: every authorize-phase caveat
  > silently stops applying. Keep the record the verifying read returned as the actor
  > (`Ash.load/3` on it preserves metadata), or use the default `when_absent: false` on
  > resources only macaroon actors should reach.
  """

  use Ash.Policy.SimpleCheck

  alias AshVault.Macaroon.CheckContext
  alias AshVault.Macaroon.Verified

  @impl Ash.Policy.Check
  def describe(opts) do
    case Keyword.get(opts, :macaroon) do
      nil -> "actor's macaroon allows this action"
      name -> "actor's #{inspect(name)} macaroon allows this action"
    end
  end

  @impl Ash.Policy.SimpleCheck
  def match?(actor, context, opts) do
    case verified(actor, Keyword.get(opts, :macaroon)) do
      %Verified{} = verified -> allows?(actor, verified, context)
      nil -> Keyword.get(opts, :when_absent, false) == true
    end
  end

  defp verified(%{__metadata__: %{macaroon: %Verified{macaroon: name} = verified}}, wanted)
       when is_nil(wanted) or wanted == name,
       do: verified

  defp verified(_actor, _wanted), do: nil

  defp allows?(actor, verified, context) do
    case AshVault.Info.macaroon(verified.resource, verified.macaroon) do
      nil ->
        false

      definition ->
        subject =
          Map.get(context, :subject) || Map.get(context, :query) || Map.get(context, :changeset)

        check_context = %CheckContext{
          phase: :authorize,
          now: AshVault.Macaroon.Clock.now(),
          resource: Map.get(context, :resource),
          macaroon: verified.macaroon,
          scope: verified.scope,
          tenant: subject && Map.get(subject, :tenant),
          actor: actor,
          record: actor,
          action: Map.get(context, :action),
          subject: subject,
          context: (subject && Map.get(subject, :context)) || %{}
        }

        AshVault.Macaroon.Runtime.check_caveats(
          verified.resource,
          definition,
          verified.authorize_caveats,
          :authorize,
          check_context
        ) == :ok
    end
  end
end
