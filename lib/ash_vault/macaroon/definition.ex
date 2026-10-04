defmodule AshVault.Macaroon.Definition do
  @moduledoc """
  The target of the `macaroon` entity in the `ash_vault` section. See `AshVault.Dsl` for
  the options and [Macaroons](macaroons.md) for the design.
  """

  defstruct [
    :name,
    :prefix,
    :identity,
    :revoked_when,
    :default_ttl,
    :max_ttl,
    :mint_action,
    :read_action,
    :__identifier__,
    accepted_key_versions: 1,
    require_authorize_enforcement?: false,
    caveats: [],
    __spark_metadata__: nil
  ]

  @type t :: %__MODULE__{
          name: atom(),
          prefix: binary(),
          identity: atom(),
          revoked_when: term(),
          default_ttl: pos_integer() | :infinity | {module(), keyword()},
          max_ttl: pos_integer() | :infinity | nil,
          accepted_key_versions: pos_integer() | :all | mfa() | {module(), keyword()},
          require_authorize_enforcement?: boolean(),
          mint_action: atom() | nil,
          read_action: atom() | nil,
          caveats: [AshVault.Macaroon.CaveatDefinition.t()]
        }

  @doc "The generated mint action's name: `mint_action`, or `:mint_<name>`."
  @spec mint_action(t()) :: atom()
  def mint_action(%__MODULE__{mint_action: nil, name: name}), do: :"mint_#{name}"
  def mint_action(%__MODULE__{mint_action: action}), do: action

  @doc """
  The `field` of the vault context a macaroon's root signature is computed under:
  `:"macaroon:<name>"`.

  A reserved label rather than the bare name, so that no ordinary `Vault.mac!/2` call
  for an attribute or field of the same resource — whose field is an attribute name and
  never contains `:` — shares associated data with the root signature. Otherwise code
  that MACs caller-chosen bytes for a field named like the macaroon would be an oracle
  for forging root signatures.
  """
  @spec vault_field(t()) :: atom()
  def vault_field(%__MODULE__{name: name}), do: :"macaroon:#{name}"

  @doc "The generated verifying read action's name: `read_action`, or `:<name>_by_token`."
  @spec read_action(t()) :: atom()
  def read_action(%__MODULE__{read_action: nil, name: name}), do: :"#{name}_by_token"
  def read_action(%__MODULE__{read_action: action}), do: action
end

defmodule AshVault.Macaroon.CaveatDefinition do
  @moduledoc """
  The target of the `caveat` entity nested in a `macaroon`. See `AshVault.Dsl`.
  """

  defstruct [
    :name,
    :type,
    :check,
    :__identifier__,
    phase: :verify,
    constraints: [],
    __spark_metadata__: nil
  ]

  @type t :: %__MODULE__{
          name: atom(),
          type: term(),
          check: {module(), keyword()},
          phase: :verify | :authorize,
          constraints: keyword()
        }
end

defmodule AshVault.Macaroon.Verified do
  @moduledoc """
  What a verified macaroon proved, attached to the loaded record as the `:macaroon`
  metadata (`record.__metadata__.macaroon`), alongside `using_macaroon?: true`.

  `caveats` is every caveat the token carried, in chain order, as `{name, value}` with
  `name` an atom from the macaroon's declaration (or `:expires_at`). `authorize_caveats`
  is the subset whose `phase: :authorize` checks have **not** run yet — they are enforced
  by `AshVault.Checks.MacaroonAllows` at authorization time.

  It carries no token bytes and no signature.
  """

  defstruct [
    :resource,
    :macaroon,
    :scope,
    :key_version,
    :id,
    :expires_at,
    caveats: [],
    authorize_caveats: []
  ]

  @type t :: %__MODULE__{
          resource: module(),
          macaroon: atom(),
          scope: binary(),
          key_version: pos_integer(),
          id: binary(),
          expires_at: DateTime.t() | nil,
          caveats: [{atom(), term()}],
          authorize_caveats: [{atom(), term()}]
        }

  defimpl Inspect do
    def inspect(verified, opts) do
      Inspect.Algebra.concat([
        "#AshVault.Macaroon.Verified<",
        Inspect.Algebra.to_doc(
          %{
            resource: verified.resource,
            macaroon: verified.macaroon,
            key_version: verified.key_version,
            caveats: Enum.map(verified.caveats, &elem(&1, 0))
          },
          opts
        ),
        ">"
      ])
    end
  end
end

defmodule AshVault.Macaroon.CheckContext do
  @moduledoc """
  What a caveat check is handed alongside the caveat's value.

    * `:phase` — `:verify` (inside the verifying read, after the record is loaded) or
      `:authorize` (inside `AshVault.Checks.MacaroonAllows`)
    * `:now` — the verifier's clock (`AshVault.Macaroon.Clock`), never caller-supplied
    * `:resource`, `:macaroon`, `:scope`, `:tenant`, `:actor`
    * `:record` — the record the token names (`:verify`), or the actor (`:authorize`)
    * `:action` — the action being authorized (`:authorize` only)
    * `:subject` — the query, changeset or action input being authorized (`:authorize`
      only)
    * `:context` — the Ash context of the verifying read or authorized action. It is
      request-supplied: a check may use it as the *request* a caveat restricts (an IP, a
      path), never as a source of trust.
  """

  defstruct [
    :phase,
    :now,
    :resource,
    :macaroon,
    :scope,
    :tenant,
    :actor,
    :record,
    :action,
    :subject,
    context: %{}
  ]

  @type t :: %__MODULE__{}
end

defmodule AshVault.Macaroon.Clock do
  @moduledoc """
  The clock macaroon expiry is checked against.

  `DateTime.utc_now/0` unless `config :ash_vault, :macaroon_clock, {m, f, a}` names
  another — a test seam. The clock is deliberately **not** read from query or request
  context: plugs forward request context into Ash, and a caller-controlled clock would
  turn expiry off.
  """

  @doc "The current time."
  @spec now() :: DateTime.t()
  def now do
    case Application.get_env(:ash_vault, :macaroon_clock) do
      {module, function, args} -> apply(module, function, args)
      nil -> DateTime.utc_now()
    end
  end
end
