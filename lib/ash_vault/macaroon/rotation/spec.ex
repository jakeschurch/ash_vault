defmodule AshVault.Macaroon.Rotation.Spec do
  @moduledoc """
  What one rotated credential is: produced by a `AshVault.Macaroon.Rotation.Source`
  from its own configuration (a Kubernetes object, a config file, a database row).

    * `:attributes` — input to the `issue_action`, minus the expiry attribute, which
      rotation sets
    * `:caveats` — caveats baked into every token minted for it (declared names)
    * `:lifetime` — seconds from mint to expiry, at most the macaroon's `max_ttl`. A
      successor is minted at two thirds of it; the last third is the overlap
    * `:quiet_period` — seconds a superseded credential must go unused before it is
      revoked; `nil` takes the DSL's `quiet_period`
    * `:consumers` — opaque to rotation, handed one by one to the delivery
    * `:ash_tenant` — the Ash tenant to issue, mint and read under (`:tenant`-scoped
      macaroons); `nil` otherwise
  """

  @enforce_keys [:lifetime, :consumers]
  defstruct attributes: %{},
            caveats: %{},
            lifetime: nil,
            quiet_period: nil,
            consumers: [],
            ash_tenant: nil

  @type t :: %__MODULE__{
          attributes: map(),
          caveats: map(),
          lifetime: pos_integer(),
          quiet_period: non_neg_integer() | nil,
          consumers: [term()],
          ash_tenant: term()
        }
end

defmodule AshVault.Macaroon.Rotation.Item do
  @moduledoc """
  One credential under rotation, as a `AshVault.Macaroon.Rotation.Source` lists it.

    * `:ref` — a stable name, unique per source (logs, telemetry, the staging slot)
    * `:spec` — a `AshVault.Macaroon.Rotation.Spec`, or `{:invalid, message}` for a
      configuration the source could not parse: it is reported, never acted on
    * `:state` — the `AshVault.Macaroon.Rotation.State` saved last time
    * `:meta` — anything the source needs back in `save/3` (an object's generation)
  """

  @enforce_keys [:ref, :spec, :state]
  defstruct [:ref, :spec, :state, :meta]

  @type t :: %__MODULE__{
          ref: String.t(),
          spec: AshVault.Macaroon.Rotation.Spec.t() | {:invalid, String.t()},
          state: AshVault.Macaroon.Rotation.State.t(),
          meta: term()
        }
end

defmodule AshVault.Macaroon.Rotation.Context do
  @moduledoc """
  Handed to every `AshVault.Macaroon.Rotation.Source` and
  `AshVault.Macaroon.Rotation.Delivery` callback.

  `:ref`, `:spec` and `:meta` are set while one item is reconciled, and `nil` in
  `c:AshVault.Macaroon.Rotation.Source.list/1`. `:now` is the reconcile's clock.
  """

  defstruct [:resource, :macaroon, :rotation, :actor, :now, :ref, :spec, :meta]

  @type t :: %__MODULE__{
          resource: module(),
          macaroon: AshVault.Macaroon.Definition.t(),
          rotation: AshVault.Macaroon.Rotation.Definition.t(),
          actor: term(),
          now: DateTime.t(),
          ref: String.t() | nil,
          spec: AshVault.Macaroon.Rotation.Spec.t() | nil,
          meta: term()
        }
end
