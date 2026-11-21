defmodule AshVault.Macaroon.Rotation.State do
  @moduledoc """
  Where one credential's rotation stands. It holds credential ids and times, never a
  token, so a source may store it anywhere (a Kubernetes status, a database column).

    * `:current` — the credential consumers are expected to use
    * `:pending` — a minted successor not yet delivered to every consumer
    * `:previous` — the superseded credential, kept until it goes unused for the quiet
      period
    * `:failure` — the last reconcile's failure, if any
    * `:phase` — `"Pending"` (nothing minted yet), `"Ready"`, `"Rotating"` (a pending or
      previous credential exists) or `"Failed"` (a failure and no current credential)

  `to_map/1` and `from_map/1` give the stored form: camelCase string keys, ISO 8601
  times. Every key is always present (`nil` when empty), so the map works as a JSON
  merge patch that also clears what is gone.
  """

  alias AshVault.Macaroon.Rotation.Entry
  alias AshVault.Macaroon.Rotation.Failure

  defstruct [
    :current,
    :pending,
    :previous,
    :failure,
    :last_rotation_at,
    :last_reconcile_at,
    phase: "Pending"
  ]

  @type t :: %__MODULE__{
          current: Entry.t() | nil,
          pending: Entry.t() | nil,
          previous: Entry.t() | nil,
          failure: Failure.t() | nil,
          last_rotation_at: DateTime.t() | nil,
          last_reconcile_at: DateTime.t() | nil,
          phase: String.t()
        }

  @doc "The stored form."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = state) do
    %{
      "phase" => state.phase,
      "current" => Entry.to_map(state.current),
      "pending" => Entry.to_map(state.pending),
      "previous" => Entry.to_map(state.previous),
      "failure" => Failure.to_map(state.failure),
      "lastRotationTime" => iso(state.last_rotation_at),
      "lastReconcileTime" => iso(state.last_reconcile_at)
    }
  end

  @doc "Read the stored form back. Unknown keys are ignored; `nil` is the empty state."
  @spec from_map(map() | nil) :: t()
  def from_map(nil), do: %__MODULE__{}

  def from_map(%{} = map) do
    %__MODULE__{
      phase: map["phase"] || "Pending",
      current: Entry.from_map(map["current"]),
      pending: Entry.from_map(map["pending"]),
      previous: Entry.from_map(map["previous"]),
      failure: Failure.from_map(map["failure"]),
      last_rotation_at: time(map["lastRotationTime"]),
      last_reconcile_at: time(map["lastReconcileTime"])
    }
  end

  @doc false
  def iso(nil), do: nil
  def iso(%DateTime{} = at), do: DateTime.to_iso8601(at)

  @doc false
  def time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, at, _offset} -> at
      _ -> nil
    end
  end

  def time(_value), do: nil
end

defmodule AshVault.Macaroon.Rotation.Entry do
  @moduledoc """
  One credential in a `AshVault.Macaroon.Rotation.State`: its id and times.

  `:delivered` maps each consumer's name to when it was handed this credential.
  `:superseded_at` and `:in_use` are set once it is `previous`.
  """

  alias AshVault.Macaroon.Rotation.State

  @enforce_keys [:id, :issued_at, :expires_at, :rotate_at]
  defstruct [
    :id,
    :issued_at,
    :expires_at,
    :rotate_at,
    :superseded_at,
    in_use: false,
    delivered: %{}
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          issued_at: DateTime.t(),
          expires_at: DateTime.t(),
          rotate_at: DateTime.t(),
          superseded_at: DateTime.t() | nil,
          in_use: boolean(),
          delivered: %{optional(String.t()) => DateTime.t()}
        }

  @doc false
  def to_map(nil), do: nil

  def to_map(%__MODULE__{} = entry) do
    %{
      "id" => entry.id,
      "issuedAt" => State.iso(entry.issued_at),
      "expiresAt" => State.iso(entry.expires_at),
      "rotateAt" => State.iso(entry.rotate_at),
      "supersededAt" => State.iso(entry.superseded_at),
      "inUse" => if(entry.in_use, do: true),
      "delivered" =>
        if(entry.delivered == %{},
          do: nil,
          else: Map.new(entry.delivered, fn {name, at} -> {name, State.iso(at)} end)
        )
    }
  end

  @doc false
  def from_map(%{"id" => id} = map) when is_binary(id) do
    with %DateTime{} = expires_at <- State.time(map["expiresAt"]),
         %DateTime{} = rotate_at <- State.time(map["rotateAt"]) do
      %__MODULE__{
        id: id,
        issued_at: State.time(map["issuedAt"]) || expires_at,
        expires_at: expires_at,
        rotate_at: rotate_at,
        superseded_at: State.time(map["supersededAt"]),
        in_use: map["inUse"] == true,
        delivered: delivered(map["delivered"])
      }
    else
      # An entry whose times cannot be read is still a credential that exists: keep the
      # id so it is retired rather than forgotten, and make it due at once.
      _ ->
        epoch = DateTime.from_unix!(0)

        %__MODULE__{
          id: id,
          issued_at: epoch,
          expires_at: epoch,
          rotate_at: epoch,
          superseded_at: State.time(map["supersededAt"])
        }
    end
  end

  def from_map(_other), do: nil

  defp delivered(%{} = map) do
    for {name, at} <- map,
        is_binary(name),
        %DateTime{} = time <- [State.time(at)],
        into: %{},
        do: {name, time}
  end

  defp delivered(_other), do: %{}
end

defmodule AshVault.Macaroon.Rotation.Failure do
  @moduledoc """
  Why the last reconcile of a credential did not complete.

  `:reason` is one of `:invalid_spec`, `:mint`, `:staging`, `:staging_lost`,
  `:distribution`, `:retire` or `:status` (the source's `save/3` failed). It is stored
  camelized (`"StagingLost"`). `:message` never holds a token or an inspected struct.
  """

  @enforce_keys [:reason, :message]
  defstruct [:reason, :message, :time]

  @type reason ::
          :invalid_spec | :mint | :staging | :staging_lost | :distribution | :retire | :status

  @type t :: %__MODULE__{reason: reason() | String.t(), message: String.t(), time: DateTime.t()}

  @doc false
  def to_map(nil), do: nil

  def to_map(%__MODULE__{} = failure) do
    reason =
      case failure.reason do
        atom when is_atom(atom) -> Macro.camelize(Atom.to_string(atom))
        string -> string
      end

    %{
      "reason" => reason,
      "message" => failure.message,
      "time" => AshVault.Macaroon.Rotation.State.iso(failure.time)
    }
  end

  @doc false
  def from_map(%{"reason" => reason} = map) when is_binary(reason),
    do: %__MODULE__{
      reason: reason,
      message: map["message"] || "",
      time: AshVault.Macaroon.Rotation.State.time(map["time"])
    }

  def from_map(_other), do: nil
end
