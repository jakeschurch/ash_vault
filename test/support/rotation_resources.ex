defmodule AshVault.Test.RotationDomain do
  @moduledoc "The Ash domain holding the macaroon-rotation test resource."

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource AshVault.Test.RotatedCredential
  end
end

defmodule AshVault.Test.Rotation.World do
  @moduledoc """
  The in-memory world a rotation test runs against: the declared credentials and their
  saved state (the source), the staging slot and each consumer's copy (the delivery),
  and failures to inject (`fail/1`: `:list`, `:save`, `:stage`, `:staged`,
  `{:deliver, name}`).
  """
  use Agent

  def start_link(specs) do
    Agent.start_link(
      fn ->
        %{specs: specs, states: %{}, staging: %{}, copies: %{}, fail: MapSet.new(), revoked: []}
      end,
      name: __MODULE__
    )
  end

  def get(key), do: Agent.get(__MODULE__, &Map.fetch!(&1, key))
  def update(key, fun), do: Agent.update(__MODULE__, &Map.update!(&1, key, fun))
  def fail(list), do: Agent.update(__MODULE__, &Map.put(&1, :fail, MapSet.new(list)))
  def failing?(what), do: Agent.get(__MODULE__, &MapSet.member?(&1.fail, what))
  def state(ref), do: get(:states)[ref]
  def copy(name), do: get(:copies)[name]
end

defmodule AshVault.Test.Rotation.Source do
  @moduledoc "A `AshVault.Macaroon.Rotation.Source` over `AshVault.Test.Rotation.World`."
  @behaviour AshVault.Macaroon.Rotation.Source

  alias AshVault.Macaroon.Rotation.{Item, State}
  alias AshVault.Test.Rotation.World

  @impl true
  def list(_context) do
    if World.failing?(:list) do
      {:error, "listing refused"}
    else
      states = World.get(:states)

      {:ok,
       for {ref, spec} <- World.get(:specs) do
         # Stored form round trip, as a real source would.
         %Item{ref: ref, spec: spec, state: State.from_map(states[ref]), meta: :meta}
       end}
    end
  end

  @impl true
  def save(%Item{ref: ref}, state, _context) do
    if World.failing?(:save) do
      {:error, {:store, 503}}
    else
      World.update(:states, &Map.put(&1, ref, State.to_map(state)))
      :ok
    end
  end

  @impl true
  def revoked(id, _context), do: World.update(:revoked, &[id | &1])

  @impl true
  def describe_error({:store, status}), do: "store answered #{status}"
  def describe_error(_other), do: nil
end

defmodule AshVault.Test.Rotation.Delivery do
  @moduledoc "A `AshVault.Macaroon.Rotation.Delivery` over `AshVault.Test.Rotation.World`."
  @behaviour AshVault.Macaroon.Rotation.Delivery

  alias AshVault.Macaroon.Rotation.Secret
  alias AshVault.Test.Rotation.World

  @impl true
  def stage(context, id, secret) do
    if World.failing?(:stage) do
      {:error, "staging refused"}
    else
      World.update(:staging, &Map.put(&1, context.ref, {id, Secret.reveal(secret)}))
      :ok
    end
  end

  @impl true
  def staged(context, id) do
    cond do
      World.failing?(:staged) ->
        {:error, "staging unreachable"}

      true ->
        case World.get(:staging)[context.ref] do
          {^id, token} -> {:ok, Secret.new(token)}
          _ -> :lost
        end
    end
  end

  @impl true
  def deliver(_context, %{name: name}, id, secret) do
    if World.failing?({:deliver, name}) do
      {:error, "consumer #{name} refused"}
    else
      World.update(:copies, &Map.put(&1, name, {id, Secret.reveal(secret)}))
      :ok
    end
  end

  @impl true
  def consumer_name(%{name: name}), do: name
end

defmodule AshVault.Test.RotatedCredential do
  @moduledoc "A globally-scoped credential whose macaroon rotates."

  use Ash.Resource,
    domain: AshVault.Test.RotationDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.GlobalVault
    scope :global

    macaroon :cred do
      prefix "avrot"
      identity :id
      default_ttl 86_400
      max_ttl 7_776_000
      revoked_when expr(not is_nil(revoked_at) or expires_at <= now())

      rotation do
        source AshVault.Test.Rotation.Source
        delivery AshVault.Test.Rotation.Delivery
        issue_action :issue
        revoke_action :revoke
        rotate_action :rotate
      end
    end
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :label, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
    attribute :last_used_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      accept [:label, :expires_at]
      validate {AshVault.Test.RotatedCredential.RefuseLabel, []}
    end

    update :revoke do
      accept []
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end

    update :touch do
      accept [:last_used_at]
    end
  end
end

defmodule AshVault.Test.RotatedCredential.RefuseLabel do
  @moduledoc "Refuses the label `\"refuse\"`: a way to make the issue action fail."
  use Ash.Resource.Validation

  @impl true
  def validate(changeset, _opts, _context) do
    if Ash.Changeset.get_attribute(changeset, :label) == "refuse",
      do: {:error, field: :label, message: "refused"},
      else: :ok
  end
end
