defmodule AshVault.Test.MacaroonDomain do
  @moduledoc "The Ash domain holding the macaroon test resources."

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource AshVault.Test.ApiClient
    resource AshVault.Test.GlobalApiClient
    resource AshVault.Test.FlakyApiClient
    resource AshVault.Test.Widget
    resource AshVault.Test.TransitApiClient
    resource AshVault.Test.DynamicApiClient
  end
end

defmodule AshVault.Test.Support.FlakyMacProvider do
  @moduledoc """
  `AshVault.KeyProviders.Memory`, until `outage!/0` — then every key call is a timeout.
  Lets a test mint a token and then verify it during an outage.
  """

  @behaviour AshVault.KeyProvider

  alias AshVault.KeyProviders.Memory

  @flag {__MODULE__, :down}

  @doc "Start failing every key call."
  def outage!, do: :persistent_term.put(@flag, true)

  @doc "Stop failing."
  def recover!, do: :persistent_term.erase(@flag)

  @doc "Keep serving stated versions, but answer `:not_found` for the current one."
  def lose_current!, do: :persistent_term.put(@flag, :current_not_found)

  defp down?, do: :persistent_term.get(@flag, false) == true
  defp current_lost?, do: :persistent_term.get(@flag, false) == :current_not_found

  @impl AshVault.KeyProvider
  def purposes, do: [:data, :mac]

  @impl AshVault.KeyProvider
  def current_key(scope), do: if(down?(), do: {:error, :timeout}, else: Memory.current_key(scope))

  @impl AshVault.KeyProvider
  def current_key(scope, purpose) do
    cond do
      down?() -> {:error, :timeout}
      current_lost?() -> {:error, :not_found}
      true -> Memory.current_key(scope, purpose)
    end
  end

  @impl AshVault.KeyProvider
  def get_key(scope, version),
    do: if(down?(), do: {:error, :timeout}, else: Memory.get_key(scope, version))

  @impl AshVault.KeyProvider
  def get_key(scope, version, purpose),
    do: if(down?(), do: {:error, :timeout}, else: Memory.get_key(scope, version, purpose))

  @impl AshVault.KeyProvider
  def rotate(scope), do: Memory.rotate(scope)

  @impl AshVault.KeyProvider
  def rotate(scope, purpose), do: Memory.rotate(scope, purpose)

  @impl AshVault.KeyProvider
  def destroy(scope), do: Memory.destroy(scope)
end

defmodule AshVault.Test.Support.FlakyMacVault do
  @moduledoc "A vault over `AshVault.Test.Support.FlakyMacProvider`."
  use AshVault.Vault, key_provider: AshVault.Test.Support.FlakyMacProvider
end

defmodule AshVault.Test.Support.RemoteIp do
  @moduledoc "A `:verify` caveat check: the request's `:remote_ip` context must equal the value."
  @behaviour AshVault.Macaroon.Caveat

  @impl AshVault.Macaroon.Caveat
  def check(ip, context, _opts), do: Map.get(context.context, :remote_ip) == ip
end

defmodule AshVault.Test.ApiClient do
  @moduledoc """
  Tenant-scoped (attribute multitenancy) ETS resource carrying a macaroon with every
  feature: per-record revocation, a `:verify` caveat, an `:authorize` caveat, a typed
  caveat, and a sign-in action.
  """

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    macaroon :api do
      prefix "avtest"
      identity :id
      revoked_when expr(not is_nil(revoked_at))
      default_ttl 3600
      accepted_key_versions 2

      caveat :ip, :string, check: AshVault.Test.Support.RemoteIp

      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn

      caveat :max_amount, :integer,
        check: fn max, ctx -> Map.get(ctx.context, :amount, 0) <= max end

      caveat :readonly, :boolean,
        check: fn ro, ctx -> not ro or Map.get(ctx.context, :write?) != true end

      caveat :not_after, :utc_datetime_usec,
        check: fn at, ctx -> DateTime.compare(ctx.now, at) == :lt end

      caveat :paths, {:array, :string},
        check: fn paths, ctx -> Map.get(ctx.context, :path) in paths end

      caveat :ports, {:array, :integer},
        check: fn ports, ctx -> Map.get(ctx.context, :port) in ports end
    end

    macaroon :nilrev do
      prefix "avnil"
      identity :id
      revoked_when expr(revoked_at <= now())
      default_ttl 3600
    end

    macaroon :strict do
      prefix "avstrict"
      identity :id
      default_ttl 3600
      require_authorize_enforcement? true

      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn
    end
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :string, allow_nil?: false, public?: true
    attribute :name, :string, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    default_accept [:org_id, :name, :revoked_at]
    defaults [:read, :destroy, create: :*, update: :*]

    read :sign_in_with_api_key do
      argument :api_key, :string, allow_nil?: false, sensitive?: true
      get? true

      prepare {AshVault.Macaroon.Preparations.Verify,
               macaroon: :api, argument: :api_key, mode: :sign_in}
    end
  end

  policies do
    bypass action([:api_by_token, :sign_in_with_api_key, :nilrev_by_token, :strict_by_token]) do
      authorize_if always()
    end

    policy action_type(:read) do
      forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api, when_absent: true}
      authorize_if actor_present()
    end

    policy action_type([:create, :update, :destroy, :action]) do
      authorize_if always()
    end
  end
end

defmodule AshVault.Test.GlobalApiClient do
  @moduledoc "A globally-scoped macaroon over a non-multitenant resource."

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.GlobalVault
    scope :global

    macaroon :svc do
      prefix "avsvc"
      identity :id
      default_ttl :infinity
      accepted_key_versions :all
    end
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :name, :string, public?: true
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end
end

defmodule AshVault.Test.FlakyApiClient do
  @moduledoc "A macaroon over a vault whose provider can be switched into an outage."

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Support.FlakyMacVault
    scope :tenant

    macaroon :flaky do
      prefix "avflaky"
      identity :id
      default_ttl 3600
    end
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :string, allow_nil?: false, public?: true
  end

  actions do
    defaults [:read, :destroy, create: :*]

    read :sign_in do
      argument :token, :string, allow_nil?: false, sensitive?: true
      get? true
      prepare {AshVault.Macaroon.Preparations.Verify, macaroon: :flaky, mode: :sign_in}
    end
  end
end

defmodule AshVault.Test.Widget do
  @moduledoc "A resource whose policies hold macaroon actors to their authorize-phase caveats."

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :name, :string, public?: true
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  policies do
    policy always() do
      forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api, when_absent: true}
      authorize_if actor_present()
    end
  end
end

defmodule AshVault.Test.Support.NoMacGlobalVault do
  @moduledoc "A globally-scoped vault whose provider has no `:mac` keyring."
  use AshVault.Vault,
    key_provider: AshVault.Test.Support.UnavailableProvider,
    scope: AshVault.Scopes.Global
end

defmodule AshVault.Test.TransitApiClient do
  @moduledoc """
  A macaroon over `AshVault.Test.Support.TransitVault`: the root signature is computed
  inside OpenBao, the caveat chain locally. Used by the `:openbao`-tagged suite.
  """

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Support.TransitVault
    scope :tenant

    macaroon :transit do
      prefix "avbao"
      identity :id
      default_ttl 3600
      caveat :ip, :string, check: AshVault.Test.Support.RemoteIp
    end
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :string, allow_nil?: false, public?: true
  end

  actions do
    defaults [:read, :destroy, create: :*]
  end
end

defmodule AshVault.Test.Support.Windows do
  @moduledoc "An `accepted_key_versions` MFA whose answer a test sets."

  @key {__MODULE__, :answer}

  @doc "Set what `window/1` returns (`{:raise, message}` raises)."
  def set!(answer), do: :persistent_term.put(@key, answer)

  @doc "Reset to the default answer, 1."
  def reset!, do: :persistent_term.erase(@key)

  @doc false
  def window(_scope) do
    case :persistent_term.get(@key, 1) do
      {:raise, message} -> raise message
      answer -> answer
    end
  end
end

defmodule AshVault.Test.DynamicApiClient do
  @moduledoc "Macaroons with a computed TTL, a computed key window and inline-fn caveats."

  use Ash.Resource,
    domain: AshVault.Test.MacaroonDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.GlobalVault
    scope :global

    macaroon :dyn do
      prefix "avdyn"
      identity :id

      default_ttl fn input ->
        case Map.get(input.context, :plan) do
          "long" -> 10_000
          "forever" -> :infinity
          "bad" -> -5
          "raise" -> raise "boom"
          _ -> 30
        end
      end

      max_ttl 100
      accepted_key_versions {AshVault.Test.Support.Windows, :window, []}

      caveat :tier, :string,
        check: fn tier, ctx ->
          if Map.get(ctx.context, :tier) == tier, do: :ok, else: {:error, :wrong_tier}
        end
    end
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
  end

  actions do
    defaults [:read, :destroy, create: :*]
  end
end
