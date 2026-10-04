defmodule Example.Accounts.ApiKey do
  @moduledoc """
  An API key that is a **macaroon**: an attenuable bearer token for one row of this
  table, signed under the organization's `:mac` key.

  Nothing secret is stored here — not the token, not a hash of it. A token is
  `exapi_...`; verifying it recomputes its signature through the vault and loads this
  row by the id the token names.

      {:ok, token} =
        Example.Accounts.ApiKey.mint_api(key.id, %{caveats: %{actions: ["read"]}},
          tenant: org.id, authorize?: false)

      # any holder can narrow it, offline
      {:ok, narrower} = AshVault.Macaroon.attenuate(token, ip: "203.0.113.7")

      # a plug signs in with it — no tenant needed, the token carries its scope
      {:ok, [key]} =
        Example.Accounts.ApiKey
        |> Ash.Query.for_read(:sign_in_with_api_key, %{api_key: narrower},
          context: %{remote_ip: "203.0.113.7"})
        |> Ash.read()

  Revoking:

    * one key — `revoke` sets `revoked_at`, and `revoked_when` refuses it from then on
    * every key of an organization — rotate the organization's `:mac` keyring
      (`AshVault.rotate_key!(vault, org.id, nil, purpose: :mac)`); with
      `accepted_key_versions 1`, every token minted before the rotation is retired
    * everything — crypto-erase the organization (`Organization.destroy_keys`)

  See AshVault's "Macaroons" guide.
  """

  use Ash.Resource,
    domain: Example.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault &Example.Vault.resolve/2
    scope :tenant

    macaroon :api do
      prefix "exapi"
      identity :id
      revoked_when expr(not is_nil(revoked_at))
      default_ttl 30 * 86_400
      accepted_key_versions 1

      caveat :ip, :string, check: &Example.Accounts.ApiKey.remote_ip?/2

      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn
    end
  end

  postgres do
    table "api_keys"
    repo Example.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :label, :string, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    default_accept [:org_id, :label]
    defaults [:read, :destroy, create: :*]

    update :revoke do
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end

    read :sign_in_with_api_key do
      argument :api_key, :string, allow_nil?: false, sensitive?: true
      get? true

      prepare {AshVault.Macaroon.Preparations.Verify,
               macaroon: :api, argument: :api_key, mode: :sign_in}
    end
  end

  policies do
    # The token is the credential: verifying it needs no actor.
    bypass action([:api_by_token, :sign_in_with_api_key]) do
      authorize_if always()
    end

    # A key signed in with a macaroon is held to its `actions` caveat everywhere this
    # check is used; actors that did not use a macaroon pass through to the next check.
    policy always() do
      forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :api, when_absent: true}
      authorize_if actor_present()
    end
  end

  @doc "The `:ip` caveat: the request's `:remote_ip` context must equal the caveat."
  @spec remote_ip?(String.t(), AshVault.Macaroon.CheckContext.t()) :: boolean()
  def remote_ip?(ip, context), do: Map.get(context.context, :remote_ip) == ip
end
