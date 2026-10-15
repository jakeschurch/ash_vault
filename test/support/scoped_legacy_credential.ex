defmodule AshVault.Test.ScopedLegacyCredential do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault

    encrypt :token,
      legacy: AshVault.Test.LegacyBinary,
      decrypt_for: [
        {AshVault.Test.Checks.IsSystem, only: [:credentials, :redacted_credentials]}
      ]
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
    attribute :token, :binary, public?: true, sensitive?: true
  end

  actions do
    defaults [:read, create: [:org_id, :token]]

    for name <- [:credentials, :redacted_credentials] do
      read name do
        argument :credential_id, :uuid, allow_nil?: false
        argument :proof, :string, allow_nil?: false
        filter expr(id == ^arg(:credential_id))

        prepare fn query, context ->
          if query.context[:caller_scope] == query.tenant and
               Ash.Query.get_argument(query, :proof) == "bound" do
            send(query.context.test_pid, {
              :credential_prepared,
              query.action.name,
              query.arguments,
              query.tenant,
              context.actor,
              query.context.caller_scope
            })

            query
          else
            Ash.Query.add_error(query, Ash.Error.Forbidden.exception([]))
          end
        end
      end
    end
  end

  policies do
    policy action_type(:create) do
      authorize_if AshVault.Test.Checks.IsSystem
    end

    policy action_type(:read) do
      forbid_unless AshVault.Test.Checks.IsSystem
      authorize_if action([:credentials, :redacted_credentials])
    end

    policy action_type(:read) do
      authorize_if expr(org_id == ^actor(:id))
    end
  end

  field_policies do
    private_fields :include

    field_policy [:token, :vault_token, :encrypted_vault_token] do
      authorize_if action(:credentials)
    end

    field_policy :* do
      authorize_if always()
    end
  end
end
