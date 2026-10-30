defmodule AshVault.Test.Checks.FreshSecretRead do
  @moduledoc false
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_opts), do: "secret fields require a fresh native read"

  @impl true
  def match?(_actor, %{query: %Ash.Query{} = query}, _opts),
    do: query.context[:query_for] != :load

  def match?(_actor, _context, _opts), do: true
end

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
        {AshVault.Test.Checks.IsSystem,
         only: [
           :credentials,
           :redacted_credentials,
           :credential_batch,
           :paged_credentials,
           :required_paged_credentials
         ]}
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

    for name <- [
          :credentials,
          :redacted_credentials,
          :credential_batch,
          :paged_credentials,
          :required_paged_credentials
        ] do
      read name do
        argument :credential_id, :uuid,
          allow_nil?: name in [:credential_batch, :paged_credentials, :required_paged_credentials]

        argument :proof, :string, allow_nil?: false
        filter expr(is_nil(^arg(:credential_id)) or id == ^arg(:credential_id))

        if name == :paged_credentials do
          pagination offset?: true, required?: false, default_limit: 1
        end

        if name == :required_paged_credentials do
          pagination keyset?: true, required?: true, default_limit: 1
        end

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
            |> Ash.Query.before_action(fn prepared ->
              send(query.context.test_pid, {:credential_lifecycle, prepared.context[:query_for]})
              prepared
            end)
            |> Ash.Query.after_action(fn prepared, records ->
              if prepared.context[:ash_vault_prefer_vault_copy_loading] do
                case prepared.context[:sibling_effect] do
                  :drop -> {:ok, []}
                  :duplicate -> {:ok, records ++ records}
                  :substitute -> {:ok, Enum.map(records, &%{&1 | id: Ash.UUID.generate()})}
                  :change -> {:ok, Enum.map(records, &%{&1 | org_id: "changed"})}
                  _ -> {:ok, records}
                end
              else
                {:ok, records}
              end
            end)
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

      authorize_if action([
                     :credentials,
                     :redacted_credentials,
                     :credential_batch,
                     :paged_credentials,
                     :required_paged_credentials
                   ])
    end

    policy action_type(:read) do
      authorize_if expr(org_id == ^actor(:id))
    end
  end

  field_policies do
    private_fields :include

    field_policy [:token, :vault_token, :encrypted_vault_token] do
      forbid_unless AshVault.Test.Checks.FreshSecretRead

      authorize_if action([
                     :credentials,
                     :credential_batch,
                     :paged_credentials,
                     :required_paged_credentials
                   ])
    end

    field_policy :* do
      authorize_if always()
    end
  end
end
