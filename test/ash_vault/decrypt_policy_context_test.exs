defmodule AshVault.DecryptPolicyContextTest do
  use ExUnit.Case, async: false

  alias AshVault.Test.{TenantDecryptDoc, TenantLegacyDecryptDoc}

  setup do
    start_supervised!({AshVault.KeyProviders.Memory, name: AshVault.KeyProviders.Memory})
    :ok
  end

  test "direct calculations pass the authoritative tenant, resource and source context" do
    record = create(TenantDecryptDoc)

    loaded =
      Ash.load!(record, :token,
        actor: %{tenant_id: "acme"},
        tenant: "acme",
        context: %{request_id: "calculation", tenant: "forged"}
      )

    assert loaded.token == "secret"

    assert_receive {:decrypt_policy_context,
                    %{
                      tenant: "acme",
                      resource: TenantDecryptDoc,
                      action: nil,
                      phase: :read,
                      source_context: %{request_id: "calculation", tenant: "forged"}
                    }}
  end

  test "a different tenant actor is redacted before decrypting a broken ciphertext" do
    record = %{create(TenantDecryptDoc) | encrypted_token: "broken"}

    loaded =
      Ash.load!(record, :token,
        actor: %{tenant_id: "other"},
        tenant: "acme",
        context: %{tenant: "other", private: %{tenant: "other"}}
      )

    assert %Ash.ForbiddenField{} = loaded.token
    refute_receive {:decrypt_policy_context, _}
  end

  test "legacy preparations pass query scope and action rather than caller context" do
    record = create(TenantLegacyDecryptDoc)

    changeset =
      record
      |> Ash.Changeset.new()
      |> Ash.Changeset.force_change_attribute(:token, "stale")

    changeset = %{changeset | tenant: "acme", to_tenant: "acme"}
    assert {:ok, _} = Ash.DataLayer.update(TenantLegacyDecryptDoc, changeset)

    assert [loaded] =
             TenantLegacyDecryptDoc
             |> Ash.Query.for_read(:read, %{},
               actor: %{tenant_id: "acme"},
               tenant: "acme",
               context: %{request_id: "legacy", tenant: "forged"}
             )
             |> Ash.read!()

    assert loaded.token == "secret"

    assert_receive {:decrypt_policy_context,
                    %{
                      tenant: "acme",
                      resource: TenantLegacyDecryptDoc,
                      action: :read,
                      phase: :read,
                      source_context: %{request_id: "legacy", tenant: "forged"}
                    }}
  end

  test "existing action-only callers and only restrictions retain their behavior" do
    actor = %AshVault.Test.Admin{role: :system}
    entries = [{AshVault.Test.Checks.IsSystem, only: [:with_secrets]}]

    assert AshVault.DecryptFor.allowed?(entries, actor, :with_secrets)
    refute AshVault.DecryptFor.allowed?(entries, actor, :read)
    refute AshVault.DecryptFor.allowed?(entries, actor, nil)

    refute AshVault.DecryptFor.allowed?(entries, actor, nil, %{action: :with_secrets})
    refute AshVault.DecryptFor.allowed?(entries, actor, :read, %{action: :with_secrets})
  end

  defp create(resource) do
    resource
    |> Ash.Changeset.for_create(:create, %{org_id: "acme", token: "secret"}, tenant: "acme")
    |> Ash.create!()
  end
end
