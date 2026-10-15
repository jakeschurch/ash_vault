defmodule AshVault.Legacy.SiblingReadAuthorityTest do
  use ExUnit.Case, async: false

  alias AshVault.Test.{Admin, ScopedLegacyCredential}

  @tenant "scoped-credentials"
  @actor %Admin{id: @tenant, role: :system}

  setup do
    start_supervised!(AshVault.KeyProviders.Memory)

    record =
      ScopedLegacyCredential
      |> Ash.Changeset.for_create(:create, %{org_id: @tenant, token: "vault-value"},
        actor: @actor,
        tenant: @tenant
      )
      |> Ash.create!()

    changeset =
      record
      |> Ash.Changeset.new()
      |> Ash.Changeset.set_tenant(@tenant)
      |> Ash.Changeset.force_change_attribute(:token, "stale-legacy")

    {:ok, _} = Ash.DataLayer.update(ScopedLegacyCredential, changeset)
    {:ok, record: record}
  end

  test "the original private action, arguments, tenant and context authorize the sibling", %{
    record: record
  } do
    assert {:error, %Ash.Error.Forbidden{}} =
             ScopedLegacyCredential
             |> Ash.Query.for_read(:read, %{}, actor: @actor, tenant: @tenant)
             |> Ash.read()

    assert {:ok, [credential]} = read(record)
    assert credential.token == "vault-value"

    for _ <- 1..2 do
      assert_receive {:credential_prepared, :credentials, %{credential_id: id, proof: "bound"},
                      @tenant, @actor, @tenant}

      assert id == record.id
    end

    refute_receive {:credential_prepared, _, _, _, _, _}
  end

  test "the sibling cannot restore a field denied by native field policies", %{record: record} do
    assert {:ok, [credential]} =
             record
             |> query(:redacted_credentials)
             |> Ash.Query.load(:vault_token)
             |> Ash.read()

    assert %Ash.ForbiddenField{} = credential.token
    assert %Ash.ForbiddenField{} = credential.vault_token
    assert %Ash.ForbiddenField{} = credential.encrypted_vault_token
  end

  test "an explicitly requested sibling retains authority through the bounded reload", %{
    record: record
  } do
    assert {:ok, [credential]} =
             record
             |> query(:credentials)
             |> Ash.Query.load(:vault_token)
             |> Ash.read()

    assert credential.token == "vault-value"
    assert credential.vault_token == "vault-value"

    for _ <- 1..2 do
      assert_receive {:credential_prepared, :credentials, _, @tenant, @actor, @tenant}
    end

    refute_receive {:credential_prepared, _, _, _, _, _}
  end

  test "an explicitly loaded absent copy retains the legacy value", %{record: record} do
    changeset =
      record
      |> Ash.Changeset.new()
      |> Ash.Changeset.set_tenant(@tenant)
      |> Ash.Changeset.force_change_attribute(:encrypted_vault_token, nil)

    {:ok, _} = Ash.DataLayer.update(ScopedLegacyCredential, changeset)

    assert {:ok, [credential]} =
             record
             |> query(:credentials)
             |> Ash.Query.load(:vault_token)
             |> Ash.read()

    assert credential.token == "stale-legacy"
    assert credential.vault_token == nil
  end

  test "missing and invalid arguments never become an unscoped reload", %{record: record} do
    assert {:error, _} = read(record, :credentials, %{})
    assert {:error, _} = read(record, :credentials, %{credential_id: record.id, proof: "wrong"})
  end

  test "a different actor tenant does not acquire the selected credential", %{record: record} do
    assert {:ok, []} = read(record, :credentials, nil, %Admin{id: "other", role: :system})
  end

  test "a selected row outside the query tenant is absent", %{record: record} do
    assert {:ok, []} = read(record, :credentials, nil, @actor, "other")
  end

  test "destroyed vault keys fail the private read instead of returning legacy plaintext", %{
    record: record
  } do
    AshVault.destroy_keys!(AshVault.Test.Vault, @tenant)
    assert {:error, error} = read(record)

    assert Enum.any?(
             Ash.Error.to_error_class(error).errors,
             &is_struct(&1, AshVault.Errors.KeyDestroyed)
           )
  end

  defp read(record, action \\ :credentials, arguments \\ nil, actor \\ @actor, tenant \\ @tenant) do
    record
    |> query(action, arguments, actor, tenant)
    |> Ash.read()
  end

  defp query(record, action, arguments \\ nil, actor \\ @actor, tenant \\ @tenant) do
    ScopedLegacyCredential
    |> Ash.Query.set_context(%{caller_scope: tenant, test_pid: self()})
    |> Ash.Query.for_read(
      action,
      arguments || %{credential_id: record.id, proof: "bound"},
      actor: actor,
      tenant: tenant
    )
  end
end
