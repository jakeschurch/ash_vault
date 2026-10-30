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

  test "fresh-read field policies admit vault preference without loading supplied records", %{
    record: record
  } do
    assert {:ok, [credential]} = read(record)
    assert credential.token == "vault-value"
    assert_receive {:credential_lifecycle, nil}
    assert_receive {:credential_lifecycle, nil}
    refute_receive {:credential_lifecycle, :load}
  end

  test "supplied stale or fabricated records never acquire fresh sibling authority", %{
    record: record
  } do
    for supplied <- [record, %{record | token: "fabricated", vault_token: "fabricated"}],
        marker <- [false, true] do
      load_query =
        record
        |> query(:credentials)
        |> Ash.Query.set_context(%{ash_vault_prefer_vault_copy_loading: marker})
        |> Ash.Query.load([:token, :vault_token, :encrypted_vault_token])

      case Ash.load(supplied, load_query) do
        {:error, _} ->
          :ok

        {:ok, loaded} ->
          for field <- [:token, :vault_token, :encrypted_vault_token] do
            assert %Ash.ForbiddenField{} = Map.fetch!(loaded, field)
          end
      end
    end
  end

  test "missing duplicate substituted or changed sibling records fail closed", %{record: record} do
    for effect <- [:drop, :duplicate, :substitute, :change] do
      assert {:error, _} =
               record
               |> query(:credentials)
               |> Ash.Query.set_context(%{sibling_effect: effect})
               |> Ash.read()
    end
  end

  test "initial_data reads cannot acquire fresh sibling authority", %{record: record} do
    for supplied <- [record, %{record | token: "fabricated", vault_token: "fabricated"}],
        marker <- [false, true] do
      load_query =
        record
        |> query(:credentials)
        |> Ash.Query.set_context(%{ash_vault_prefer_vault_copy_loading: marker})
        |> Ash.Query.load([:token, :vault_token, :encrypted_vault_token])

      case Ash.Actions.Read.run(load_query, load_query.action,
             initial_data: [supplied],
             actor: @actor,
             tenant: @tenant,
             authorize?: true
           ) do
        {:error, _} ->
          :ok

        {:ok, [loaded]} ->
          for field <- [:token, :vault_token, :encrypted_vault_token] do
            assert %Ash.ForbiddenField{} = Map.fetch!(loaded, field)
          end
      end
    end
  end

  test "caller hooks are not replayed and original filters remain in force", %{record: record} do
    require Ash.Query

    assert {:ok, [_]} =
             record
             |> query(:credentials)
             |> Ash.Query.filter(org_id == ^@tenant)
             |> Ash.Query.after_action(fn _query, records ->
               send(self(), :caller_hook)
               {:ok, records}
             end)
             |> Ash.read()

    assert_receive :caller_hook
    refute_receive :caller_hook

    assert {:ok, []} =
             record
             |> query(:credentials)
             |> Ash.Query.filter(org_id == "other")
             |> Ash.read()
  end

  test "batch offset limit sorting and pagination retain the selected rows", %{record: record} do
    second =
      ScopedLegacyCredential
      |> Ash.Changeset.for_create(:create, %{org_id: @tenant, token: "second-vault"},
        actor: @actor,
        tenant: @tenant
      )
      |> Ash.create!()

    ids = Enum.sort([record.id, second.id])

    assert {:ok, [credential]} =
             record
             |> query(:credential_batch, %{proof: "bound"})
             |> Ash.Query.sort(id: :asc)
             |> Ash.Query.offset(1)
             |> Ash.Query.limit(1)
             |> Ash.read()

    assert credential.id == List.last(ids)
    assert credential.token in ["vault-value", "second-vault"]

    assert {:ok, %Ash.Page.Offset{results: [paged]}} =
             record
             |> query(:paged_credentials, %{proof: "bound"})
             |> Ash.Query.sort(id: :asc)
             |> Ash.read(page: [limit: 1, offset: 1])

    assert paged.id == credential.id
    assert paged.token == credential.token

    assert {:ok, %Ash.Page.Keyset{results: [first]}} =
             record
             |> query(:required_paged_credentials, %{proof: "bound"})
             |> Ash.Query.sort(id: :asc)
             |> Ash.read(page: [limit: 1])

    assert {:ok, %Ash.Page.Keyset{results: [last]}} =
             record
             |> query(:required_paged_credentials, %{proof: "bound"})
             |> Ash.Query.sort(id: :asc)
             |> Ash.read(page: [limit: 1, after: first.__metadata__.keyset])

    assert last.id == credential.id
    assert last.token == credential.token
  end

  test "composite primary keys match siblings in the original order" do
    alias AshVault.Test.CompositeLegacyCredential

    for part <- ["first", "second"] do
      record =
        CompositeLegacyCredential
        |> Ash.Changeset.for_create(
          :create,
          %{group: "same", part: part, org_id: @tenant, token: "vault-" <> part},
          actor: @actor,
          tenant: @tenant
        )
        |> Ash.create!()

      changeset =
        record
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_tenant(@tenant)
        |> Ash.Changeset.force_change_attribute(:token, "stale-" <> part)

      assert {:ok, _} = Ash.DataLayer.update(CompositeLegacyCredential, changeset)
    end

    assert {:ok, records} =
             CompositeLegacyCredential
             |> Ash.Query.for_read(:read, %{}, actor: @actor, tenant: @tenant)
             |> Ash.Query.sort(part: :desc)
             |> Ash.read()

    assert Enum.map(records, &{&1.part, &1.token}) == [
             {"second", "vault-second"},
             {"first", "vault-first"}
           ]
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
