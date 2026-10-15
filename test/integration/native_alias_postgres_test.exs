defmodule AshVault.NativeAliasPostgresTest do
  use ExUnit.Case, async: false

  require Ash.Query

  alias AshVault.{Context, Serializer}
  alias AshVault.Test.{NativeAliasPgAccount, Repo, Vault}

  @moduletag :postgres

  setup do
    start_supervised!(AshVault.KeyProviders.Memory)
    AshVault.Test.Db.reset!()
    {:ok, tenant: Ash.UUID.generate()}
  end

  test "native reads consume old ciphertext without a column rename or legacy field", %{
    tenant: tenant
  } do
    record = create(tenant, "seed")

    blob =
      Vault.encrypt!(
        Serializer.serialize!("old-value", :binary, [], NativeAliasPgAccount, :vault_token),
        crypto_context(tenant)
      )

    Repo.query!("UPDATE legacy_accounts SET encrypted_vault_token=$1 WHERE id=$2", [
      blob,
      Ecto.UUID.dump!(record.id)
    ])

    assert read(record, tenant).token == "old-value"

    assert %{rows: [[nil, ^blob]]} =
             Repo.query!("SELECT token, encrypted_vault_token FROM legacy_accounts WHERE id=$1", [
               Ecto.UUID.dump!(record.id)
             ])

    assert Ash.Resource.Info.attribute(NativeAliasPgAccount, :encrypted_vault_token).source ==
             :encrypted_vault_token

    refute Ash.Resource.Info.attribute(NativeAliasPgAccount, :token)
    refute Ash.Resource.Info.attribute(NativeAliasPgAccount, :encrypted_token)
  end

  test "normal atomic and upsert writes retain the physical column and AAD", %{tenant: tenant} do
    record = create(tenant, "first")
    assert decrypt_raw(record, tenant) == "first"

    updated =
      record
      |> Ash.Changeset.for_update(:update, %{token: "normal"}, tenant: tenant)
      |> Ash.update!()

    assert decrypt_raw(updated, tenant) == "normal"

    assert %Ash.BulkResult{status: :success, records: [atomic]} =
             NativeAliasPgAccount
             |> Ash.Query.filter(id == ^record.id)
             |> Ash.bulk_update(:replace_token, %{token: "atomic"},
               tenant: tenant,
               strategy: [:atomic],
               return_records?: true,
               return_errors?: true
             )

    assert decrypt_raw(atomic, tenant) == "atomic"
    assert read(atomic, tenant).token == "atomic"

    upsert =
      NativeAliasPgAccount
      |> Ash.Changeset.for_create(:upsert, %{org_id: tenant, name: "record", token: "upsert"},
        tenant: tenant
      )
      |> Ash.create!()

    assert upsert.id == record.id
    assert decrypt_raw(upsert, tenant) == "upsert"

    assert %{rows: [[nil]]} =
             Repo.query!("SELECT token FROM legacy_accounts WHERE id=$1", [
               Ecto.UUID.dump!(record.id)
             ])
  end

  test "native reads have no legacy fallback and writes never mirror the old column", %{
    tenant: tenant
  } do
    record = create(tenant, "first")
    legacy = AshVault.Test.LegacyBinary.stored("obsolete")

    Repo.query!("UPDATE legacy_accounts SET token=$1, encrypted_vault_token=NULL WHERE id=$2", [
      legacy,
      Ecto.UUID.dump!(record.id)
    ])

    assert read(record, tenant).token == nil

    updated =
      record
      |> Ash.Changeset.for_update(:update, %{token: "native"}, tenant: tenant)
      |> Ash.update!()

    assert read(updated, tenant).token == "native"

    assert %{rows: [[^legacy]]} =
             Repo.query!("SELECT token FROM legacy_accounts WHERE id=$1", [
               Ecto.UUID.dump!(record.id)
             ])
  end

  defp create(tenant, value) do
    NativeAliasPgAccount
    |> Ash.Changeset.for_create(:create, %{org_id: tenant, name: "record", token: value},
      tenant: tenant
    )
    |> Ash.create!()
  end

  defp read(record, tenant) do
    NativeAliasPgAccount
    |> Ash.Query.for_read(:read, %{}, tenant: tenant)
    |> Ash.Query.filter(id == ^record.id)
    |> Ash.Query.load(:token)
    |> Ash.read_one!()
  end

  defp crypto_context(tenant),
    do: %Context{
      resource: NativeAliasPgAccount,
      field: :vault_token,
      ash_context: %{tenant: tenant}
    }

  defp decrypt_raw(record, tenant) do
    %{rows: [[blob]]} =
      Repo.query!("SELECT encrypted_vault_token FROM legacy_accounts WHERE id=$1", [
        Ecto.UUID.dump!(record.id)
      ])

    assert {:ok, value} =
             Serializer.deserialize(
               Vault.decrypt!(blob, crypto_context(tenant)),
               :binary,
               [],
               NativeAliasPgAccount,
               :vault_token
             )

    value
  end
end
