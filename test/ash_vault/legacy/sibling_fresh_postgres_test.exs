defmodule AshVault.Legacy.SiblingFreshPostgresTest do
  use ExUnit.Case, async: false

  alias AshVault.Test.{Admin, Db, PgLegacyAccount, Repo}

  @moduletag :postgres

  setup do
    start_supervised!(AshVault.KeyProviders.Memory)
    Db.reset!()
    tenant = Ash.UUID.generate()
    actor = %Admin{id: tenant, role: :admin}

    record =
      PgLegacyAccount
      |> Ash.Changeset.for_create(:create, %{name: "fresh", token: "vault-value", org_id: tenant},
        actor: actor,
        tenant: tenant
      )
      |> Ash.create!()

    Repo.query!("UPDATE legacy_accounts SET token=$1 WHERE id=$2", [
      AshVault.Test.LegacyBinary.stored("stale-legacy"),
      Ecto.UUID.dump!(record.id)
    ])

    {:ok, record: record, tenant: tenant, actor: actor}
  end

  test "a locked native read retains fresh field authority", context do
    assert {:ok, {:ok, [credential]}} =
             Repo.transaction(fn ->
               PgLegacyAccount
               |> Ash.Query.for_read(:read, %{}, actor: context.actor, tenant: context.tenant)
               |> Ash.Query.lock("FOR SHARE")
               |> Ash.read()
             end)

    assert credential.id == context.record.id
    assert credential.token == "vault-value"
  end

  test "supplied stale records cannot gain fresh authority inside a transaction", context do
    assert {:ok, result} =
             Repo.transaction(fn ->
               query =
                 PgLegacyAccount
                 |> Ash.Query.for_read(:read, %{}, actor: context.actor, tenant: context.tenant)
                 |> Ash.Query.load([:token, :vault_token, :encrypted_vault_token])

               Ash.load(context.record, query)
             end)

    case result do
      {:error, _} ->
        :ok

      {:ok, loaded} ->
        for field <- [:token, :vault_token, :encrypted_vault_token] do
          assert %Ash.ForbiddenField{} = Map.fetch!(loaded, field)
        end
    end
  end
end
