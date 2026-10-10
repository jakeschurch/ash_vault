defmodule AshVault.LegacyExpandPostgresTest do
  @moduledoc """
  Expand mode on the atomic paths, which only a data layer with real update queries
  exercises: an atomic update that sets the legacy value, one that leaves it alone, an
  atomic clear, a bulk atomic update, and an `ON CONFLICT` upsert.
  """

  use ExUnit.Case, async: false

  require Ash.Query

  @moduletag :postgres

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.{Admin, PgLegacyAccount, Repo}

  @admin %Admin{id: 1, role: :admin}

  setup do
    start_supervised!({Memory, name: Memory})
    AshVault.Test.Db.reset!()
    %{org: Ash.UUID.generate()}
  end

  test "an atomic update that sets the value writes both copies in one statement", %{org: org} do
    account = create!(org, "tok-1")

    updated = atomic!(account, :replace_token, %{token: "tok-2"}, org)

    assert raw(account).token == AshVault.Test.LegacyBinary.stored("tok-2")
    assert decrypt(updated, org) == "tok-2"
  end

  test "an atomic update that does not touch the value leaves the ciphertext alone", %{org: org} do
    account = create!(org, "tok-1")
    before = raw(account).encrypted_vault_token

    atomic!(account, :rename, %{name: "renamed"}, org)

    assert raw(account).encrypted_vault_token == before
  end

  test "an atomic clear clears both copies", %{org: org} do
    account = create!(org, "tok-1")

    atomic!(account, :clear_token, %{}, org)

    assert %{token: nil, encrypted_vault_token: nil} = raw(account)
  end

  test "a bulk atomic update mirrors every row", %{org: org} do
    a = create!(org, "a")
    b = create!(org, "b")

    assert %Ash.BulkResult{status: :success} =
             PgLegacyAccount
             |> Ash.Query.filter(id in ^[a.id, b.id])
             |> Ash.bulk_update(:replace_token, %{token: "same"},
               tenant: org,
               strategy: [:atomic],
               return_errors?: true
             )

    for record <- [a, b], do: assert(decrypt(record, org) == "same")
  end

  test "an ON CONFLICT upsert rewrites the ciphertext with the legacy column", %{org: org} do
    upsert!(org, "dup", "first")
    upsert!(org, "dup", "second")

    {:ok, [read]} =
      PgLegacyAccount
      |> Ash.Query.for_read(:read, %{}, actor: @admin, tenant: org)
      |> Ash.read()

    assert read.token == "second"
  end

  defp create!(org, token) do
    PgLegacyAccount
    |> Ash.Changeset.for_create(:create, %{org_id: org, name: "n-#{token}", token: token},
      tenant: org
    )
    |> Ash.create!()
  end

  defp upsert!(org, name, token) do
    PgLegacyAccount
    |> Ash.Changeset.for_create(:upsert, %{org_id: org, name: name, token: token}, tenant: org)
    |> Ash.create!(upsert?: true)
  end

  defp atomic!(record, action, input, org) do
    %Ash.BulkResult{status: :success, records: [updated]} =
      PgLegacyAccount
      |> Ash.Query.filter(id == ^record.id)
      |> Ash.bulk_update(action, input,
        tenant: org,
        strategy: [:atomic],
        return_records?: true,
        return_errors?: true
      )

    updated
  end

  defp decrypt(record, org) do
    PgLegacyAccount
    |> Ash.Query.filter(id == ^record.id)
    |> Ash.Query.load(:vault_token)
    |> Ash.read_one!(tenant: org, authorize?: false)
    |> Map.fetch!(:vault_token)
  end

  defp raw(record) do
    %{rows: [[token, encrypted]]} =
      Repo.query!("SELECT token, encrypted_vault_token FROM legacy_accounts WHERE id = $1", [
        Ecto.UUID.dump!(record.id)
      ])

    %{token: token, encrypted_vault_token: encrypted}
  end
end
