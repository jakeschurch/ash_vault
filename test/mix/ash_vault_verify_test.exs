defmodule Mix.Tasks.AshVault.VerifyTest do
  @moduledoc "`mix ash_vault.verify` against PostgreSQL."

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.LegacyUser
  alias AshVault.Test.LegacyVault
  alias AshVault.Test.Repo

  @moduletag :postgres

  setup do
    start_supervised!({Memory, name: Memory})
    AshVault.Test.Db.reset!()
    LegacyVault.reset!()
    on_exit(&LegacyVault.reset!/0)

    org = Ecto.UUID.generate()

    for i <- 1..8 do
      LegacyUser
      |> Ash.Changeset.for_create(:create, %{org_id: org, legacy_email: "u#{i}@example.com"},
        tenant: org
      )
      |> Ash.create!()
    end

    {:ok, org: org}
  end

  defp backfill(org) do
    capture_io(fn ->
      Mix.Tasks.AshVault.Backfill.run([
        "AshVault.Test.LegacyUser",
        "email",
        "--tenant",
        org,
        "--yes"
      ])
    end)
  end

  defp verify(argv), do: capture_io(fn -> Mix.Tasks.AshVault.Verify.run(argv) end)

  test "passes clean after a good backfill", %{org: org} do
    backfill(org)

    output =
      verify(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--sample", "0"])

    assert output =~ "ash_vault.verify=result"
    assert output =~ "rows=8 checked=8 mismatches=0"
    assert output =~ "no mismatches"
  end

  test "samples the first and last row by default", %{org: org} do
    backfill(org)

    output = verify(["AshVault.Test.LegacyUser", "email", "--tenant", org])

    assert output =~ "mismatches=0"
    assert output =~ ~r/checked=[12] /
  end

  test "exits non-zero when a row was never backfilled", %{org: org} do
    backfill(org)

    Repo.query!(
      "UPDATE legacy_users SET encrypted_email = NULL WHERE org_id::text = $1",
      [org]
    )

    assert_raise Mix.Error, ~r/Verification failed/, fn ->
      verify(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--sample", "0"])
    end
  end

  test "exits non-zero when a row is corrupted", %{org: org} do
    backfill(org)

    [[id]] =
      Repo.query!(
        "SELECT id::text FROM legacy_users WHERE org_id::text = $1 ORDER BY id LIMIT 1",
        [org]
      ).rows

    Repo.query!(
      "UPDATE legacy_users SET encrypted_email = overlay(encrypted_email placing '\\xff'::bytea from 40) WHERE id::text = $1",
      [id]
    )

    error =
      assert_raise Mix.Error, fn ->
        verify(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--sample", "0"])
      end

    assert Exception.message(error) =~ "Verification failed"
    assert Exception.message(error) =~ "decrypt_failed"
    assert Exception.message(error) =~ id
  end

  test "writes nothing", %{org: org} do
    backfill(org)

    before =
      Repo.query!(
        "SELECT id::text, encrypted_email FROM legacy_users WHERE org_id::text = $1 ORDER BY id",
        [org]
      ).rows

    verify(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--sample", "0"])

    assert Repo.query!(
             "SELECT id::text, encrypted_email FROM legacy_users WHERE org_id::text = $1 ORDER BY id",
             [org]
           ).rows == before
  end
end
