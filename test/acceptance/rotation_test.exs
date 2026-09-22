defmodule AshVault.Acceptance.RotationTest do
  @moduledoc """
  TEST_HARNESS_SPEC §28 — the rotation acceptance test.

  Every version assertion decodes the **raw column bytes** with `AshVault.Envelope.decode/1`.
  Inferring the key version from "decryption succeeded" would pass even if `rotate!/1` did
  nothing at all, which is precisely the bug this test exists to catch.

  Parameterized over the two real key providers, for the same reason §27 is: `Memory`'s
  versions live only in the test process. Tenant ids are freshly generated per run so the
  final `destroy` cannot poison a later run against the long-lived OpenBao dev server.
  """

  use ExUnit.Case, async: false

  require Ash.Query

  @moduletag :postgres

  alias AshVault.Envelope
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.KeyProviders.Local
  alias AshVault.Test.AcceptanceUser
  alias AshVault.Test.AcceptanceVaultResolver
  alias AshVault.Test.Db
  alias AshVault.Test.Repo

  setup do
    Db.reset!()
    on_exit(fn -> AcceptanceVaultResolver.put(AshVault.Test.Vault) end)
    :ok
  end

  describe "§28 rotation — AshVault.KeyProviders.Local" do
    test "three key versions coexist, then all three are erased together" do
      root = Path.join(System.tmp_dir!(), "ash_vault_rot_#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm_rf!(root) end)
      # The provider refuses to start on a root it did not see initialised — that is
      # what stops an unmounted key volume from looking like a pristine key store.
      Local.init_root!(root)
      start_supervised!({Local, name: Local, root: root})

      run_rotation_cycle(AshVault.Test.LocalVault)
    end
  end

  describe "§28 rotation — AshVault.KeyProviders.OpenBao" do
    @describetag :openbao

    setup do
      Application.put_env(:ash_vault, AshVault.KeyProviders.OpenBao,
        address: System.get_env("BAO_ADDR", "http://127.0.0.1:8200"),
        token: System.get_env("BAO_TOKEN", "ashvault-root")
      )

      on_exit(fn -> Application.delete_env(:ash_vault, AshVault.KeyProviders.OpenBao) end)
      :ok
    end

    test "three key versions coexist, then all three are erased together" do
      run_rotation_cycle(AshVault.Test.BaoVault)
    end
  end

  defp run_rotation_cycle(vault) do
    AcceptanceVaultResolver.put(vault)
    tenant = Ecto.UUID.generate()

    assert AshVault.Info.vault!(AcceptanceUser, %{tenant: tenant, actor: nil}) == vault

    # ── 1. key v1, row 1 ────────────────────────────────────────────────────────────
    row1 = create!(tenant, "one@example.invalid", "111-11-1111")

    # ── 2. the stored envelope itself says version 1 ────────────────────────────────
    assert stored_key_version(row1.id) == 1
    row1_blob = raw_blob(row1.id)

    # ── 3. rotate to v2, write row 2 ────────────────────────────────────────────────
    assert {:ok, 2} = AshVault.rotate_key!(vault, tenant)
    row2 = create!(tenant, "two@example.invalid", "222-22-2222")

    # ── 4. row 2 carries v2; row 1 still carries v1 ─────────────────────────────────
    assert stored_key_version(row2.id) == 2
    assert stored_key_version(row1.id) == 1

    # Rotation must not have rewritten the old row: the bytes are byte-identical to the
    # ones captured before `rotate_key!/2` ran.
    assert raw_blob(row1.id) == row1_blob

    # ── 5. both decrypt ─────────────────────────────────────────────────────────────
    assert %{email: "one@example.invalid", ssn: "111-11-1111"} = read_one!(tenant, row1.id)
    assert %{email: "two@example.invalid", ssn: "222-22-2222"} = read_one!(tenant, row2.id)

    # ── 6. rotate again to v3; all three rows decrypt, carrying 1, 2 and 3 ──────────
    assert {:ok, 3} = AshVault.rotate_key!(vault, tenant)
    row3 = create!(tenant, "three@example.invalid", "333-33-3333")

    assert [stored_key_version(row1.id), stored_key_version(row2.id), stored_key_version(row3.id)] ==
             [1, 2, 3]

    # Both encrypted fields of a row were written under the same version.
    assert stored_key_version(row3.id, "encrypted_ssn") == 3
    assert stored_key_version(row1.id, "encrypted_ssn") == 1

    emails =
      tenant
      |> read_all!()
      |> Enum.map(& &1.email)
      |> Enum.sort()

    assert emails == [
             "one@example.invalid",
             "three@example.invalid",
             "two@example.invalid"
           ]

    # ── 7. destroy: every version goes at once ──────────────────────────────────────
    assert :ok = AshVault.destroy_keys!(vault, tenant)

    for row <- [row1, row2, row3] do
      row_id = row.id

      result =
        AcceptanceUser
        |> Ash.Query.filter(id == ^row_id)
        |> Ash.Query.load([:email, :ssn])
        |> Ash.read(tenant: tenant)

      assert {:error, %Ash.Error.Invalid{errors: errors}} = result,
             "expected a clean error value for #{row.id}, got: #{inspect(result)}"

      assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1)),
             "expected KeyDestroyed for #{row.id}, got: #{inspect(errors)}"

      refute Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1))
    end

    # The rows and their version stamps are all still on disk — only the keys are gone.
    assert [[3]] = Repo.query!("SELECT count(*) FROM acceptance_users").rows
    assert stored_key_version(row1.id) == 1
    assert stored_key_version(row3.id) == 3
  end

  defp create!(tenant, email, ssn) do
    AcceptanceUser
    |> Ash.Changeset.for_create(:create, %{org_id: tenant, email: email, ssn: ssn},
      tenant: tenant
    )
    |> Ash.create!()
  end

  defp read_one!(tenant, id) do
    AcceptanceUser
    |> Ash.Query.filter(id == ^id)
    |> Ash.Query.load([:email, :ssn])
    |> Ash.read_one!(tenant: tenant)
  end

  defp read_all!(tenant) do
    AcceptanceUser
    |> Ash.Query.load([:email, :ssn])
    |> Ash.read!(tenant: tenant)
  end

  defp stored_key_version(id, column \\ "encrypted_email") do
    assert {:ok, %{key_version: version}} = Envelope.decode(raw_blob(id, column))
    version
  end

  defp raw_blob(id, column \\ "encrypted_email") do
    [[blob]] =
      Repo.query!("SELECT #{column} FROM acceptance_users WHERE id = $1", [Ecto.UUID.dump!(id)]).rows

    blob
  end
end
