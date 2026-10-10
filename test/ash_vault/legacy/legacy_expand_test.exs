defmodule AshVault.Legacy.LegacyExpandTest do
  # Not async: every vault talks to the default-named Memory provider.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  require Ash.Query

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.{Admin, EtsLegacyAccount, EtsLegacyUpsert, LegacyBinary}

  @tenant "acme"
  @admin %Admin{id: 1, role: :admin}
  @system %Admin{id: 2, role: :system}
  @member %Admin{id: 3, role: :member}

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  describe "the generated shape" do
    test "the legacy attribute keeps its column, retyped to the legacy type" do
      token = Ash.Resource.Info.attribute(EtsLegacyAccount, :token)

      assert token.type == LegacyBinary
      assert token.public?
    end

    test "the AshVault copy is stored under vault_<name> by default, or stored_as" do
      assert %{type: Ash.Type.Binary, public?: false} =
               Ash.Resource.Info.attribute(EtsLegacyAccount, :encrypted_vault_token)

      assert Ash.Resource.Info.calculation(EtsLegacyAccount, :vault_token).type ==
               Ash.Type.Binary

      assert Ash.Resource.Info.attribute(EtsLegacyAccount, :encrypted_sealed_settings)

      assert Ash.Resource.Info.calculation(EtsLegacyAccount, :sealed_settings).type ==
               Ash.Type.Map
    end

    test "encrypted_fields/1 presents the AshVault copy, backfilled from the legacy attribute" do
      field = AshVault.Info.encrypted_field(EtsLegacyAccount, :vault_token)

      assert field.backfill_from == :token
      assert field.legacy_of == :token

      assert [:token, :settings] =
               Enum.map(AshVault.Info.legacy_fields(EtsLegacyAccount), & &1.name)
    end

    test "an upsert that rewrites the legacy column also rewrites the ciphertext" do
      action = Ash.Resource.Info.action(EtsLegacyUpsert, :upsert)

      assert :encrypted_vault_token in action.upsert_fields
    end
  end

  describe "dual-write on every action that changes the field" do
    test "create writes both copies, bound to the stored_as name" do
      account = create!(%{token: "tok-1"})

      assert account.token == "tok-1"
      assert <<"AV", 1::8, _::binary>> = account.encrypted_vault_token
      refute account.encrypted_vault_token =~ "tok-1"
      assert decrypt(account, :vault_token) == "tok-1"
    end

    test "an update that changes it rewrites the copy; one that does not leaves it alone" do
      account = create!(%{token: "tok-1"})
      before = account.encrypted_vault_token

      renamed = update!(account, :rename, %{name: "renamed"})
      assert renamed.encrypted_vault_token == before

      updated = update!(renamed, :update, %{token: "tok-2"})
      refute updated.encrypted_vault_token == before
      assert decrypt(updated, :vault_token) == "tok-2"
    end

    test "a value set inside an earlier before_action hook is mirrored too" do
      account = create!(%{token: "tok-1"})

      rotated = update!(account, :rotate_in_hook, %{})
      assert decrypt(rotated, :vault_token) == "rotated-in-hook"
    end

    test "clearing the legacy value clears the copy (encrypt_nil?: false)" do
      account = create!(%{token: "tok-1"})

      cleared = update!(account, :clear_token, %{})
      assert cleared.token == nil
      assert cleared.encrypted_vault_token == nil
      assert read_one!(@admin).token == nil
    end

    test "an upsert on conflict rewrites the copy" do
      upsert!("dup", "first")
      upsert!("dup", "second")

      {:ok, [read]} =
        EtsLegacyUpsert
        |> Ash.Query.for_read(:read, %{}, actor: @admin, tenant: @tenant)
        |> Ash.read()

      assert read.token == "second"
    end

    test "maps are normalized through the legacy type, so both copies read back alike" do
      account = create!(%{settings: %{"n" => 1, mode: :fast}})

      assert decrypt(account, :sealed_settings) == %{"mode" => "fast", "n" => 1}
      assert [%{status: :ok}] = [verify(:sealed_settings)]
    end

    test "a vault failure fails the write instead of leaving only the legacy copy" do
      AshVault.destroy_keys!(AshVault.Test.Vault, @tenant)

      assert {:error, _} =
               EtsLegacyAccount
               |> Ash.Changeset.for_create(:create, %{org_id: @tenant, name: "x", token: "t"},
                 tenant: @tenant
               )
               |> Ash.create()

      assert Ash.read!(EtsLegacyAccount, tenant: @tenant, authorize?: false) == []
    end
  end

  describe "dual-read for decrypt_for actors" do
    test "an admitted actor reads the AshVault copy over a diverged legacy copy" do
      account = create!(%{token: "tok-1", settings: %{"a" => 1}})
      diverge!(account, token: "stale", settings: %{"stale" => true})

      read = read_one!(@admin)
      assert read.token == "tok-1"
      assert read.settings == %{"a" => 1}
    end

    test "others keep the legacy value and never decrypt" do
      account = create!(%{token: "tok-1"})
      diverge!(account, token: "stale")
      AshVault.destroy_keys!(AshVault.Test.Vault, @tenant)

      assert read_one!(@member).token == "stale"
      assert read_one!(nil).token == "stale"
    end

    test "an `only:` entry admits its actor on that action alone" do
      account = create!(%{token: "tok-1"})
      diverge!(account, token: "stale")

      assert read_one!(@system).token == "stale"
      assert read_one!(@system, :with_secrets).token == "tok-1"
    end

    test "a row without a copy yet falls back to the legacy value" do
      account = create!(%{token: "tok-1"})
      null_copy!(account)

      assert read_one!(@admin).token == "tok-1"
    end

    test "a decrypt failure fails the read, never answered from the legacy copy" do
      create!(%{token: "tok-1"})
      AshVault.destroy_keys!(AshVault.Test.Vault, @tenant)

      assert {:error, error} = read(@admin)

      assert Enum.any?(
               Ash.Error.to_error_class(error).errors,
               &match?(%AshVault.Errors.KeyDestroyed{}, &1)
             )
    end

    test "a query that does not select the field never decrypts" do
      create!(%{token: "tok-1"})
      AshVault.destroy_keys!(AshVault.Test.Vault, @tenant)

      assert {:ok, [_]} =
               EtsLegacyAccount
               |> Ash.Query.select([:name])
               |> Ash.read(actor: @admin, tenant: @tenant)
    end
  end

  describe "backfill and verify" do
    test "legacy-only rows backfill under the stored_as name and verify clean" do
      account = create!(%{token: "tok-1"})
      null_copy!(account)

      assert {:ok, %{done: 1}} = backfill(:vault_token)
      assert decrypt(get!(account), :vault_token) == "tok-1"
      assert {:ok, %{mismatches: []}} = verify_result(:vault_token)
      assert {:ok, %{done: 0}} = backfill(:vault_token)
    end

    test "a legacy-only write is caught by verify" do
      account = create!(%{token: "tok-1"})
      diverge!(account, token: "rolled-back")

      log =
        capture_log(fn ->
          assert {:error, _, %{mismatches: [_]}} = verify_result(:vault_token)
        end)

      refute log =~ "rolled-back"
      refute log =~ "tok-1"
    end
  end

  defp create!(attrs) do
    EtsLegacyAccount
    |> Ash.Changeset.for_create(
      :create,
      Map.merge(%{org_id: @tenant, name: "acct-#{System.unique_integer([:positive])}"}, attrs),
      tenant: @tenant
    )
    |> Ash.create!()
  end

  defp upsert!(name, token) do
    EtsLegacyUpsert
    |> Ash.Changeset.for_create(:upsert, %{org_id: @tenant, name: name, token: token},
      tenant: @tenant
    )
    |> Ash.create!(upsert?: true)
  end

  defp update!(record, action, attrs) do
    record
    |> Ash.Changeset.for_update(action, attrs, tenant: @tenant)
    |> Ash.update!()
  end

  defp get!(record) do
    EtsLegacyAccount
    |> Ash.Query.filter(id == ^record.id)
    |> Ash.read_one!(tenant: @tenant, authorize?: false)
  end

  defp read(actor, action \\ :read) do
    EtsLegacyAccount
    |> Ash.Query.for_read(action, %{}, actor: actor, tenant: @tenant)
    |> Ash.read()
  end

  defp read_one!(actor, action \\ :read) do
    {:ok, [record]} = read(actor, action)
    record
  end

  defp decrypt(record, calc) do
    record |> Ash.load!([calc], tenant: @tenant, authorize?: false) |> Map.fetch!(calc)
  end

  defp diverge!(record, changes) do
    record
    |> Ash.Changeset.new()
    |> Ash.Changeset.force_change_attributes(Map.new(changes))
    |> raw_update!()
  end

  defp null_copy!(record) do
    record
    |> Ash.Changeset.new()
    |> Ash.Changeset.force_change_attribute(:encrypted_vault_token, nil)
    |> raw_update!()
  end

  # Writes straight through the data layer, bypassing the action (and so the
  # dual-write), the way a rolled-back release or a hand-run UPDATE would.
  defp raw_update!(changeset) do
    changeset = %{changeset | tenant: @tenant, to_tenant: @tenant}
    {:ok, _} = Ash.DataLayer.update(EtsLegacyAccount, changeset)
    :ok
  end

  defp backfill(field) do
    AshVault.Backfill.run(EtsLegacyAccount, field, tenant: @tenant, action: :vault_backfill)
  end

  defp verify_result(field) do
    AshVault.Backfill.run(EtsLegacyAccount, field,
      tenant: @tenant,
      action: :vault_backfill,
      verify?: true,
      sample: 0
    )
  end

  defp verify(field) do
    case verify_result(field) do
      {:ok, stats} -> Map.put(stats, :status, :ok)
      other -> %{status: other}
    end
  end
end
