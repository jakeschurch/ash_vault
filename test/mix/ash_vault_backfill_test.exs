defmodule Mix.Tasks.AshVault.BackfillTest do
  @moduledoc """
  The backfill task end to end, against PostgreSQL.

  The load-bearing assertion is the first one: a row written by the backfill must come
  back out of an ordinary `Ash.read`, which only happens if the backfill built the same
  AAD (`scope | resource | field`) an ordinary write would.
  """

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
    :ok
  end

  defp seed(org, n) do
    for i <- 1..n do
      LegacyUser
      |> Ash.Changeset.for_create(:create, %{org_id: org, legacy_email: "user#{i}@example.com"},
        tenant: org
      )
      |> Ash.create!()
    end
  end

  defp org, do: Ecto.UUID.generate()

  defp ciphertext_bytes(org) do
    "SELECT id::text, encrypted_email FROM legacy_users WHERE org_id::text = $1 ORDER BY id"
    |> Repo.query!([org])
    |> Map.fetch!(:rows)
    |> Map.new(fn [id, blob] -> {id, blob} end)
  end

  defp backfill(argv), do: capture_io(fn -> Mix.Tasks.AshVault.Backfill.run(argv) end)

  describe "backfilling a plaintext column" do
    test "encrypts every row and the rows decrypt through the ordinary Ash read path" do
      org = org()
      seed(org, 7)

      output = backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--yes"])

      assert output =~ "ash_vault.backfill=start"
      assert output =~ "source=legacy_email"
      assert output =~ "rows=7"
      assert output =~ "Backfilled 7 row(s)"

      assert Enum.all?(ciphertext_bytes(org), fn {_id, blob} -> is_binary(blob) end)

      records =
        LegacyUser
        |> Ash.Query.load(:email)
        |> Ash.read!(tenant: org, authorize?: false)

      assert length(records) == 7

      for record <- records do
        assert record.email == record.legacy_email
        assert record.email =~ ~r/^user\d@example\.com$/
      end
    end

    test "pages with a keyset across several committed batches" do
      org = org()
      seed(org, 7)

      output =
        backfill([
          "AshVault.Test.LegacyUser",
          "email",
          "--tenant",
          org,
          "--batch-size",
          "3",
          "--yes"
        ])

      assert output =~ "batch=1 rows=3 done=3"
      assert output =~ "batch=2 rows=3 done=6"
      assert output =~ "batch=3 rows=1 done=7"
      assert output =~ "in 3 batch(es)"
    end

    test "a second run is a no-op — the ciphertext bytes are untouched" do
      org = org()
      seed(org, 5)

      backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--yes"])
      before = ciphertext_bytes(org)

      output = backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--yes"])

      assert output =~ "rows=0"
      assert output =~ "Backfilled 0 row(s)"

      # Not merely "still decrypts": re-encrypting would mint a fresh nonce, so equal
      # bytes is the only proof that nothing was rewritten.
      assert ciphertext_bytes(org) == before
    end

    test "--dry-run writes nothing" do
      org = org()
      seed(org, 4)

      output = backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--dry-run"])

      assert output =~ "dry_run=true"
      assert output =~ "Dry run: would back-fill 4 row(s)"

      assert Enum.all?(ciphertext_bytes(org), fn {_id, blob} -> is_nil(blob) end)

      # It mints nothing either: `current_key/1` creates version 1 on first use, so a dry
      # run that encrypted anything would leave key material behind for a scope that has
      # never been written to.
      assert {:error, :not_found} = Memory.get_key(org, 1)
    end
  end

  describe "encrypt_nil?: false" do
    test "skips rows whose plaintext source is NULL, and still converges" do
      org = org()

      for i <- 1..6 do
        LegacyUser
        |> Ash.Changeset.for_create(
          :create,
          %{
            org_id: org,
            legacy_email: "user#{i}@example.com",
            legacy_ssn: if(rem(i, 2) == 0, do: "ssn-#{i}")
          },
          tenant: org
        )
        |> Ash.create!()
      end

      output = backfill(["AshVault.Test.LegacyUser", "ssn", "--tenant", org, "--yes"])

      # Only the three rows with a non-NULL source are even selected: a nil source under
      # `encrypt_nil?: false` legitimately stores SQL NULL, so it must be excluded from
      # the NULL filter or the task would never converge.
      assert output =~ "rows=3"
      assert output =~ "Backfilled 3 row(s)"

      # The convergence guard: a second run has nothing left to do.
      assert backfill(["AshVault.Test.LegacyUser", "ssn", "--tenant", org, "--yes"]) =~ "rows=0"

      records =
        LegacyUser
        |> Ash.Query.load([:ssn])
        |> Ash.read!(tenant: org, authorize?: false)

      for record <- records do
        assert record.ssn == record.legacy_ssn
      end

      assert Enum.count(records, &is_nil(&1.ssn)) == 3
    end
  end

  describe "--verify" do
    test "passes after a clean backfill" do
      org = org()
      seed(org, 6)
      backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--yes"])

      output =
        backfill([
          "AshVault.Test.LegacyUser",
          "email",
          "--tenant",
          org,
          "--verify",
          "--sample",
          "0"
        ])

      assert output =~ "mismatches=0"
      assert output =~ "no mismatches"
    end

    test "fails non-zero when a row is corrupted" do
      org = org()
      seed(org, 6)
      backfill(["AshVault.Test.LegacyUser", "email", "--tenant", org, "--yes"])

      [[id]] =
        Repo.query!(
          "SELECT id::text FROM legacy_users WHERE org_id::text = $1 ORDER BY id LIMIT 1",
          [org]
        ).rows

      Repo.query!(
        "UPDATE legacy_users SET encrypted_email = overlay(encrypted_email placing '\\xff'::bytea from 40) WHERE id::text = $1",
        [id]
      )

      assert_raise Mix.Error, ~r/Verification failed/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacyUser",
            "email",
            "--tenant",
            org,
            "--verify",
            "--sample",
            "0"
          ])
        end)
      end
    end
  end

  describe "a provider that disappears mid-run" do
    test "leaves the committed batch alone and prints a resume command that works" do
      org = org()
      seed(org, 6)

      # One resolve call plans the run, then one per encrypted row: breaking after four
      # makes the provider vanish while batch 2 is being encrypted, before it is written.
      LegacyVault.break_after!(4)

      output =
        capture_io(fn ->
          assert_raise Mix.Error, ~r/unavailable/, fn ->
            Mix.Tasks.AshVault.Backfill.run([
              "AshVault.Test.LegacyUser",
              "email",
              "--tenant",
              org,
              "--batch-size",
              "3",
              "--yes"
            ])
          end
        end)

      assert output =~ "batch=1 rows=3 done=3"
      refute output =~ "batch=2"

      committed = ciphertext_bytes(org) |> Map.values() |> Enum.count(&is_binary/1)
      assert committed == 3

      resume =
        output
        |> String.split("\n")
        |> Enum.find(&String.starts_with?(String.trim(&1), "mix ash_vault.backfill"))

      assert resume, "expected a resume command in:\n#{output}"
      assert resume =~ "--resume-from"
      assert resume =~ "--tenant #{org}"

      LegacyVault.reset!()

      argv =
        resume
        |> String.trim()
        |> String.split(~r/\s+/)
        |> Enum.drop(2)
        |> Kernel.++(["--yes"])

      resumed = capture_io(fn -> Mix.Tasks.AshVault.Backfill.run(argv) end)

      assert resumed =~ "Backfilled 3 row(s)"
      assert ciphertext_bytes(org) |> Map.values() |> Enum.all?(&is_binary/1)

      records = LegacyUser |> Ash.Query.load(:email) |> Ash.read!(tenant: org, authorize?: false)
      assert Enum.all?(records, &(&1.email == &1.legacy_email))
    end

    test "fails before the first batch when the provider is unreachable" do
      org = org()
      seed(org, 3)

      LegacyVault.break_after!(0)

      assert_raise Mix.Error, ~r/unavailable/, fn ->
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

      assert Enum.all?(ciphertext_bytes(org), fn {_id, blob} -> is_nil(blob) end)
    end
  end

  describe "multi-tenancy" do
    test "each tenant is backfilled under its own key and cross-tenant reads fail" do
      acme = org()
      globex = org()
      seed(acme, 3)
      seed(globex, 2)

      for tenant <- [acme, globex] do
        backfill(["AshVault.Test.LegacyUser", "email", "--tenant", tenant, "--yes"])
      end

      for tenant <- [acme, globex] do
        records =
          LegacyUser |> Ash.Query.load(:email) |> Ash.read!(tenant: tenant, authorize?: false)

        assert Enum.all?(records, &(&1.email == &1.legacy_email))
      end

      # Two distinct tenant keys.
      {:ok, acme_key} = Memory.current_key(acme)
      {:ok, globex_key} = Memory.current_key(globex)
      refute acme_key.key == globex_key.key

      # A ciphertext written for acme cannot be read as globex: both the key and the AAD
      # differ, so the AEAD tag does not verify.
      [[_id, blob]] =
        Repo.query!(
          "SELECT id::text, encrypted_email FROM legacy_users WHERE org_id::text = $1 LIMIT 1",
          [acme]
        ).rows

      wrong_context =
        AshVault.Context.Builder.from_calculation(LegacyUser, :email, %{
          tenant: globex,
          actor: nil,
          source_context: %{}
        })

      assert {:error, %AshVault.Errors.CiphertextIntegrityFailed{}} =
               AshVault.decrypt_value(AshVault.Test.Vault, blob, wrong_context, :string, [])
    end

    test "--all-tenants loops every tenant" do
      acme = org()
      globex = org()
      seed(acme, 2)
      seed(globex, 2)

      :persistent_term.put({__MODULE__, :tenants}, [acme, globex])

      output =
        backfill([
          "AshVault.Test.LegacyUser",
          "email",
          "--all-tenants",
          "Mix.Tasks.AshVault.BackfillTest.tenants/0",
          "--yes"
        ])

      assert output =~ "for tenant #{acme}"
      assert output =~ "for tenant #{globex}"

      for tenant <- [acme, globex] do
        assert tenant |> ciphertext_bytes() |> Map.values() |> Enum.all?(&is_binary/1)
      end
    end
  end

  describe "refusing to run" do
    test "when the field is not configured under ash_vault" do
      assert_raise Mix.Error, ~r/not configured under `ash_vault`/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacyUser",
            "legacy_email",
            "--tenant",
            org(),
            "--yes"
          ])
        end)
      end
    end

    test "when there is no plaintext source to read" do
      assert_raise Mix.Error, ~r/no attribute :nope to back-fill from/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacyUser",
            "email",
            "--from",
            "nope",
            "--tenant",
            org(),
            "--yes"
          ])
        end)
      end
    end

    test "when the key scope needs a tenant and none was given" do
      assert_raise Mix.Error, ~r/--tenant/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run(["AshVault.Test.LegacyUser", "email", "--yes"])
        end)
      end
    end

    test "when the chosen update action is require_atomic?" do
      assert_raise Mix.Error, ~r/require_atomic\? true/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacyUser",
            "email",
            "--tenant",
            org(),
            "--action",
            "update_atomic",
            "--yes"
          ])
        end)
      end
    end
  end

  @doc false
  def tenants, do: :persistent_term.get({__MODULE__, :tenants})
end
