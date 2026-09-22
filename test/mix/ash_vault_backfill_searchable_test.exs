defmodule Mix.Tasks.AshVault.BackfillSearchableTest do
  @moduledoc """
  Back-filling a field that is `searchable?: true` as well as `backfill_from:`.

  The combination used to write half a row. `encrypt_batch/2` called
  `AshVault.encrypt_value/4` directly instead of `AshVault.write_attributes/4`, and
  `write_batch/3` applied exactly one column, so a backfilled row got ciphertext and a
  NULL `email_lookup`: unfindable through `AshVault.Query.filter_by/4`, its `unique?`
  constraint unenforced, and — with a `normalize:` configured — holding the *raw* legacy
  value where every ordinary write stores the normalized one. `verify` had no token check
  at all, so it reported the row as correct, and the migration guide's next step drops the
  plaintext column, making it permanent.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AshVault.Backfill
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.LegacyPlainSearchUser
  alias AshVault.Test.LegacySearchUser

  @tenant "acme"

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp seed!(resource, legacy_emails) do
    for email <- legacy_emails do
      resource
      |> Ash.Changeset.for_create(:create, %{legacy_email: email}, tenant: @tenant)
      |> Ash.create!()
    end
  end

  defp rows(resource) do
    resource
    |> Ash.Query.select([:id, :legacy_email, :encrypted_email, :email_lookup])
    |> Ash.read!(tenant: @tenant)
  end

  defp decrypted(resource) do
    resource
    |> Ash.Query.load([:email])
    |> Ash.read!(tenant: @tenant)
    |> Enum.map(& &1.email)
    |> Enum.sort()
  end

  defp token!(resource, value) do
    AshVault.Lookup.token_for!(resource, :email, value, write_context(resource))
  end

  defp write_context(resource) do
    AshVault.Context.Builder.from_changeset(
      resource |> struct() |> Ash.Changeset.new() |> Ash.Changeset.set_tenant(@tenant),
      :email,
      %{tenant: @tenant, actor: nil, source_context: %{}}
    )
  end

  defp force!(record, attribute, value) do
    record
    |> Ash.Changeset.for_update(:update, %{}, tenant: @tenant)
    |> Ash.Changeset.force_change_attribute(attribute, value)
    |> Ash.update!()
  end

  describe "an ordinary backfill of a searchable field" do
    test "writes the lookup token in the same batch as the ciphertext" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])

      assert {:ok, %{total: 2, done: 2, remaining: 0}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      tokens = Enum.map(rows(LegacySearchUser), & &1.email_lookup)

      refute Enum.any?(tokens, &is_nil/1),
             "a backfilled searchable row must carry its lookup token"

      assert Enum.all?(tokens, &is_binary/1)
      assert length(Enum.uniq(tokens)) == 2
    end

    test "encrypts the NORMALIZED value, exactly as an ordinary write does" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])

      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      assert decrypted(LegacySearchUser) == ["b@example.com", "jake@example.com"]
    end

    test "writes the token a fresh lookup computes, so filter_by finds the row" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])

      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      found =
        LegacySearchUser
        |> AshVault.Query.filter_by(:email, "jake@example.com", tenant: @tenant)
        |> Ash.read!(tenant: @tenant)

      assert [%{legacy_email: "Jake@Example.COM"}] = found

      assert {:ok, [%{legacy_email: "Jake@Example.COM"}]} =
               LegacySearchUser
               |> Ash.Query.for_read(:by_email, %{email: "jake@example.com"}, tenant: @tenant)
               |> Ash.read()
    end

    test "leaves `--lookup` nothing to do afterwards" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])

      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      assert {:ok, %{total: 0, done: 0}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant, lookup?: true)
    end
  end

  describe "an ordinary backfill with `normalize: :none`" do
    test "still writes the lookup token, and leaves the value untouched" do
      seed!(LegacyPlainSearchUser, ["Jake@Example.COM", "b@example.com"])

      assert {:ok, %{done: 2}} = Backfill.run(LegacyPlainSearchUser, :email, tenant: @tenant)

      tokens = Enum.map(rows(LegacyPlainSearchUser), & &1.email_lookup)
      refute Enum.any?(tokens, &is_nil/1)

      # `:none` is not "no normalization applied to the ciphertext" by accident — it is
      # the case that proves the missing column was the token, not the spelling.
      assert decrypted(LegacyPlainSearchUser) == ["Jake@Example.COM", "b@example.com"]

      found =
        LegacyPlainSearchUser
        |> AshVault.Query.filter_by(:email, "Jake@Example.COM", tenant: @tenant)
        |> Ash.read!(tenant: @tenant)

      assert [%{legacy_email: "Jake@Example.COM"}] = found
    end
  end

  describe "verify" do
    test "passes on a correctly back-filled searchable field" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])
      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      assert {:ok, %{checked: 2, mismatches: []}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant, verify?: true, sample: 0)
    end

    test "reports :lookup_missing for a row whose token is NULL" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])
      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      # Exactly the state the old backfill left every row in.
      [victim | _] = rows(LegacySearchUser)
      force!(victim, :email_lookup, nil)

      assert {:error, error, %{mismatches: mismatches}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant, verify?: true, sample: 0)

      assert [%{primary_key: pk, reason: :lookup_missing}] = mismatches
      assert pk == victim.id
      assert Exception.message(error) =~ "lookup_missing"
    end

    test "reports :lookup_mismatch for a token that is not the one a lookup computes" do
      seed!(LegacySearchUser, ["Jake@Example.COM", "b@example.com"])
      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      [victim | _] = rows(LegacySearchUser)
      force!(victim, :email_lookup, token!(LegacySearchUser, "someone.else@example.com"))

      assert {:error, _error, %{mismatches: mismatches}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant, verify?: true, sample: 0)

      assert [%{primary_key: _, reason: :lookup_mismatch}] = mismatches
    end

    test "does not call a normalized ciphertext a value_mismatch against the raw column" do
      # `legacy_email` holds `"Jake@Example.COM"`; the ciphertext holds
      # `"jake@example.com"`, because that is what an ordinary write stores. Comparing
      # the decrypted value against the RAW column would flag every such row.
      seed!(LegacySearchUser, ["Jake@Example.COM"])
      assert {:ok, _} = Backfill.run(LegacySearchUser, :email, tenant: @tenant)

      assert {:ok, %{mismatches: []}} =
               Backfill.run(LegacySearchUser, :email, tenant: @tenant, verify?: true, sample: 0)
    end
  end

  describe "the Mix task" do
    test "refuses --all-tenants together with --resume-from" do
      assert_raise Mix.Error, ~r/`--all-tenants` and `--resume-from` cannot be combined/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacySearchUser",
            "email",
            "--all-tenants",
            "AshVault.Test.NoSuchModule.tenants/0",
            "--resume-from",
            "00000000-0000-0000-0000-000000000000",
            "--yes"
          ])
        end)
      end
    end

    test "refuses --lookup together with --verify, naming --verify as the token check" do
      assert_raise Mix.Error, ~r/`--verify` on its own checks email_lookup/, fn ->
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.LegacySearchUser",
            "email",
            "--tenant",
            @tenant,
            "--lookup",
            "--verify",
            "--yes"
          ])
        end)
      end
    end
  end
end
