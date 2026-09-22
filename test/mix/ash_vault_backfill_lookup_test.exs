defmodule Mix.Tasks.AshVault.BackfillLookupTest do
  @moduledoc """
  `mix ash_vault.backfill --lookup` end to end, against PostgreSQL.

  The load-bearing assertions: a token written by the backfill must be the one a fresh
  `AshVault.Query.filter_by/4` computes (otherwise the migration produces rows nobody can
  find), and a second run must be a no-op.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AshVault.Backfill
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Repo
  alias AshVault.Test.SearchUser

  @moduletag :postgres

  setup do
    start_supervised!({Memory, name: Memory})
    AshVault.Test.Db.reset!()

    %{org: Ash.UUID.generate()}
  end

  # Write rows through the ordinary path, then blank the token column — which is exactly
  # the state a table is in after `searchable?: true` is added to a field that already
  # held ciphertext.
  defp seed_without_tokens!(org, emails) do
    records =
      for email <- emails do
        SearchUser
        |> Ash.Changeset.for_create(:create, %{org_id: org, email: email})
        |> Ash.create!(tenant: org)
      end

    Repo.query!("UPDATE search_users SET email_lookup = NULL")

    records
  end

  defp tokens do
    "SELECT id::text, email_lookup FROM search_users ORDER BY id"
    |> Repo.query!([])
    |> Map.fetch!(:rows)
    |> Map.new(fn [id, token] -> {id, token} end)
  end

  defp run!(org, opts \\ []) do
    Backfill.run(SearchUser, :email, Keyword.merge([lookup?: true, tenant: org], opts))
  end

  describe "the engine" do
    test "populates tokens that a fresh lookup matches", %{org: org} do
      [a, b] = seed_without_tokens!(org, ["jake@example.com", "jane@example.com"])

      assert Enum.all?(Map.values(tokens()), &is_nil/1)

      assert {:ok, stats} = run!(org)
      assert stats.done == 2

      assert [%{id: id}] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "jake@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert id == a.id

      assert [%{id: id}] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "jane@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert id == b.id
    end

    test "normalizes exactly as the write path does", %{org: org} do
      # ` Mixed@Example.COM ` was normalized to `mixed@example.com` on write, so the
      # backfill decrypts the normalized value and must hash that, unchanged.
      [record] = seed_without_tokens!(org, [" Mixed@Example.COM "])

      assert {:ok, %{done: 1}} = run!(org)

      assert [%{id: id}] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "MIXED@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert id == record.id
    end

    test "is idempotent: a second run touches nothing", %{org: org} do
      seed_without_tokens!(org, ["a@example.com", "b@example.com", "c@example.com"])

      assert {:ok, %{done: 3}} = run!(org)
      after_first = tokens()

      assert {:ok, %{total: 0, done: 0, batches: 0}} = run!(org)
      assert tokens() == after_first
    end

    test "writes ONLY the token column — the ciphertext is untouched", %{org: org} do
      seed_without_tokens!(org, ["ct@example.com"])

      before =
        "SELECT id::text, encrypted_email FROM search_users"
        |> Repo.query!([])
        |> Map.fetch!(:rows)

      assert {:ok, %{done: 1}} = run!(org)

      assert before ==
               "SELECT id::text, encrypted_email FROM search_users"
               |> Repo.query!([])
               |> Map.fetch!(:rows)
    end

    test "skips rows with no ciphertext rather than looping on them forever", %{org: org} do
      seed_without_tokens!(org, ["has@example.com"])

      Repo.query!(
        "INSERT INTO search_users (id, org_id, encrypted_email, email_lookup) " <>
          "VALUES (gen_random_uuid(), $1, NULL, NULL)",
        [Ecto.UUID.dump!(org)]
      )

      assert {:ok, stats} = run!(org)
      assert stats.total == 1
      assert stats.done == 1
    end

    test "pages in batches", %{org: org} do
      seed_without_tokens!(org, for(n <- 1..25, do: "user#{n}@example.com"))

      assert {:ok, stats} = run!(org, batch_size: 10)
      assert stats.done == 25
      assert stats.batches == 3
    end

    test "a dry run writes nothing", %{org: org} do
      seed_without_tokens!(org, ["dry@example.com"])

      assert {:ok, %{dry_run?: true}} = run!(org, dry_run?: true)
      assert Enum.all?(Map.values(tokens()), &is_nil/1)
    end

    test "a non-searchable field is refused by name" do
      assert {:error, error} =
               Backfill.run(AshVault.Test.LegacyUser, :email, lookup?: true, tenant: "x")

      assert Exception.message(error) =~ "is not `searchable?: true`"
    end

    test "refuses a row whose ciphertext predates the current `normalize:`", %{org: org} do
      # Write the ciphertext by hand, under NO normalization, which is the state a column
      # is left in when `normalize:` is changed after rows exist.
      id = Ash.UUID.generate()

      context =
        AshVault.Context.Builder.from_query(
          Ash.Query.set_tenant(Ash.Query.new(SearchUser), org),
          :email,
          %{tenant: org, actor: nil, source_context: %{}}
        )

      blob =
        AshVault.Test.Vault.encrypt!(
          AshVault.Serializer.serialize!(
            " Stale@Example.COM ",
            Ash.Type.String,
            [],
            SearchUser,
            :email
          ),
          context
        )

      Repo.query!(
        "INSERT INTO search_users (id, org_id, encrypted_email, email_lookup) " <>
          "VALUES ($1, $2, $3, NULL)",
        [Ecto.UUID.dump!(id), Ecto.UUID.dump!(org), blob]
      )

      assert {:error, error, _stats} = run!(org)
      message = Exception.message(error)

      assert message =~ "was encrypted under a different `normalize:`"
      assert message =~ "no plaintext column left to re-encrypt from"

      # And it wrote nothing: a token here would make the row findable as
      # "stale@example.com" while it still decrypts to " Stale@Example.COM ".
      assert Enum.all?(Map.values(tokens()), &is_nil/1)
    end

    test "--lookup and --verify are refused together", %{org: org} do
      assert {:error, error} = run!(org, verify?: true)
      assert Exception.message(error) =~ "cannot be combined"
    end

    test "a destroyed scope fails before any row is written", %{org: org} do
      seed_without_tokens!(org, ["erased@example.com"])
      assert :ok = AshVault.destroy_keys!(AshVault.Test.Vault, org)

      assert {:error, %AshVault.Errors.KeyDestroyed{}} = run!(org)
      assert Enum.all?(Map.values(tokens()), &is_nil/1)
    end
  end

  describe "the Mix task" do
    test "runs, reports the target column, and populates tokens", %{org: org} do
      seed_without_tokens!(org, ["task@example.com"])

      output =
        capture_io(fn ->
          Mix.Tasks.AshVault.Backfill.run([
            "AshVault.Test.SearchUser",
            "email",
            "--tenant",
            org,
            "--lookup",
            "--yes"
          ])
        end)

      assert output =~ "lookup=true"
      assert output =~ "target=email_lookup"
      assert output =~ "Backfilled 1 row(s)"

      assert [_] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "task@example.com", tenant: org)
               |> Ash.read!(tenant: org)
    end
  end
end
