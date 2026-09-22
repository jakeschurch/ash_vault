defmodule AshVault.SearchableFieldsPostgresTest do
  @moduledoc """
  The parts of `searchable?`/`unique?` that only a real database can answer: whether the
  unique index actually rejects a duplicate, whether it is scoped per tenant, and whether
  a lookup query uses the index instead of scanning the table.
  """

  use ExUnit.Case, async: false

  require Ash.Query

  @moduletag :postgres

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Repo
  alias AshVault.Test.SearchUser

  setup do
    start_supervised!({Memory, name: Memory})
    AshVault.Test.Db.reset!()

    %{org: Ash.UUID.generate(), other: Ash.UUID.generate()}
  end

  defp create(org, email) do
    SearchUser
    |> Ash.Changeset.for_create(:create, %{org_id: org, email: email})
    |> Ash.create(tenant: org)
  end

  defp create!(org, email) do
    {:ok, record} = create(org, email)
    record
  end

  describe "unique?" do
    test "rejects a duplicate value in the same tenant", %{org: org} do
      assert {:ok, _first} = create(org, "dup@example.com")
      assert {:error, error} = create(org, "dup@example.com")

      # The database index is what enforces it; Ash turns the constraint violation into
      # an ordinary invalid-changes error.
      assert %Ash.Error.Invalid{} = error
    end

    test "rejects a duplicate that differs only by the normalization", %{org: org} do
      assert {:ok, _first} = create(org, "dup2@example.com")
      assert {:error, %Ash.Error.Invalid{}} = create(org, " Dup2@Example.COM ")
    end

    test "permits the same value in a different tenant", %{org: org, other: other} do
      assert {:ok, _a} = create(org, "shared@example.com")
      assert {:ok, _b} = create(other, "shared@example.com")

      assert [_] = Ash.read!(SearchUser, tenant: org)
      assert [_] = Ash.read!(SearchUser, tenant: other)
    end

    test "permits any number of nil values — nils_distinct? and Postgres agree", %{org: org} do
      assert {:ok, _a} = create(org, nil)
      assert {:ok, _b} = create(org, nil)
      assert {:ok, _c} = create(org, nil)

      assert 3 == length(Ash.read!(SearchUser, tenant: org))
    end

    test "the ciphertext column is NOT what is constrained", %{org: org} do
      a = create!(org, "ct@example.com")
      b = create!(org, "ct2@example.com")

      # Two different plaintexts, two different tokens — but note the ciphertexts would
      # differ even for the SAME plaintext, which is exactly why the constraint cannot
      # live on them.
      refute a.encrypted_email == b.encrypted_email

      # The token is `select_by_default?: false` on a data layer that can select, so it
      # is NotLoaded on a returned record — a stable per-scope fingerprint of the
      # plaintext has no business in every struct that reaches a log line. Asking for it
      # explicitly is the only way to see it.
      assert %Ash.NotLoaded{} = a.email_lookup

      [a, b] =
        SearchUser
        |> Ash.Query.select([:id, :email_lookup])
        |> Ash.Query.filter(id in ^[a.id, b.id])
        |> Ash.Query.sort(id: :asc)
        |> Ash.read!(tenant: org)

      refute a.email_lookup == b.email_lookup
    end
  end

  describe "the lookup column is indexed and used" do
    # Seeded inside each test rather than in a `setup`, because the module-level `setup`
    # truncates and the two orderings are easy to get wrong silently — an empty table
    # makes the EXPLAIN assertion below pass or fail for the wrong reason.
    defp seed!(org, count) do
      for n <- 1..count, do: create!(org, "user#{n}@example.com")
      Repo.query!("ANALYZE search_users")
      :ok
    end

    test "the query Ash actually issues plans as an index scan, not a sequential scan",
         %{org: org} do
      # Enough rows that the planner has a real reason to prefer the index; on a handful
      # of rows a sequential scan is genuinely cheaper and the assertion would be testing
      # the planner's cost model rather than the schema.
      seed!(org, 2_000)

      # The SQL is captured from Ecto's own telemetry rather than reconstructed, so the
      # EXPLAIN is of the statement AshPostgres really sent — including whatever the
      # multitenancy layer added to it.
      test_pid = self()
      handler = {__MODULE__, System.unique_integer([:positive])}

      :telemetry.attach(
        handler,
        [:ash_vault, :test, :repo, :query],
        fn _event, _measurements, metadata, _config ->
          if metadata.query =~ "email_lookup" do
            send(test_pid, {:sql, metadata.query, metadata.params})
          end
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      assert [_] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "user250@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert_receive {:sql, sql, params}

      %Postgrex.Result{rows: rows} = Repo.query!("EXPLAIN " <> sql, params)
      plan = rows |> List.flatten() |> Enum.join("\n")

      assert plan =~ "Index Scan" or plan =~ "Index Only Scan" or plan =~ "Bitmap",
             "expected an index scan on search_users_email_lookup_unique_index, got:\n" <> plan

      refute plan =~ "Seq Scan"
    end

    test "the generated read action finds one row among many", %{org: org} do
      seed!(org, 50)

      assert [_] =
               SearchUser
               |> Ash.Query.for_read(:by_email, %{email: "USER25@example.com"}, tenant: org)
               |> Ash.read!(tenant: org)
    end
  end

  describe "round trip" do
    test "the row decrypts to the normalized value it was stored under", %{org: org} do
      record = create!(org, " Round@Example.COM ")

      loaded = Ash.load!(record, [:email], tenant: org)
      assert loaded.email == "round@example.com"

      assert [%{id: id}] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "round@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert id == record.id
    end
  end
end
