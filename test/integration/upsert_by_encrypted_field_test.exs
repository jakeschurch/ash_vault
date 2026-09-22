defmodule AshVault.UpsertByEncryptedFieldTest do
  @moduledoc """
  `upsert_identity: :<field>_lookup_unique` — "create or update this user by email",
  against a real PostgreSQL `ON CONFLICT`.

  ## Why this works at all

  The obvious worry is timing: `AshVault.Changes.Encrypt` computes the lookup token in a
  `before_action` hook, so is the token there when Ash resolves the upsert identity?

  It is, and the ordering question turns out to be moot in both directions:

    * The identity's *keys* are only ever read as **column names**, not values.
      `deps/ash/lib/ash/actions/create/create.ex:282-307` turns the identity into
      `upsert_keys`, and adds the multitenancy attribute itself when the identity is not
      `all_tenants?` — which is why `SetupEncryption` deliberately lists only
      `[:email_lookup]`.
    * The identity is never eager- or pre-checked.
      `deps/ash/lib/ash/changeset/changeset.ex:3236-3240` short-circuits
      `validate_identity/3` for the identity being upserted on, and in any case
      `SetupEncryption.add_lookup_identity/3` sets neither `eager_check_with` nor
      `pre_check_with`, so `eager_validate_identities/1`
      (`deps/ash/lib/ash/changeset/changeset.ex:3208-3232`) skips it entirely.

  The *values* are read at `Ash.DataLayer.upsert/4` time, which runs inside
  `Ash.Changeset.with_hooks/3` — after every `before_action` hook. By then the ciphertext
  and the token are ordinary attributes on the changeset.

  The tests below assert the SQL rather than inferring behaviour from the result, because
  "the row came back with the right values" passes for a no-op update too — see
  `upsert_fields`.
  """

  use ExUnit.Case, async: false

  require Ash.Query

  @moduletag :postgres

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.LooseSearchUser
  alias AshVault.Test.Repo
  alias AshVault.Test.SearchUser

  setup do
    start_supervised!({Memory, name: Memory})
    AshVault.Test.Db.reset!()

    %{org: Ash.UUID.generate(), other: Ash.UUID.generate()}
  end

  defp upsert(resource, org, attrs, opts \\ []) do
    resource
    |> Ash.Changeset.for_create(:upsert_by_email, Map.put(attrs, :org_id, org))
    |> Ash.create([tenant: org] ++ opts)
  end

  defp upsert!(resource, org, attrs, opts \\ []) do
    {:ok, record} = upsert(resource, org, attrs, opts)
    record
  end

  defp rows(org) do
    Repo.query!(
      "SELECT id, name, encrypted_email, email_lookup FROM search_users " <>
        "WHERE org_id = $1 ORDER BY name",
      [Ecto.UUID.dump!(org)]
    ).rows
  end

  # Capture the statement AshPostgres really sent, rather than reconstructing it. The
  # ON CONFLICT target and the DO UPDATE SET list are the whole behaviour under test and
  # neither is visible in the returned record.
  defp capture_insert_sql(fun) do
    test_pid = self()
    handler = {__MODULE__, System.unique_integer([:positive])}

    :telemetry.attach(
      handler,
      [:ash_vault, :test, :repo, :query],
      fn _event, _measurements, metadata, _config ->
        if metadata.query =~ "INSERT INTO \"search_users\"" do
          send(test_pid, {:sql, metadata.query})
        end
      end,
      nil
    )

    try do
      result = fun.()
      assert_receive {:sql, sql}
      {result, sql}
    after
      :telemetry.detach(handler)
    end
  end

  describe "the SQL" do
    test "ON CONFLICT targets the tenant plus the lookup token, and updates the ciphertext",
         %{org: org} do
      {_record, sql} =
        capture_insert_sql(fn -> upsert!(SearchUser, org, %{email: "sql@example.com"}) end)

      # The token, not the ciphertext. A unique index on `encrypted_email` would
      # constrain nothing: AES-GCM draws a fresh nonce per write.
      assert sql =~ ~s|ON CONFLICT ("org_id", "email_lookup")|
      refute sql =~ "ON CONFLICT (\"encrypted_email\""

      # `org_id` is in the conflict target even though the generated identity lists only
      # `[:email_lookup]` — Ash adds the multitenancy attribute itself
      # (deps/ash/lib/ash/actions/create/create.ex:298-307).

      # And the UPDATE half really rewrites the ciphertext. Asserted on the statement,
      # not on the row: a row whose email did not change reads identically either way.
      assert sql =~ ~s|DO UPDATE SET|
      assert sql =~ ~s|"encrypted_email" = EXCLUDED."encrypted_email"|
    end
  end

  describe "create or update by email" do
    test "the first upsert inserts", %{org: org} do
      assert {:ok, record} = upsert(SearchUser, org, %{name: "first", email: "new@example.com"})

      assert [[_id, "first", ciphertext, token]] = rows(org)
      assert is_binary(ciphertext)
      assert is_binary(token)
      assert record.id
    end

    test "the second upsert updates the same row instead of inserting", %{org: org} do
      first = upsert!(SearchUser, org, %{name: "before", email: "same@example.com"})
      second = upsert!(SearchUser, org, %{name: "after", email: "same@example.com"})

      assert first.id == second.id
      assert [[_id, "after", _ciphertext, _token]] = rows(org)
    end

    test "it matches through the field's normalization", %{org: org} do
      first = upsert!(SearchUser, org, %{name: "before", email: "norm@example.com"})
      second = upsert!(SearchUser, org, %{name: "after", email: "  Norm@Example.COM  "})

      assert first.id == second.id
      assert [[_id, "after", _, _]] = rows(org)
    end

    test "the ciphertext is rewritten on the update half, not left stale", %{org: org} do
      _first = upsert!(SearchUser, org, %{name: "before", email: "rewrite@example.com"})
      [[_, _, before_ciphertext, before_token]] = rows(org)

      _second = upsert!(SearchUser, org, %{name: "after", email: "rewrite@example.com"})
      [[_, _, after_ciphertext, after_token]] = rows(org)

      # A fresh nonce per write means a re-encryption of the same plaintext is visibly
      # different bytes. That is the proof the UPDATE half wrote a new ciphertext rather
      # than doing nothing.
      refute before_ciphertext == after_ciphertext

      # The token is deterministic, so it is the one thing that must NOT move.
      assert before_token == after_token
    end

    test "the updated row still decrypts", %{org: org} do
      record = upsert!(SearchUser, org, %{name: "before", email: "decrypt@example.com"})
      _ = upsert!(SearchUser, org, %{name: "after", email: "Decrypt@Example.com"})

      assert %{email: "decrypt@example.com", name: "after"} =
               Ash.get!(SearchUser, record.id, tenant: org, load: [:email])
    end

    test "a plain (non-upsert) create still raises on the duplicate", %{org: org} do
      _ = upsert!(SearchUser, org, %{email: "plain@example.com"})

      assert {:error, %Ash.Error.Invalid{}} =
               SearchUser
               |> Ash.Changeset.for_create(:create, %{org_id: org, email: "plain@example.com"})
               |> Ash.create(tenant: org)
    end
  end

  describe "tenancy" do
    test "the same email in two tenants upserts into two rows", %{org: org, other: other} do
      a = upsert!(SearchUser, org, %{name: "a", email: "two@example.com"})
      b = upsert!(SearchUser, other, %{name: "b", email: "two@example.com"})

      refute a.id == b.id
      assert [_] = Ash.read!(SearchUser, tenant: org)
      assert [_] = Ash.read!(SearchUser, tenant: other)

      # NOTE: this passing does NOT prove `org_id` is in the ON CONFLICT column set.
      # The two tenants derive different lookup keys, so the tokens differ and the rows
      # would not collide even on a global index. The tenant's presence in the conflict
      # target is asserted on the SQL, above, and comes from
      # deps/ash/lib/ash/actions/create/create.ex:298-307.
      [[_, _, _, token_a]] = rows(org)
      [[_, _, _, token_b]] = rows(other)
      refute token_a == token_b
    end

    test "upserting without a tenant is refused, never silently global", %{org: org} do
      # Ash's own multitenancy requirement fires first here
      # (deps/ash/lib/ash/actions/create/create.ex:89), before the encrypt hook ever
      # runs, so the error class is Ash's rather than AshVault's `MissingScope`. Either
      # way the write is refused: what must never happen is a row landing with a token
      # computed under some other scope, or under none.
      assert_raise Ash.Error.Invalid, ~r/require a tenant/, fn ->
        SearchUser
        |> Ash.Changeset.for_create(:upsert_by_email, %{org_id: org, email: "no@example.com"})
        |> Ash.create!()
      end

      assert [] == rows(org)
    end
  end

  describe "nil plaintext" do
    test "every nil-email upsert inserts another row", %{org: org} do
      _ = upsert!(SearchUser, org, %{name: "a", email: nil})
      _ = upsert!(SearchUser, org, %{name: "b", email: nil})
      _ = upsert!(SearchUser, org, %{name: "c", email: nil})

      # A nil plaintext produces a nil token, and PostgreSQL's ON CONFLICT never matches
      # NULL — the same rule that makes `nils_distinct?: true` true of the index. So
      # "upsert by email" with no email is an INSERT, every time, forever. That is
      # correct (there is no key to match on) and silent, which is why it is asserted
      # here rather than left to be discovered in production.
      assert 3 == length(rows(org))
      assert Enum.all?(rows(org), fn [_, _, _, token] -> is_nil(token) end)
    end
  end

  describe "upsert_fields" do
    test "naming the field itself silently degrades to a no-op update", %{org: org} do
      _ = upsert!(SearchUser, org, %{name: "before", email: "uf@example.com"})
      [[_, _, before_ciphertext, _]] = rows(org)

      {_result, sql} =
        capture_insert_sql(fn ->
          upsert!(SearchUser, org, %{name: "after", email: "uf@example.com"},
            upsert_fields: [:email]
          )
        end)

      # `:email` is a *calculation* on an AshVault resource — the plaintext attribute is
      # gone. AshPostgres filters `upsert_fields` down to attributes actually changing
      # (deps/ash_postgres/lib/data_layer.ex:2845-2846), `:email` is not one, the list
      # empties, and the empty case falls back to the conflict keys themselves
      # (deps/ash_postgres/lib/data_layer.ex:2856-2858).
      #
      # The result is `DO UPDATE SET "org_id" = EXCLUDED."org_id", "email_lookup" =
      # EXCLUDED."email_lookup"` — an update that writes the row's own key back over
      # itself. No error, no warning, and the "Only attribute names can be used in
      # upsert_fields" raise at data_layer.ex:2884-2888 is never reached because the
      # filter removed the offending name first.
      assert sql =~ ~s|DO UPDATE SET "org_id" = EXCLUDED."org_id"|
      refute sql =~ "encrypted_email\" = EXCLUDED"

      [[_, name, after_ciphertext, _]] = rows(org)
      assert name == "before", "the name was silently not updated"
      assert after_ciphertext == before_ciphertext, "the ciphertext was silently not updated"
    end

    test "naming the generated attributes works", %{org: org} do
      _ = upsert!(SearchUser, org, %{name: "before", email: "uf2@example.com"})
      [[_, _, before_ciphertext, _]] = rows(org)

      _ =
        upsert!(SearchUser, org, %{name: "after", email: "uf2@example.com"},
          upsert_fields: [:name, :encrypted_email]
        )

      [[_, name, after_ciphertext, _]] = rows(org)
      assert name == "after"
      refute after_ciphertext == before_ciphertext
    end
  end

  describe "a changed normalize:" do
    test "a row written under one strategy is invisible to an upsert under another",
         %{org: org} do
      strict = upsert!(SearchUser, org, %{name: "strict", email: "Renorm@Example.com"})

      # `LooseSearchUser` is the same table and the same field with `normalize: :none`.
      # `"Renorm@Example.com"` therefore hashes to a different token than the
      # `:downcase_trim` row already holding the same address, so ON CONFLICT does not
      # fire and a second row lands.
      loose = upsert!(LooseSearchUser, org, %{name: "loose", email: "Renorm@Example.com"})

      refute strict.id == loose.id
      assert 2 == length(rows(org))

      # Both rows decrypt, each to the value its own strategy normalized to. Nothing is
      # corrupted — the tokens simply no longer describe the same equivalence classes.
      assert %{email: "renorm@example.com"} =
               Ash.get!(SearchUser, strict.id, tenant: org, load: [:email])

      assert %{email: "Renorm@Example.com"} =
               Ash.get!(LooseSearchUser, loose.id, tenant: org, load: [:email])
    end

    test "the old row is also invisible to a plain lookup under the new strategy",
         %{org: org} do
      _ = upsert!(SearchUser, org, %{name: "strict", email: "Gone@Example.com"})

      # This is the failure a `normalize:` change causes in production, in its purest
      # form: the row is right there, and the lookup returns nothing. The fix is a
      # backfill (`mix ash_vault.backfill --lookup`), never a rotation.
      assert [] =
               LooseSearchUser
               |> AshVault.Query.filter_by(:email, "gone@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert [_] =
               SearchUser
               |> AshVault.Query.filter_by(:email, "gone@example.com", tenant: org)
               |> Ash.read!(tenant: org)
    end
  end

  describe "Ash.get/3 by the generated identity" do
    test "finds the row by its token", %{org: org} do
      record = upsert!(SearchUser, org, %{name: "byid", email: "identity@example.com"})

      token =
        AshVault.Lookup.token_for!(
          SearchUser,
          :email,
          "identity@example.com",
          AshVault.Context.Builder.from_query(
            SearchUser |> Ash.Query.new() |> Ash.Query.set_tenant(org),
            :email,
            %{tenant: org, actor: nil, source_context: %{}}
          )
        )

      assert {:ok, %{id: id}} = Ash.get(SearchUser, [email_lookup: token], tenant: org)
      assert id == record.id
    end

    test "returns not-found for a token that matches nothing", %{org: org} do
      assert {:error, %Ash.Error.Invalid{errors: [%Ash.Error.Query.NotFound{}]}} =
               Ash.get(SearchUser, [email_lookup: :crypto.strong_rand_bytes(32)], tenant: org)
    end
  end

  describe "dedupe by GROUP BY" do
    test "the recipe finds nothing while unique? is enforced", %{org: org} do
      _ = upsert!(SearchUser, org, %{name: "one", email: "clean1@example.com"})
      _ = upsert!(SearchUser, org, %{name: "two", email: "clean2@example.com"})

      assert [] == duplicate_tokens("search_users", org)
    end

    test "it finds rows sharing an encrypted value, without decrypting anything",
         %{org: org} do
      # `DedupeUser` is `searchable?: true` with no `unique?`, over its own table with a
      # plain index — the shape every table has before someone adds the constraint, and
      # the only shape where this recipe has anything to find.
      a = create_dedupe!(org, "one", "dupe@example.com")
      b = create_dedupe!(org, "two", " Dupe@Example.COM ")
      _ = create_dedupe!(org, "solo", "solo@example.com")

      assert [[token, 2]] = duplicate_tokens("dedupe_users", org)
      assert is_binary(token)

      # The duplicate group resolves back to real rows through an ordinary filter on the
      # token — still without a single decryption. The token IS the query.
      ids =
        AshVault.Test.DedupeUser
        |> Ash.Query.filter(email_lookup == ^token)
        |> Ash.read!(tenant: org)
        |> Enum.map(& &1.id)
        |> Enum.sort()

      assert ids == Enum.sort([a.id, b.id])

      # Note what the group means: the two rows agree on the *normalized* plaintext.
      # `:downcase_trim` is what made `" Dupe@Example.COM "` and `"dupe@example.com"`
      # the same row group, and a different `normalize:` would partition them
      # differently. The column implements one equality relation, not "the same email".
    end

    defp create_dedupe!(org, name, email) do
      AshVault.Test.DedupeUser
      |> Ash.Changeset.for_create(:create, %{org_id: org, name: name, email: email})
      |> Ash.create!(tenant: org)
    end

    defp duplicate_tokens(table, org) do
      Repo.query!(
        """
        SELECT email_lookup, count(*)
        FROM #{table}
        WHERE org_id = $1 AND email_lookup IS NOT NULL
        GROUP BY email_lookup
        HAVING count(*) > 1
        ORDER BY count(*) DESC
        """,
        [Ecto.UUID.dump!(org)]
      ).rows
    end
  end
end
