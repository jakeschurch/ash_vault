defmodule AshVault.Acceptance.DefinitionOfDoneTest do
  @moduledoc """
  The definition-of-done checklist: one test per numbered item, each named in a comment,
  so this file answers "is AshVault done?" without re-reading the whole suite.

  ## Provenance of the list — read this before trusting the numbering

  `docs/TEST_HARNESS_SPEC.md` says "one test per numbered item in §32 of the plan". **That
  plan is not in this repository** — there is no §32 anywhere under `docs/`, and no
  17-item numbered list in any spec file. The list below was therefore *reconstructed*
  from the three anchors `TEST_HARNESS_SPEC.md` does pin down —

    * item 4  = "DB contains no plaintext"
    * items 7 and 8 = cross-tenant and cross-field ciphertext substitution
    * item 17 = `mix ash_vault.backfill`

  — plus the in-scope numbered attacks in `docs/threat-model.md` and the test list in
  `docs/EXTENSION_SPEC.md` §11. The three anchors sit at their stated numbers. The
  remaining fourteen are a faithful reconstruction, not an authoritative transcription;
  if the original §32 surfaces, re-check the numbering against it.

  ### The checklist

   1. an encrypted attribute round-trips through `Ash.create`/`Ash.read`
   2. the plaintext attribute is replaced — no plaintext column exists in the data layer
   3. plaintext is scrubbed from `changeset.arguments` and `changeset.params`
   4. the database contains no plaintext — the raw column is an `"AV"` envelope  [anchor]
   5. embedded, array and array-of-embedded attributes round-trip
   6. nil handling — `encrypt_nil?: true` stores ciphertext, `false` stores SQL NULL
   7. cross-tenant ciphertext substitution fails with `CiphertextIntegrityFailed`  [anchor]
   8. cross-field / cross-resource substitution fails with `CiphertextIntegrityFailed`  [anchor]
   9. tampered ciphertext fails with `CiphertextIntegrityFailed`
  10. multitenancy — each tenant reads its own value; one tenant key spans resources
  11. rotation — the envelope carries the key version; pre-rotation rows keep decrypting
  12. crypto-erasure — a destroyed scope reads `KeyDestroyed`; the rows stay
  13. the operational errors are distinguishable from one another
  14. field policies still govern the decrypted calculation
  15. `key_lifecycle` actions exist on the scope-owner resource and act on its scope
  16. restoring a pre-erasure `pg_dump` does not resurrect the erased tenant (§27)
  17. `mix ash_vault.backfill` encrypts an existing plaintext column  [anchor]
  """

  use ExUnit.Case, async: false

  @moduletag :postgres

  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.MissingScope
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.Local
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.AcceptanceUser
  alias AshVault.Test.AcceptanceVaultResolver
  alias AshVault.Test.Backup
  alias AshVault.Test.Contact
  alias AshVault.Test.Db
  alias AshVault.Test.EtsTicket
  alias AshVault.Test.LegacyUser
  alias AshVault.Test.Organization
  alias AshVault.Test.Repo
  alias AshVault.Test.User

  @acme "11111111-1111-1111-1111-111111111111"
  @other "22222222-2222-2222-2222-222222222222"

  setup do
    start_supervised!({Memory, name: Memory})
    Db.reset!()
    on_exit(fn -> AcceptanceVaultResolver.put(AshVault.Test.Vault) end)
    :ok
  end

  # ── 1. an encrypted attribute round-trips ──────────────────────────────────────────
  test "1. create then read returns the plaintext" do
    create!(%{email: "one@example.invalid"})

    assert [%{email: "one@example.invalid"}] = read!(@acme, [:email])
  end

  # ── 2. the plaintext attribute is replaced ─────────────────────────────────────────
  test "2. there is no plaintext column — only the encrypted backing column" do
    assert [] =
             columns("users", ~w[email ssn profile tags contacts]),
           "a plaintext column survived the transformer"

    assert Enum.sort(columns("users", ~w[encrypted_email encrypted_ssn])) ==
             ["encrypted_email", "encrypted_ssn"]

    refute :email in Enum.map(Ash.Resource.Info.attributes(User), & &1.name)
    assert :encrypted_email in Enum.map(Ash.Resource.Info.attributes(User), & &1.name)
  end

  # ── 3. plaintext is scrubbed from the changeset ────────────────────────────────────
  test "3. the plaintext is gone from changeset arguments and params after the change" do
    test_pid = self()

    User
    |> Ash.Changeset.for_create(
      :create,
      %{org_id: @acme, name: "n", email: "scrub@example.invalid"},
      tenant: @acme,
      authorize?: false
    )
    |> Ash.Changeset.after_action(fn changeset, record ->
      send(test_pid, {:changeset, changeset})
      {:ok, record}
    end)
    |> Ash.create!()

    assert_received {:changeset, changeset}

    refute Map.has_key?(changeset.arguments, :email)
    refute Map.has_key?(changeset.params, :email)
    refute Map.has_key?(changeset.params, "email")
    refute inspect(changeset.arguments) =~ "scrub@example.invalid"
    refute inspect(changeset.params) =~ "scrub@example.invalid"
  end

  # ── 4. the database contains no plaintext ── [anchor: item 4] ──────────────────────
  test "4. the raw column holds an AV envelope and no substring of the plaintext" do
    email = "plaintext-needle@example.invalid"
    ssn = "999-88-7777"
    create!(%{email: email, ssn: ssn})

    [[email_blob, ssn_blob]] = raw("SELECT encrypted_email, encrypted_ssn FROM users")

    assert <<"AV", 1::8, _::binary>> = email_blob
    assert <<"AV", 1::8, _::binary>> = ssn_blob

    for needle <- [email, ssn, "plaintext-needle", "example.invalid", "999-88"] do
      refute String.contains?(email_blob, needle)
      refute String.contains?(ssn_blob, needle)
    end
  end

  # ── 5. embedded, array and array-of-embedded attributes ────────────────────────────
  test "5. embedded, array and array-of-embedded attributes round-trip" do
    create!(%{
      email: "five@example.invalid",
      profile: %{nickname: "nick", age: 7},
      tags: ["x", "y"],
      contacts: [%{nickname: "c1", age: 1}, %{nickname: "c2", age: 2}]
    })

    [user] = read!(@acme, [:email, :profile, :tags, :contacts])

    assert user.profile.nickname == "nick"
    assert user.profile.age == 7
    assert user.tags == ["x", "y"]
    assert Enum.map(user.contacts, & &1.nickname) == ["c1", "c2"]
  end

  # ── 6. nil handling ────────────────────────────────────────────────────────────────
  test "6. encrypt_nil? true stores ciphertext, false stores SQL NULL" do
    create!(%{email: nil, ssn: nil})

    assert [[email_blob, nil]] = raw("SELECT encrypted_email, encrypted_ssn FROM users")
    assert <<"AV", 1::8, _::binary>> = email_blob

    assert [%{email: nil, ssn: nil}] = read!(@acme, [:email, :ssn])
  end

  # ── 7. cross-tenant ciphertext substitution ── [anchor: item 7] ────────────────────
  test "7. moving tenant B's ciphertext into tenant A's row fails authentication" do
    create!(%{email: "acme@example.invalid"}, @acme)
    create!(%{email: "other@example.invalid"}, @other)

    [[other_blob]] = raw("SELECT encrypted_email FROM users WHERE org_id = $1", [uuid(@other)])
    raw("UPDATE users SET encrypted_email = $1 WHERE org_id = $2", [other_blob, uuid(@acme)])

    errors = read_errors(@acme, [:email])

    assert Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1))
    refute Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
  end

  # ── 8. cross-field and cross-resource substitution ── [anchor: item 8] ─────────────
  test "8. moving ciphertext between fields, or between resources, fails authentication" do
    create!(%{email: "eight@example.invalid", ssn: "123-45-6789"})

    # field -> field, same row, same key
    raw("UPDATE users SET encrypted_email = encrypted_ssn")
    assert Enum.any?(read_errors(@acme, [:email]), &match?(%CiphertextIntegrityFailed{}, &1))

    # resource -> resource, same tenant, same key
    Contact
    |> Ash.Changeset.for_create(:create, %{org_id: @acme, phone: "555-0100"}, tenant: @acme)
    |> Ash.create!()

    [[ssn_blob]] = raw("SELECT encrypted_ssn FROM users")
    raw("UPDATE contacts SET encrypted_phone = $1", [ssn_blob])

    assert {:error, %Ash.Error.Invalid{errors: contact_errors}} =
             Contact |> Ash.Query.load([:phone]) |> Ash.read(tenant: @acme)

    assert Enum.any?(contact_errors, &match?(%CiphertextIntegrityFailed{}, &1))
  end

  # ── 9. tampered ciphertext ─────────────────────────────────────────────────────────
  test "9. flipping a single byte of the stored ciphertext fails authentication" do
    create!(%{email: "nine@example.invalid"})

    [[blob]] = raw("SELECT encrypted_email FROM users")

    # Flip the very last byte — inside the ciphertext body, past nonce and tag.
    size = byte_size(blob) - 1
    <<head::binary-size(^size), last::8>> = blob
    tampered = <<head::binary, Bitwise.bxor(last, 0xFF)::8>>

    refute tampered == blob
    raw("UPDATE users SET encrypted_email = $1", [tampered])

    assert Enum.any?(read_errors(@acme, [:email]), &match?(%CiphertextIntegrityFailed{}, &1))
  end

  # ── 10. multitenancy ───────────────────────────────────────────────────────────────
  test "10. each tenant reads its own value, and one tenant key spans resources" do
    create!(%{email: "acme@example.invalid"}, @acme)
    create!(%{email: "other@example.invalid"}, @other)

    contact =
      Contact
      |> Ash.Changeset.for_create(:create, %{org_id: @acme, phone: "555-0100"}, tenant: @acme)
      |> Ash.create!()

    assert [%{email: "acme@example.invalid"}] = read!(@acme, [:email])
    assert [%{email: "other@example.invalid"}] = read!(@other, [:email])
    assert Ash.load!(contact, [:phone], tenant: @acme).phone == "555-0100"

    # One key lineage for the whole tenant: User and Contact share scope @acme.
    assert {:ok, %{version: 1, key: key}} = Memory.current_key(@acme)
    assert {:ok, %{key: other_key}} = Memory.current_key(@other)
    assert key != other_key
  end

  # ── 11. rotation ───────────────────────────────────────────────────────────────────
  test "11. the envelope carries the key version and old rows keep decrypting" do
    before_user = create!(%{email: "before@example.invalid"})
    assert {:ok, 2} = AshVault.rotate_key!(AshVault.Test.Vault, @acme)
    after_user = create!(%{email: "after@example.invalid"})

    assert {:ok, %{key_version: 1}} = AshVault.Envelope.decode(blob_of(before_user.id))
    assert {:ok, %{key_version: 2}} = AshVault.Envelope.decode(blob_of(after_user.id))

    assert read!(@acme, [:email]) |> Enum.map(& &1.email) |> Enum.sort() ==
             ["after@example.invalid", "before@example.invalid"]
  end

  # ── 12. crypto-erasure ─────────────────────────────────────────────────────────────
  test "12. a destroyed scope reads KeyDestroyed, the rows survive, other tenants are fine" do
    create!(%{email: "doomed@example.invalid"}, @acme)
    create!(%{email: "safe@example.invalid"}, @other)

    assert :ok = AshVault.destroy_keys!(AshVault.Test.Vault, @acme)

    errors = read_errors(@acme, [:email])
    assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
    refute Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1))

    assert [[1]] = raw("SELECT count(*) FROM users WHERE org_id = $1", [uuid(@acme)])
    assert [%{email: "safe@example.invalid"}] = read!(@other, [:email])
  end

  # ── 13. the operational errors are distinguishable ─────────────────────────────────
  test "13. KeyDestroyed, KeyNotFound, ProviderUnavailable, CiphertextIntegrityFailed and " <>
         "MissingScope are five distinct errors" do
    context = fn tenant ->
      %AshVault.Context{
        resource: User,
        field: :email,
        ash_context: %{tenant: tenant, actor: nil, source_context: %{}}
      }
    end

    live = "13-live-#{System.unique_integer([:positive])}"
    blob = AshVault.Test.Vault.encrypt!("plaintext", context.(live))

    # CiphertextIntegrityFailed — right key, wrong AAD (another tenant's scope).
    other = "13-other-#{System.unique_integer([:positive])}"
    AshVault.Test.Vault.encrypt!("x", context.(other))

    assert_raise CiphertextIntegrityFailed, fn ->
      AshVault.Test.Vault.decrypt!(blob, context.(other))
    end

    # KeyNotFound — an envelope naming a key version the provider has never minted.
    assert_raise KeyNotFound, fn ->
      AshVault.Test.Vault.decrypt!(with_key_version(blob, 99), context.(live))
    end

    # ProviderUnavailable — the provider is down. Never reported as erasure.
    assert_raise ProviderUnavailable, fn ->
      AshVault.Test.Support.UnavailableVault.encrypt!("x", context.(live))
    end

    # MissingScope — tenant-scoped encryption with no tenant in the context.
    assert {:error, %Ash.Error.Invalid{errors: ticket_errors}} =
             EtsTicket
             |> Ash.Changeset.for_create(:create, %{secret: "s"})
             |> Ash.create()

    assert Enum.any?(ticket_errors, &match?(%MissingScope{}, &1))

    # KeyDestroyed — and specifically not CiphertextIntegrityFailed.
    :ok = AshVault.destroy_keys!(AshVault.Test.Vault, live)

    assert_raise KeyDestroyed, fn ->
      AshVault.Test.Vault.decrypt!(blob, context.(live))
    end
  end

  # ── 14. field policies govern the decrypted calculation ────────────────────────────
  test "14. a denied field becomes ForbiddenField while the rest of the record reads" do
    create!(%{email: "fourteen@example.invalid", ssn: "123"})

    assert {:ok, [denied]} =
             User
             |> Ash.Query.load([:email, :ssn])
             |> Ash.read(tenant: @acme, actor: %{admin?: false})

    assert %Ash.ForbiddenField{} = denied.email
    assert denied.ssn == "123"
    assert denied.name == "n"

    assert {:ok, [allowed]} =
             User |> Ash.Query.load([:email]) |> Ash.read(tenant: @acme, actor: %{admin?: true})

    assert allowed.email == "fourteen@example.invalid"
  end

  # ── 15. key_lifecycle actions on the scope owner ───────────────────────────────────
  test "15. rotate_key and destroy_keys run as actions on the scope-owner resource" do
    create!(%{email: "fifteen@example.invalid"})

    assert {:ok, 2} =
             Organization
             |> Ash.ActionInput.for_action(:rotate_key, %{}, tenant: @acme)
             |> Ash.run_action()

    rotated = create!(%{email: "rotated@example.invalid"})
    assert {:ok, %{key_version: 2}} = AshVault.Envelope.decode(blob_of(rotated.id))

    assert {:ok, :ok} =
             Organization
             |> Ash.ActionInput.for_action(:destroy_keys, %{}, tenant: @acme)
             |> Ash.run_action()

    assert Enum.any?(read_errors(@acme, [:email]), &match?(%KeyDestroyed{}, &1))
  end

  # ── 16. backup / restore — the §27 property, end to end ────────────────────────────
  # The full parameterized version (OpenBao *and* Local) lives in
  # test/acceptance/backup_restore_test.exs. This is the compact restatement, so that
  # this checklist stands on its own.
  test "16. restoring a pre-erasure pg_dump brings back the rows but not the plaintext" do
    root = Path.join(System.tmp_dir!(), "ash_vault_dod_#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(root) end)
    # The provider refuses to start on a root it did not see initialised — that is
    # what stops an unmounted key volume from looking like a pristine key store.
    Local.init_root!(root)
    start_supervised!({Local, name: Local, root: root})

    AcceptanceVaultResolver.put(AshVault.Test.LocalVault)
    tenant = Ecto.UUID.generate()

    row =
      AcceptanceUser
      |> Ash.Changeset.for_create(
        :create,
        %{org_id: tenant, email: "restored@example.invalid", ssn: "424-24-2424"},
        tenant: tenant
      )
      |> Ash.create!()

    assert %{email: "restored@example.invalid"} =
             AcceptanceUser |> Ash.Query.load([:email]) |> Ash.read_one!(tenant: tenant)

    dump_path =
      Path.join(System.tmp_dir!(), "ash_vault_dod_#{System.unique_integer([:positive])}.sql")

    on_exit(fn -> File.rm_rf!(dump_path) end)

    dump = Backup.dump!(dump_path)
    assert dump =~ "COPY public.acceptance_users"
    assert dump =~ row.id
    refute dump =~ "restored@example.invalid"
    refute dump =~ "424-24-2424"

    :ok = AshVault.destroy_keys!(AshVault.Test.LocalVault, tenant)
    :ok = Backup.restore!(dump_path)

    assert [[1]] =
             raw("SELECT count(*) FROM acceptance_users WHERE org_id = $1", [uuid(tenant)])

    assert {:error, %Ash.Error.Invalid{errors: errors}} =
             AcceptanceUser |> Ash.Query.load([:email]) |> Ash.read(tenant: tenant)

    assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
    refute Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1))
  end

  # ── 17. mix ash_vault.backfill ── [anchor: item 17] ────────────────────────────────
  test "17. mix ash_vault.backfill encrypts an existing plaintext column" do
    org = Ecto.UUID.generate()

    for i <- 1..3 do
      LegacyUser
      |> Ash.Changeset.for_create(
        :create,
        %{org_id: org, legacy_email: "legacy#{i}@example.invalid"},
        tenant: org
      )
      |> Ash.create!()
    end

    # Before: the plaintext column is populated and nothing is encrypted yet.
    assert [[3]] = raw("SELECT count(*) FROM legacy_users WHERE encrypted_email IS NULL")

    # The engine underneath the task. This is the part that actually has to be correct.
    assert {:ok, %{done: 3}} = AshVault.Backfill.run(LegacyUser, :email, tenant: org)

    # Re-running is a no-op: only rows whose encrypted column IS NULL are selected.
    assert {:ok, %{done: 0}} = AshVault.Backfill.run(LegacyUser, :email, tenant: org)

    # After: every row carries an AshVault envelope...
    assert [[0]] = raw("SELECT count(*) FROM legacy_users WHERE encrypted_email IS NULL")

    for [blob] <- raw("SELECT encrypted_email FROM legacy_users") do
      assert <<"AV", 1::8, _::binary>> = blob
      refute String.contains?(blob, "example.invalid")
    end

    # ...and it decrypts, through the ordinary read path, back to the plaintext column.
    rows = Ash.read!(LegacyUser, tenant: org, authorize?: false, load: [:email])
    assert length(rows) == 3
    assert Enum.all?(rows, &(&1.email == &1.legacy_email))

    assert Enum.sort(Enum.map(rows, & &1.email)) == [
             "legacy1@example.invalid",
             "legacy2@example.invalid",
             "legacy3@example.invalid"
           ]
  end

  # ── 17 (continued). The operator-facing entry point for the same item. ─────────────
  #
  # This is a regression guard for a real defect found while writing this file: the task
  # used to crash before doing anything, on every invocation that passed neither
  # `--verify` nor `--dry-run`:
  #
  #     unless opts[:verify] or opts[:dry_run] do   # lib/mix/tasks/ash_vault.backfill.ex:101
  #
  # `OptionParser` leaves absent boolean switches as `nil`, and Elixir's `or` raises
  # `BadBooleanError` on a non-boolean left operand. It is now `if !… and !…` and passes.
  # Keep this test: it exercises the task entry point, not just `AshVault.Backfill`.
  test "17b. the mix ash_vault.backfill task runs" do
    org = Ecto.UUID.generate()

    LegacyUser
    |> Ash.Changeset.for_create(:create, %{org_id: org, legacy_email: "t@example.invalid"},
      tenant: org
    )
    |> Ash.create!()

    ExUnit.CaptureIO.capture_io(fn ->
      Mix.Tasks.AshVault.Backfill.run([to_string(LegacyUser), "email", "--tenant", org, "--yes"])
    end)

    assert [[0]] = raw("SELECT count(*) FROM legacy_users WHERE encrypted_email IS NULL")
  end

  # ── helpers ──────────────────────────────────────────────────────────────────────

  defp create!(attrs, tenant \\ @acme) do
    User
    |> Ash.Changeset.for_create(:create, Map.merge(%{org_id: tenant, name: "n"}, attrs),
      tenant: tenant,
      authorize?: false
    )
    |> Ash.create!()
  end

  defp read!(tenant, load) do
    User |> Ash.Query.load(load) |> Ash.read!(tenant: tenant, authorize?: false)
  end

  defp read_errors(tenant, load) do
    assert {:error, %Ash.Error.Invalid{errors: errors}} =
             User |> Ash.Query.load(load) |> Ash.read(tenant: tenant, authorize?: false)

    errors
  end

  defp raw(sql, params \\ []), do: Repo.query!(sql, params).rows

  defp blob_of(id) do
    [[blob]] = raw("SELECT encrypted_email FROM users WHERE id = $1", [uuid(id)])
    blob
  end

  defp columns(table, names) do
    ("SELECT column_name FROM information_schema.columns " <>
       "WHERE table_name = $1 AND column_name = ANY($2)")
    |> raw([table, names])
    |> List.flatten()
  end

  # Rewrite an envelope's key_version field in place, leaving everything else untouched.
  # V1 layout: "AV", version::8, cipher_id_len::8, cipher_id, key_version::32, ...
  defp with_key_version(<<"AV", 1::8, cid_len::8, rest::binary>>, version) do
    <<cipher_id::binary-size(^cid_len), _old::32-unsigned-big, tail::binary>> = rest
    <<"AV", 1::8, cid_len::8, cipher_id::binary, version::32-unsigned-big, tail::binary>>
  end

  defp uuid(string), do: Ecto.UUID.dump!(string)
end
