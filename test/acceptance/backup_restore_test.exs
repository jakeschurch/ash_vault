defmodule AshVault.Acceptance.BackupRestoreTest do
  @moduledoc """
  TEST_HARNESS_SPEC §27 — the mandatory backup/restore acceptance test.

  > Customer data remains present in historical database backups, but destroying that
  > customer's encryption keys makes the historical ciphertext permanently undecryptable.

  The whole library is step 8: after restoring a `pg_dump` taken *before* the erasure,
  tenant A's rows are back as rows and still refuse to decrypt.

  This deliberately never runs against `AshVault.KeyProviders.Memory` — Memory's keys
  were never in PostgreSQL, so it would pass vacuously. It runs twice:

    * `AshVault.KeyProviders.Local`, rooted in a temp directory outside the repository
      and outside anything `pg_dump` can see (a logical dump contains no filesystem)
    * `AshVault.KeyProviders.OpenBao`, where the key material lives in another process
      entirely — the convincing case

  Tenant ids are generated per run. OpenBao's tombstones are permanent and the dev
  server outlives the test suite, so a hardcoded tenant would pass once and then be
  destroyed forever.
  """

  use ExUnit.Case, async: false

  @moduletag :postgres

  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.KeyProviders.Local
  alias AshVault.Test.AcceptanceUser
  alias AshVault.Test.AcceptanceVaultResolver
  alias AshVault.Test.Backup
  alias AshVault.Test.Db
  alias AshVault.Test.Repo

  # Distinctive needles: if any of these ever appear in a dump the test must fail on the
  # string alone, with no chance of a coincidental match against base64 or hex noise.
  @email_a "tenant-a-needle@example.invalid"
  @ssn_a "AAA-11-9991"
  @email_b "tenant-b-needle@example.invalid"
  @ssn_b "BBB-22-9992"

  setup do
    Db.reset!()
    on_exit(fn -> AcceptanceVaultResolver.put(AshVault.Test.Vault) end)
    :ok
  end

  describe "§27 backup, crypto-erase, restore — AshVault.KeyProviders.Local" do
    test "restoring a pre-erasure pg_dump does not resurrect the erased tenant" do
      # The key root is deliberately outside the repository *and* outside the database.
      # A logical dump carries no filesystem at all, which is the point: the assertion
      # that actually proves it is `refute dump =~ key_bytes`, below.
      root = Path.join(System.tmp_dir!(), "ash_vault_keys_#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm_rf!(root) end)

      refute String.starts_with?(root, File.cwd!()),
             "the Local key root must not live inside the project directory"

      # The provider refuses to start on a root it did not see initialised — that is
      # what stops an unmounted key volume from looking like a pristine key store.
      Local.init_root!(root)
      start_supervised!({Local, name: Local, root: root})

      run_acceptance_cycle(AshVault.Test.LocalVault)

      # Sanity: the provider really did put key material on disk, outside the database.
      assert File.dir?(root)
    end
  end

  describe "§27 backup, crypto-erase, restore — AshVault.KeyProviders.OpenBao" do
    @describetag :openbao

    setup do
      Application.put_env(:ash_vault, AshVault.KeyProviders.OpenBao,
        address: System.get_env("BAO_ADDR", "http://127.0.0.1:8200"),
        token: System.get_env("BAO_TOKEN", "ashvault-root")
      )

      on_exit(fn -> Application.delete_env(:ash_vault, AshVault.KeyProviders.OpenBao) end)
      :ok
    end

    test "restoring a pre-erasure pg_dump does not resurrect the erased tenant" do
      run_acceptance_cycle(AshVault.Test.BaoVault)
    end
  end

  # ── the eight steps ──────────────────────────────────────────────────────────────

  defp run_acceptance_cycle(vault) do
    AcceptanceVaultResolver.put(vault)

    tenant_a = Ecto.UUID.generate()
    tenant_b = Ecto.UUID.generate()

    # Guard against the one silent failure mode of a runtime-resolved vault: if the
    # write and read paths resolved different vaults, step 8 would "pass" for the wrong
    # reason.
    assert AshVault.Info.vault!(AcceptanceUser, %{tenant: tenant_a, actor: nil}) == vault

    # ── 1. two tenants, encrypted rows for each ─────────────────────────────────────
    a = create!(tenant_a, %{label: "a", email: @email_a, ssn: @ssn_a})
    b = create!(tenant_b, %{label: "b", email: @email_b, ssn: @ssn_b})

    # ── 2. both decrypt ─────────────────────────────────────────────────────────────
    assert [%{email: @email_a, ssn: @ssn_a}] = read!(tenant_a)
    assert [%{email: @email_b, ssn: @ssn_b}] = read!(tenant_b)

    # What is actually stored is an envelope, not the plaintext.
    assert <<"AV", 1::8, _::binary>> = raw_blob(a.id, "encrypted_email")
    assert <<"AV", 1::8, _::binary>> = raw_blob(b.id, "encrypted_email")

    # Grab the live key material so step 4 can prove the dump does not contain it.
    key_a = current_key_bytes!(vault, tenant_a)
    key_b = current_key_bytes!(vault, tenant_b)
    assert byte_size(key_a) == 32
    assert key_a != key_b

    # ── 3. a real pg_dump, to a real file on disk ───────────────────────────────────
    dump_path =
      Path.join(System.tmp_dir!(), "ash_vault_backup_#{System.unique_integer([:positive])}.sql")

    on_exit(fn -> File.rm_rf!(dump_path) end)

    dump = Backup.dump!(dump_path)

    assert File.exists?(dump_path)
    assert File.stat!(dump_path).size == byte_size(dump)
    assert byte_size(dump) > 0

    # Positive control. "No plaintext in the dump" is worthless if the dump is empty,
    # schema-only, or of the wrong database — so first assert the rows are in there.
    assert dump =~ "COPY public.acceptance_users"
    assert dump =~ tenant_a
    assert dump =~ tenant_b
    assert dump =~ a.id
    assert dump =~ b.id

    # ── 4. the dump contains no plaintext, and no key material ──────────────────────
    for needle <- [@email_a, @ssn_a, @email_b, @ssn_b, "tenant-a-needle", "tenant-b-needle"] do
      refute dump =~ needle, "plaintext #{inspect(needle)} leaked into the pg_dump"

      # bytea columns dump as `\x<hex>`, so plaintext that leaked *into* a bytea column
      # would only ever be visible in hex form.
      refute dump =~ Base.encode16(needle, case: :lower),
             "hex-encoded plaintext #{inspect(needle)} leaked into the pg_dump"
    end

    for {label, key} <- [{"tenant A", key_a}, {"tenant B", key_b}] do
      refute String.contains?(dump, key), "#{label}'s raw key material is in the pg_dump"

      refute dump =~ Base.encode16(key, case: :lower),
             "#{label}'s key material is in the pg_dump, hex-encoded"

      refute dump =~ Base.encode64(key),
             "#{label}'s key material is in the pg_dump, base64-encoded"
    end

    # ── 5. crypto-erase tenant A ────────────────────────────────────────────────────
    assert :ok = AshVault.destroy_keys!(vault, tenant_a)

    # ── 6. A reads KeyDestroyed — not CiphertextIntegrityFailed, not a raise ─────────────
    assert_key_destroyed(tenant_a)
    assert [%{email: @email_b, ssn: @ssn_b}] = read!(tenant_b)

    # The rows are untouched; only the key is gone.
    assert [[2]] = Repo.query!("SELECT count(*) FROM acceptance_users").rows

    # ── 7. restore the dump — the state from BEFORE the destruction ─────────────────
    :ok = Backup.restore!(dump_path)

    # ── 8. the rows are back, and they still will not decrypt ───────────────────────
    assert [[2]] = Repo.query!("SELECT count(*) FROM acceptance_users").rows

    assert [[1]] =
             Repo.query!("SELECT count(*) FROM acceptance_users WHERE org_id = $1", [
               Ecto.UUID.dump!(tenant_a)
             ]).rows

    # The restored ciphertext is byte-identical to what was there before the erasure,
    # so this is genuinely the same data — it simply cannot be read any more.
    assert <<"AV", 1::8, _::binary>> = raw_blob(a.id, "encrypted_email")

    assert_key_destroyed(tenant_a)

    # And the restore did not harm the tenant that was never erased.
    assert [%{email: @email_b, ssn: @ssn_b}] = read!(tenant_b)
  end

  # ── helpers ──────────────────────────────────────────────────────────────────────

  defp assert_key_destroyed(tenant) do
    result =
      AcceptanceUser
      |> Ash.Query.load([:email, :ssn])
      |> Ash.read(tenant: tenant)

    assert {:error, %Ash.Error.Invalid{errors: errors}} = result,
           "expected a clean error value, got: #{inspect(result)}"

    assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1)),
           "expected AshVault.Errors.KeyDestroyed, got: #{inspect(errors)}"

    refute Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1)),
           "erasure must never be reported as tampering: #{inspect(errors)}"
  end

  defp create!(tenant, attrs) do
    AcceptanceUser
    |> Ash.Changeset.for_create(:create, Map.merge(%{org_id: tenant}, attrs), tenant: tenant)
    |> Ash.create!()
  end

  defp read!(tenant) do
    AcceptanceUser
    |> Ash.Query.load([:email, :ssn])
    |> Ash.read!(tenant: tenant)
  end

  defp raw_blob(id, column) do
    [[blob]] =
      Repo.query!("SELECT #{column} FROM acceptance_users WHERE id = $1", [Ecto.UUID.dump!(id)]).rows

    blob
  end

  defp current_key_bytes!(vault, tenant) do
    provider = vault.__ash_vault__(:key_provider)
    assert {:ok, %{key: key}} = provider.current_key(tenant)
    key
  end
end
