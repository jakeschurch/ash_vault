defmodule Mix.Tasks.Example.Demo do
  @shortdoc "Walk the whole AshVault story end to end, with narration."

  @moduledoc """
  The runnable demonstration. Eight steps, in order:

    1. two organizations, each with users and contacts
    2. a raw SQL read of the encrypted columns — ciphertext only
    3. the same rows through Ash — plaintext
    4. a field policy denying a field, and a policy denying key rotation
    5. rotate organization A's key; old rows keep their old key version
    6. register and sign in by an **encrypted** email address
    7. a `pg_dump` taken while A is healthy, then crypto-erase A
    8. restore that dump — A's rows come back, and still cannot be decrypted

  Step 8 is the reason the library exists. Everything before it is scaffolding.

      mix example.demo
      ASHVAULT_PROVIDER=local mix example.demo
  """

  use Mix.Task

  require Ash.Query

  alias AshVault.Envelope
  alias AshVault.Errors.KeyDestroyed
  alias Example.Accounts.AuthUser
  alias Example.Accounts.Contact
  alias Example.Accounts.Organization
  alias Example.Accounts.User
  alias Example.Backup
  alias Example.Repo

  @requirements ["app.start"]

  # An admin actor passes the field policy on `User.email` and the action policy on
  # `Organization`'s key lifecycle. A staff actor passes neither.
  @admin %{id: "admin", admin?: true}
  @staff %{id: "staff", admin?: false}

  # Distinctive needles. If any of these ever turns up in a pg_dump the demo must be
  # able to say so on the string alone, with no chance of a coincidental match against
  # base64 or hex noise.
  @a_email "ada@acme-needle.invalid"
  @a_phone "+1-555-0100-NEEDLE"
  @b_email "bob@beta-needle.invalid"
  @b_phone "+1-555-0200-NEEDLE"

  # Registered in BOTH organizations, deliberately: the same address under two tenants is
  # what shows the lookup token is per-scope.
  @auth_email "ada@acme-needle.invalid"

  @impl Mix.Task
  def run(_args) do
    Backup.available?() ||
      Mix.raise("""
      `docker exec <pg container> pg_dump` does not work, so step 7 cannot run.
      Set PGCONTAINER if your PostgreSQL container is not `foundrybox-postgres-1`.
      """)

    banner()

    {org_a, org_b} = step_1_seed()

    step_2_raw_sql(org_a, org_b)
    step_3_ash_read(org_a, org_b)
    step_4_policies(org_a)
    step_5_rotate(org_a, org_b)
    step_6_sign_in(org_a, org_b)
    dump_path = step_7_backup_and_erase(org_a, org_b)
    step_8_restore(dump_path, org_a, org_b)

    outro(org_a)
  end

  # ── 0 ────────────────────────────────────────────────────────────────────────────

  defp banner do
    provider = Example.Vault.key_provider()

    where =
      case provider do
        AshVault.KeyProviders.OpenBao ->
          cfg = AshVault.KeyProvider.config(AshVault.KeyProviders.OpenBao)
          "OpenBao transit at #{cfg[:address]} (mount #{cfg[:transit_mount]})"

        AshVault.KeyProviders.Local ->
          cfg = AshVault.KeyProvider.config(AshVault.KeyProviders.Local)
          "the filesystem, rooted at #{cfg[:root]}"

        other ->
          inspect(other)
      end

    say([
      "AshVault example",
      "",
      "  database      #{Application.get_env(:example, Repo)[:database]} (PostgreSQL)",
      "  key provider  #{inspect(provider)}",
      "  key material  #{where}",
      "",
      "The database and the key store are two different systems. That separation is",
      "the entire thesis: a backup of one cannot restore the other."
    ])
  end

  # ── 1 ────────────────────────────────────────────────────────────────────────────

  defp step_1_seed do
    step(1, "Two organizations, each with encrypted user and contact rows")

    # Fresh ids per run. OpenBao tombstones are permanent and outlive the database, so
    # a hardcoded organization id would be crypto-erased by the first run and every
    # later run would fail at the first write with KeyDestroyed.
    org_a = create_org!("Acme")
    org_b = create_org!("Beta")

    create_user!(org_a, "Ada", @a_email)
    create_user!(org_a, "Alan", "alan@acme-needle.invalid")
    create_contact!(org_a, "Acme support", @a_phone)

    create_user!(org_b, "Bob", @b_email)
    create_contact!(org_b, "Beta support", @b_phone)

    say([
      "  org A  #{org_a}  Acme   2 users, 1 contact",
      "  org B  #{org_b}  Beta   1 user,  1 contact",
      "",
      "Both resources are tenant-scoped, so all four encrypted values in org A are",
      "encrypted under ONE key: org A's. That is why key lifecycle lives on",
      "Organization and not on User — see Example.Accounts.Organization's moduledoc."
    ])

    {org_a, org_b}
  end

  # ── 2 ────────────────────────────────────────────────────────────────────────────

  defp step_2_raw_sql(org_a, org_b) do
    step(2, "Raw SQL, straight past Ash: what is actually on disk")

    rows =
      query!(
        "SELECT u.name, u.encrypted_email FROM users u WHERE u.org_id = $1 ORDER BY u.name",
        [uuid(org_a)]
      )

    say(["  SELECT name, encrypted_email FROM users WHERE org_id = '#{org_a}'", ""])

    for [name, blob] <- rows do
      {:ok, env} = Envelope.decode(blob)

      say([
        "    #{String.pad_trailing(name, 6)} #{byte_size(blob)} bytes  " <>
          "\\x#{Base.encode16(binary_part(blob, 0, 24), case: :lower)}...",
        "           decoded envelope: magic=AV v#{env.version} cipher=#{env.cipher} " <>
          "key_version=#{env.key_version} nonce=#{byte_size(env.nonce)}B tag=#{byte_size(env.tag)}B"
      ])
    end

    # There is no plaintext column to check: `encrypt :email` removes the `:email`
    # attribute from the resource entirely, so the migration never created one.
    columns =
      query!(
        "SELECT column_name, data_type FROM information_schema.columns " <>
          "WHERE table_name = 'users' ORDER BY ordinal_position",
        []
      )

    say([
      "",
      "  users columns: " <> Enum.map_join(columns, ", ", fn [c, t] -> "#{c} #{t}" end),
      "  There is no `email` column at all. AshVault replaces the plaintext attribute",
      "  with a private `encrypted_email bytea`, so no data layer can write plaintext."
    ])

    needles = [@a_email, @a_phone, @b_email, @b_phone]
    found = needles_in_database(needles)

    say([
      "",
      "  scanning every bytea column in users+contacts for the plaintext needles",
      "  #{inspect(needles)}",
      "  → #{if found == [], do: "not found. ciphertext only.", else: "LEAKED: #{inspect(found)}"}"
    ])

    _ = org_b
    :ok
  end

  # ── 3 ────────────────────────────────────────────────────────────────────────────

  defp step_3_ash_read(org_a, org_b) do
    step(3, "The same rows through Ash: plaintext, transparently")

    for {label, org} <- [{"org A", org_a}, {"org B", org_b}] do
      users = User |> Ash.read!(tenant: org, actor: @admin)
      contacts = Contact |> Ash.read!(tenant: org, actor: @admin)

      say([
        "  #{label}",
        "    users:    " <> Enum.map_join(users, ", ", &"#{&1.name} <#{&1.email}>"),
        "    contacts: " <> Enum.map_join(contacts, ", ", &"#{&1.label} #{&1.phone}")
      ])
    end

    say([
      "",
      "  `decrypt_by_default` loaded the decrypt calculations, so a plain Ash.read",
      "  returns plaintext. Note the reads are tenant-scoped: the tenant is both the",
      "  row filter (Ash multitenancy) and the key scope (AshVault)."
    ])
  end

  # ── 4 ────────────────────────────────────────────────────────────────────────────

  defp step_4_policies(org_a) do
    step(4, "Authorization and encryption composing, not competing")

    [ada | _] =
      User
      |> Ash.Query.filter(name == "Ada")
      |> Ash.read!(tenant: org_a, actor: @staff)
      |> List.wrap()

    say([
      "  a) field policy on User.email — read as a non-admin actor #{inspect(@staff)}",
      "       name  #{inspect(ada.name)}   (allowed)",
      "       email #{inspect(ada.email)}",
      "",
      "     The field policy applies to the *decrypt calculation*, because that is",
      "     what the encrypted attribute became. A denied field arrives as",
      "     %Ash.ForbiddenField{} and the decrypt calculation passes it straight",
      "     through — it never decrypts a value the actor may not see."
    ])

    [ada_admin | _] =
      User
      |> Ash.Query.filter(name == "Ada")
      |> Ash.read!(tenant: org_a, actor: @admin)
      |> List.wrap()

    say([
      "",
      "     the same row as the admin actor:",
      "       email #{inspect(ada_admin.email)}"
    ])

    denied =
      Organization
      |> Ash.ActionInput.for_action(:rotate_key, %{}, tenant: org_a, actor: @staff)
      |> Ash.run_action()

    say([
      "",
      "  b) action policy on Organization.rotate_key — as the non-admin actor",
      "       #{summarize_error(denied)}",
      "",
      "     `rotate_key` and `destroy_keys` are ordinary Ash generic actions, so they",
      "     are exactly as guarded as your policies make them. AshVault adds no",
      "     authorization of its own — crypto-erasure is not special-cased."
    ])
  end

  # ── 5 ────────────────────────────────────────────────────────────────────────────

  defp step_5_rotate(org_a, org_b) do
    step(5, "Rotate org A's key: new writes move, old rows do not")

    before = user_versions(org_a)
    ada_blob = blob_of(:users, "encrypted_email", org_a, "Ada")

    {:ok, new_version} =
      Organization
      |> Ash.ActionInput.for_action(:rotate_key, %{}, tenant: org_a, actor: @admin)
      |> Ash.run_action()

    create_user!(org_a, "Amy", "amy@acme-needle.invalid")

    say([
      "  before rotate, stored key_version per row (decoded from the bytea, never",
      "  inferred from \"decryption worked\"):",
      "    " <> inspect(before),
      "",
      "  Organization.rotate_key → {:ok, #{new_version}}",
      "  wrote a new user, Amy, afterwards",
      "",
      "  after rotate:",
      "    " <> inspect(user_versions(org_a)),
      "",
      "  Ada's stored bytes are byte-identical to before the rotation: " <>
        "#{blob_of(:users, "encrypted_email", org_a, "Ada") == ada_blob}",
      "  Ada's row still decrypts: " <>
        inspect(read_user_email(org_a, "Ada")),
      "",
      "  org A's contact still carries key_version " <>
        "#{contact_version(org_a)} (decoded from contacts.encrypted_phone) " <>
        "and still reads: " <>
        inspect(hd(Contact |> Ash.read!(tenant: org_a, actor: @admin)).phone),
      "  org B is a different scope, so it is untouched: " <>
        inspect(user_versions(org_b)),
      "",
      "  Rotation mints a new key version and leaves history intact. The envelope",
      "  carries the key version, so every old row says which key decrypts it."
    ])
  end

  # ── 6 ────────────────────────────────────────────────────────────────────────────

  defp step_6_sign_in(org_a, org_b) do
    step(6, "Register and sign in, by an email address that is encrypted at rest")

    say([
      "  `Example.Accounts.AuthUser` is `encrypt :email, searchable?: true, unique?: true,",
      "  normalize: :downcase_trim`. A password login has to FIND a row by email before it",
      "  can check anything, and `WHERE encrypted_email = $1` can never match — AES-GCM",
      "  draws a fresh nonce per write. The deterministic `email_lookup` token is what",
      "  makes the query possible.",
      "",
      "  Password hashing and verification are ash_authentication's own",
      "  `AshAuthentication.BcryptProvider`. Its `password` STRATEGY cannot be pointed at",
      "  an encrypted field — see Example.Accounts.AuthUser's moduledoc for the three",
      "  reasons and the deps/ citations — so the register and sign-in actions are written",
      "  out by hand and AshVault supplies the lookup.",
      ""
    ])

    {:ok, _ada} = register(org_a, @auth_email, "correct horse battery staple")
    {:ok, _bob} = register(org_b, @auth_email, "a different password entirely")

    columns =
      query!(
        "SELECT column_name, data_type FROM information_schema.columns " <>
          "WHERE table_name = 'auth_users' ORDER BY ordinal_position",
        []
      )

    [[token_a]] = query!("SELECT email_lookup FROM auth_users WHERE org_id = $1", [uuid(org_a)])
    [[token_b]] = query!("SELECT email_lookup FROM auth_users WHERE org_id = $1", [uuid(org_b)])

    say([
      "  a) what is on disk",
      "",
      "     auth_users columns: " <> Enum.map_join(columns, ", ", fn [c, t] -> "#{c} #{t}" end),
      "     Still no `email` column. One ciphertext column and one token column.",
      "",
      "     both organizations registered the SAME address, #{inspect(@auth_email)}:",
      "       org A token  \\x#{Base.encode16(token_a, case: :lower)}",
      "       org B token  \\x#{Base.encode16(token_b, case: :lower)}",
      "       identical?   #{token_a == token_b}",
      "",
      "     The token key is per-scope, so the same address is a different token in each",
      "     tenant. That is what keeps the equality leak inside one tenant instead of",
      "     across all of them — and it is why the unique index is per tenant:",
      "       #{index_definition("auth_users_email_lookup_unique_index")}"
    ])

    say([
      "",
      "  b) sign in",
      "",
      "     correct password, and the address typed the way a human types it:",
      "       sign_in(#{inspect("  ADA@Acme-Needle.INVALID  ")}) → " <>
        sign_in_summary(org_a, "  ADA@Acme-Needle.INVALID  ", "correct horse battery staple"),
      "       (`normalize: :downcase_trim` hashed the same bytes that were encrypted)",
      "",
      "     wrong password:",
      "       → " <> sign_in_summary(org_a, @auth_email, "hunter2"),
      "",
      "     an address nobody registered:",
      "       → " <> sign_in_summary(org_a, "nobody@acme-needle.invalid", "hunter2"),
      "",
      "     org B's password against org A's tenant — two different rows, two different",
      "     keys, no crossover:",
      "       → " <> sign_in_summary(org_a, @auth_email, "a different password entirely"),
      "",
      "     and with NO tenant at all:",
      "       → " <> no_tenant_sign_in_summary(),
      "",
      "     That last one is the important one. A tenant-less lookup that quietly returned",
      "     zero rows would read as \"no such user\" at a login form, and would look",
      "     perfectly healthy in review, in logs and in tests."
    ])

    [[id_before]] = query!("SELECT id FROM auth_users WHERE org_id = $1", [uuid(org_a)])

    duplicate = register(org_a, @auth_email, "another password")

    {:ok, upserted} =
      AuthUser
      |> Ash.Changeset.for_create(:register_or_update, %{
        org_id: org_a,
        email: "Ada@ACME-needle.invalid",
        password: "rotated in place"
      })
      |> Ash.create(tenant: org_a)

    [[id_after]] = query!("SELECT id FROM auth_users WHERE org_id = $1", [uuid(org_a)])

    say([
      "",
      "  c) uniqueness and upsert, both on the token",
      "",
      "     registering the same address twice: " <> summarize_error(duplicate),
      "       enforced by a real unique index on (org_id, email_lookup). A unique index on",
      "       encrypted_email would constrain nothing at all.",
      "",
      "     `upsert_identity: :email_lookup_unique` with a differently-cased address:",
      "       rows in org A:  #{length(query!("SELECT id FROM auth_users WHERE org_id = $1", [uuid(org_a)]))}",
      "       same row?       #{id_before == id_after} (#{Ecto.UUID.load!(id_after)})",
      "       returned id matches: #{Ecto.UUID.load!(id_after) == upserted.id}",
      "",
      "     and the new password took:",
      "       → " <> sign_in_summary(org_a, @auth_email, "rotated in place"),
      "       → " <> sign_in_summary(org_a, @auth_email, "correct horse battery staple")
    ])
  end

  # ── 6 ────────────────────────────────────────────────────────────────────────────

  defp step_7_backup_and_erase(org_a, org_b) do
    step(7, "Take a backup while org A is healthy, then crypto-erase org A")

    dump_path =
      Path.join(System.tmp_dir!(), "ash_vault_example_#{System.unique_integer([:positive])}.sql")

    dump = Backup.dump!(dump_path)

    # Positive controls first. "No plaintext in the dump" is a worthless claim about a
    # dump that is empty, schema-only, or of the wrong database.
    key_a = current_key!(org_a)
    key_b = current_key!(org_b)

    say([
      "  pg_dump (run inside the PostgreSQL container, written to a host file)",
      "    #{dump_path}  #{byte_size(dump)} bytes",
      "",
      "  positive controls — the rows really are in there:",
      "    contains \"COPY public.users\":    #{String.contains?(dump, "COPY public.users")}",
      "    contains \"COPY public.contacts\": #{String.contains?(dump, "COPY public.contacts")}",
      "    contains org A's id:             #{String.contains?(dump, org_a)}",
      "",
      "  and it contains neither plaintext nor key material:",
      "    any plaintext needle:            #{needles_in_dump(dump) != []}",
      "    org A's 32-byte key, any encoding: #{key_in_dump?(dump, key_a)}",
      "    org B's 32-byte key, any encoding: #{key_in_dump?(dump, key_b)}",
      "",
      "  This is the backup a leaked tarball, an old S3 object or a compliance",
      "  retention policy would be holding. Keep it in mind for step 8."
    ])

    {:ok, %AshVault.Erasure{scope: erased_scope, destroyed_at: erased_at}} =
      Organization
      |> Ash.ActionInput.for_action(:destroy_keys, %{}, tenant: org_a, actor: @admin)
      |> Ash.run_action()

    [[user_count]] = query!("SELECT count(*) FROM users WHERE org_id = $1", [uuid(org_a)])
    [[contact_count]] = query!("SELECT count(*) FROM contacts WHERE org_id = $1", [uuid(org_a)])

    say([
      "  Organization.destroy_keys on org A",
      "    → %AshVault.Erasure{scope: #{erased_scope}, destroyed_at: #{erased_at}}",
      "    every key version destroyed at once, and the scope tombstoned so it can",
      "    never mint a fresh v1 and quietly look like a brand-new tenant.",
      "",
      "  org A, after erasure:",
      "    rows still in PostgreSQL:  #{user_count} users, #{contact_count} contacts",
      "    User read:     #{read_summary(User, org_a)}",
      "    Contact read:  #{read_summary(Contact, org_a)}",
      "",
      "    Both resources fail, from one destroy on Organization. That is the payoff",
      "    of scoping the key to the tenant.",
      "",
      "  org B, untouched:",
      "    User read:     #{read_summary(User, org_b)}",
      "    Contact read:  #{read_summary(Contact, org_b)}"
    ])

    dump_path
  end

  # ── 7 ────────────────────────────────────────────────────────────────────────────

  defp step_8_restore(dump_path, org_a, org_b) do
    step(8, "Restore the pre-erasure backup. The data comes back. The key does not.")

    ada_before = blob_of(:users, "encrypted_email", org_a, "Ada")

    :ok = Backup.restore!(dump_path)

    [[user_count]] = query!("SELECT count(*) FROM users WHERE org_id = $1", [uuid(org_a)])
    ada_after = blob_of(:users, "encrypted_email", org_a, "Ada")

    say([
      "  DROP DATABASE ash_vault_example; CREATE DATABASE ash_vault_example;",
      "  psql -f #{Path.basename(dump_path)}",
      "",
      "  the rows are genuinely back:",
      "    org A users in PostgreSQL:       #{user_count}",
      "    Ada's ciphertext byte-identical: #{ada_after == ada_before}",
      "    its envelope header:             " <>
        "\\x#{Base.encode16(binary_part(ada_after, 0, 12), case: :lower)}... " <>
        "(magic AV, v1, key_version #{decoded_version(ada_after)})",
      "",
      "  and they are still unreadable:",
      "    User read:     #{read_summary(User, org_a)}",
      "    Contact read:  #{read_summary(Contact, org_a)}",
      "",
      "  org B rode the restore through unharmed:",
      "    User read:     #{read_summary(User, org_b)}"
    ])

    File.rm_rf!(dump_path)
  end

  defp outro(org_a) do
    say([
      "",
      String.duplicate("=", 78),
      "  THE POINT",
      String.duplicate("=", 78),
      "",
      "  A full pg_dump taken before the erasure was restored into a freshly created",
      "  database. Every byte of org A's ciphertext came back, bit for bit. It is",
      "  still permanently undecryptable, because the key was never in the dump —",
      "  it lived in #{inspect(Example.Vault.key_provider())}, a different system,",
      "  and `destroy_keys` destroyed it there and left a tombstone behind.",
      "",
      "  Restoring a database backup cannot undo a crypto-erasure. That is the whole",
      "  library.",
      "",
      "  (org A was #{org_a}; its key is gone for good. Re-run the demo — it mints",
      "   fresh organization ids every time, so it is repeatable.)",
      ""
    ])
  end

  # ── narration ───────────────────────────────────────────────────────────────────

  defp step(n, title) do
    IO.puts([
      "\n",
      String.duplicate("─", 78),
      "\nSTEP #{n} — #{title}\n",
      String.duplicate("─", 78)
    ])
  end

  defp say(lines), do: IO.puts(Enum.join(lines, "\n"))

  # ── data helpers ────────────────────────────────────────────────────────────────

  defp create_org!(name) do
    Organization
    |> Ash.Changeset.for_create(:create, %{name: name}, actor: @admin)
    |> Ash.create!()
    |> Map.fetch!(:id)
  end

  # The tenant passed here is the organization id as a string — the same value the
  # lifecycle actions on Organization are given. If the write path and the lifecycle
  # action normalized the tenant differently they would address different keys, and
  # step 6 would silently "pass" while erasing a key nobody ever wrote under.
  defp create_user!(org, name, email) do
    User
    |> Ash.Changeset.for_create(:create, %{org_id: org, name: name, email: email},
      tenant: org,
      actor: @admin
    )
    |> Ash.create!()
  end

  defp create_contact!(org, label, phone) do
    Contact
    |> Ash.Changeset.for_create(:create, %{org_id: org, label: label, phone: phone}, tenant: org)
    |> Ash.create!()
  end

  defp register(org, email, password) do
    AuthUser
    |> Ash.Changeset.for_create(:register, %{
      org_id: org,
      email: email,
      password: password,
      password_confirmation: password
    })
    |> Ash.create(tenant: org)
  end

  defp sign_in_summary(org, email, password) do
    AuthUser
    |> Ash.Query.for_read(:sign_in, %{email: email, password: password}, tenant: org)
    |> Ash.read_one(tenant: org)
    |> case do
      {:ok, nil} -> "refused (no matching user)"
      {:ok, user} -> "signed in as #{inspect(user.email)} (#{user.id})"
      {:error, error} -> "error — #{inspect(error.__struct__)}"
    end
  end

  # `AshVault.Preparations.FilterByLookup` adds the error to the query rather than
  # filtering on nothing, so `Ash.read_one/2` returns it like any other Ash error.
  defp no_tenant_sign_in_summary do
    AuthUser
    |> Ash.Query.for_read(:sign_in, %{email: @auth_email, password: "irrelevant"})
    |> Ash.read_one()
    |> case do
      {:ok, nil} ->
        "SILENTLY EMPTY (this would be a bug)"

      {:error, %Ash.Error.Invalid{errors: errors}} ->
        classes =
          errors |> Enum.map(&(&1.__struct__ |> Module.split() |> List.last())) |> Enum.uniq()

        "REFUSED — #{inspect(classes)}"

      other ->
        inspect(other)
    end
  end

  defp index_definition(name) do
    case query!("SELECT indexdef FROM pg_indexes WHERE indexname = $1", [name]) do
      [[definition]] -> definition
      _ -> "(not found)"
    end
  end

  defp read_user_email(org, name) do
    User
    |> Ash.Query.filter(name == ^name)
    |> Ash.read_one!(tenant: org, actor: @admin)
    |> Map.fetch!(:email)
  end

  # Reduce a tenant read to one line of narration: either the plaintext it returned or
  # the AshVault error class that stopped it.
  defp read_summary(resource, org) do
    case Ash.read(resource, tenant: org, actor: @admin) do
      {:ok, records} ->
        "ok — " <>
          Enum.map_join(records, ", ", fn record ->
            inspect(Map.get(record, :email) || Map.get(record, :phone))
          end)

      {:error, %Ash.Error.Invalid{errors: errors}} ->
        classes =
          errors |> Enum.map(&(&1.__struct__ |> Module.split() |> List.last())) |> Enum.uniq()

        destroyed? = Enum.any?(errors, &match?(%KeyDestroyed{}, &1))

        "REFUSED — #{inspect(classes)}" <>
          if destroyed?, do: " (AshVault.Errors.KeyDestroyed: the key is gone)", else: ""

      {:error, other} ->
        "error — #{inspect(other)}"
    end
  end

  defp summarize_error({:error, %Ash.Error.Forbidden{}}), do: "refused: Ash.Error.Forbidden"
  defp summarize_error({:error, error}), do: "refused: #{inspect(error.__struct__)}"
  defp summarize_error({:ok, value}), do: "ALLOWED (unexpected): #{inspect(value)}"

  defp user_versions(org) do
    "SELECT name, encrypted_email FROM users WHERE org_id = $1 ORDER BY name"
    |> query!([uuid(org)])
    |> Enum.map(fn [name, blob] -> {name, decoded_version(blob)} end)
  end

  defp decoded_version(blob) do
    {:ok, %{key_version: version}} = Envelope.decode(blob)
    version
  end

  defp contact_version(org) do
    [[blob]] = query!("SELECT encrypted_phone FROM contacts WHERE org_id = $1", [uuid(org)])
    decoded_version(blob)
  end

  defp blob_of(:users, column, org, name) do
    [[blob]] =
      query!("SELECT #{column} FROM users WHERE org_id = $1 AND name = $2", [uuid(org), name])

    blob
  end

  defp current_key!(org) do
    {:ok, %{key: key}} = Example.Vault.key_provider().current_key(org)
    key
  end

  defp needles_in_dump(dump) do
    Enum.filter([@a_email, @a_phone, @b_email, @b_phone], fn needle ->
      # A plaintext leak into a bytea column would only ever be visible hex-encoded.
      String.contains?(dump, needle) or
        String.contains?(dump, Base.encode16(needle, case: :lower))
    end)
  end

  defp key_in_dump?(dump, key) do
    String.contains?(dump, key) or String.contains?(dump, Base.encode16(key, case: :lower)) or
      String.contains?(dump, Base.encode64(key))
  end

  defp needles_in_database(needles) do
    blobs =
      query!("SELECT encrypted_email FROM users", []) ++
        query!("SELECT encrypted_phone FROM contacts", [])

    haystack = blobs |> Enum.map(fn [blob] -> blob end) |> Enum.join()

    Enum.filter(needles, &String.contains?(haystack, &1))
  end

  defp query!(sql, params), do: Repo.query!(sql, params).rows

  defp uuid(id), do: Ecto.UUID.dump!(id)
end
