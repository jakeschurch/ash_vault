# Getting started

Zero to an encrypted attribute, ending with you looking at the ciphertext in your own
database.

By the end you will have: a key provider running, a vault, a resource with an encrypted
`:email`, a row you can read back as plaintext through Ash, and a `psql` query proving the
column holds an AshVault envelope and no trace of the email address.

Assumed: an existing Phoenix or Elixir app with Ash and `ash_postgres` already working.

## 1. Add the dependency

```elixir
# mix.exs
def deps do
  [
    {:ash, "~> 3.0"},
    {:ash_postgres, "~> 2.0"},
    {:ash_vault, "~> 0.1.0"}
  ]
end
```

```
mix deps.get
```

Add AshVault to your formatter so the DSL formats correctly:

```elixir
# .formatter.exs
[
  import_deps: [:ash, :ash_postgres, :ash_vault],
  ...
]
```

## 2. Pick a key provider

This is the one decision that matters, and the whole guarantee rests on it: **the key
store must be a different system from the database**, so that restoring a database backup
cannot restore the keys.

| Provider | Use it for |
|---|---|
| `AshVault.KeyProviders.Memory` | tests only — keys die with the process |
| `AshVault.KeyProviders.Local` | single-node deployments, homelab, dev with persistence |
| `AshVault.KeyProviders.OpenBao` | production, multi-node |

We will use `Local`: it persists across restarts (so your data survives an `iex` restart,
which `Memory` would not), it needs no extra infrastructure, and it makes the "keys live
somewhere else" requirement concrete — it is a directory you can point at.

Create the key root. This is an explicit, one-time operator step:

```
mix ash_vault.local.init priv/ash_vault_keys
```

```
Initialised AshVault key root: /home/you/my_app/priv/ash_vault_keys
  mode:     0700
  sentinel: .ash_vault_root

Back this directory up separately from the database, and exclude it from the
database backup job. See the AshVault.KeyProviders.Local moduledoc.
```

> #### `priv/` is fine for development and wrong for production {: .warning}
>
> In production the key root belongs on its own volume, excluded from the database backup
> job — `/var/lib/my_app/ash_vault_keys`, say. If the keys and the database ever land in
> the same tarball, crypto-erasure is defeated. Add `priv/ash_vault_keys/` to your
> `.gitignore` now, before you forget.

Configure it and start it:

```elixir
# config/runtime.exs
config :ash_vault, AshVault.KeyProviders.Local,
  root: System.get_env("ASH_VAULT_KEY_ROOT", "priv/ash_vault_keys")
```

```elixir
# lib/my_app/application.ex
def start(_type, _args) do
  children = [
    MyApp.Repo,
    AshVault.KeyProviders.Local,
    MyAppWeb.Endpoint
  ]

  Supervisor.start_link(children, strategy: :one_for_one, name: MyApp.Supervisor)
end
```

`AshVault.KeyProviders.Local` never creates its own key root; if the directory or its
`.ash_vault_root` sentinel is missing it refuses to start, which is what stops an unmounted
key volume from looking like a pristine, empty key store.

## 3. Define a vault

A vault bundles the key provider with a cipher, an envelope format, a scope and a rotation
policy. Only the provider is required:

```elixir
# lib/my_app/vault.ex
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end
```

The defaults are `AshVault.Ciphers.AES.GCM`, `AshVault.Envelope.V1`,
`AshVault.Scopes.AshTenant` and `AshVault.RotationPolicies.Manual` — AES-256-GCM,
per-tenant keys, rotate only when asked. That is the right starting point.

## 4. Add `ash_vault` to a resource

```elixir
# lib/my_app/accounts/user.ex
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault

    encrypt :email

    decrypt_by_default [:email]
  end

  postgres do
    table "users"
    repo MyApp.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :name, :string, public?: true
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*]

    update :update do
      primary? true
      require_atomic? false
    end
  end
end
```

Four things to notice:

* **`encrypt :email` replaces the attribute.** At compile time the `:email` attribute is
  *removed* and replaced by a private `encrypted_email` `:binary` attribute plus an
  `:email` calculation that decrypts. There is no plaintext column, so no data layer can
  write one. You still declare `attribute :email, :string` — that declaration is what
  tells AshVault the type, the constraints and the nullability to preserve.
* **`decrypt_by_default [:email]`** loads the decrypt calculation automatically. Without
  it you load `:email` explicitly, like any other calculation.
* **The default scope is the Ash tenant**, so this resource needs multitenancy — here,
  attribute multitenancy on `org_id`. Every read and write must pass a tenant. (If you are
  not multitenant, see the note at the end.)
* **`require_atomic? false` is not required** — `AshVault.Changes.Encrypt` implements
  `atomic/3` and both paths scrub the plaintext from the changeset. It is here because
  most resources have other non-atomic changes; drop it if yours does not.

## 5. Generate and run the migration

```
mix ash.codegen add_encrypted_users
mix ash.migrate
```

The generated migration creates `encrypted_email bytea` and no `email` column — the
attribute is gone by the time codegen sees the resource. Schema migrations like this need
no keys at all.

## 6. Write and read

```
iex -S mix
```

```elixir
org_id = Ecto.UUID.generate()

user =
  MyApp.Accounts.User
  |> Ash.Changeset.for_create(:create, %{org_id: org_id, name: "Ada", email: "ada@example.com"},
    tenant: org_id
  )
  |> Ash.create!()

user.email
#=> "ada@example.com"
```

The key was minted on that first write — version 1, created by `current_key/1`, with no
explicit setup step.

Read it back:

```elixir
[found] = Ash.read!(MyApp.Accounts.User, tenant: org_id)

found.email
#=> "ada@example.com"
```

`decrypt_by_default` loaded the calculation. Without it:

```elixir
MyApp.Accounts.User
|> Ash.Query.load([:email])
|> Ash.read!(tenant: org_id)
```

## 7. Verify the column holds ciphertext

This is the step that matters. Look at the raw bytes:

```elixir
%{rows: [[blob]]} = MyApp.Repo.query!("SELECT encrypted_email FROM users LIMIT 1")

# An AshVault envelope: "AV" magic, then the envelope version byte.
<<"AV", 1::8, _rest::binary>> = blob

# And no trace of the plaintext anywhere in it.
String.contains?(blob, "ada@example.com")
#=> false

String.contains?(blob, "example.com")
#=> false
```

There is no plaintext column at all:

```elixir
MyApp.Repo.query!("""
SELECT column_name FROM information_schema.columns
WHERE table_name = 'users' AND column_name = 'email'
""").rows
#=> []
```

Decode the envelope to see what it actually carries — everything needed to decrypt except
the key itself:

```elixir
AshVault.Envelope.decode(blob)
#=> {:ok,
#=>  %{
#=>    version: 1,
#=>    cipher: "aes_256_gcm_v1",
#=>    key_version: 1,
#=>    nonce: <<...12 bytes...>>,
#=>    tag: <<...16 bytes...>>,
#=>    ciphertext: <<...>>
#=>  }}
```

That `key_version: 1` is what makes rotation cheap: rotate the tenant's key and this row
keeps decrypting with version 1 while new writes use version 2.

And the key material is where you put it, not in the database:

```
$ ls priv/ash_vault_keys/
.ash_vault_root  <base64-of-the-tenant-id>

$ ls priv/ash_vault_keys/<base64-of-the-tenant-id>/
meta.json  v1.key
```

```elixir
AshVault.KeyProviders.Local.scope_dir(org_id)
#=> the directory name for that tenant
```

## 8. See what erasure does

The reason for all of this. Destroy the tenant's keys:

```elixir
:ok = AshVault.destroy_keys!(MyApp.Vault, org_id)
```

Now read:

```elixir
Ash.read(MyApp.Accounts.User, tenant: org_id)
#=> {:error, %Ash.Error.Invalid{errors: [%AshVault.Errors.KeyDestroyed{...}]}}
```

```
Encryption key for scope "<org_id>" (version 1) has been destroyed.

This data was cryptographically erased and cannot be recovered.
```

The row is still there. Its bytes are unchanged. Every backup you have taken still contains
it — and none of them can be read. That is the whole library.

Note what the error is **not**: it is not `CiphertextIntegrityFailed` (which would mean
tampering) and not `ProviderUnavailable` (which would mean retry). Destruction is checked
before any decryption is attempted, and the provider records a tombstone so the tenant can
never be silently re-minted — even if someone restores an old key directory over the top,
the tombstone sits beside the scope directory rather than inside it.

In production this is a mix task with real guardrails — it makes you type the scope back,
and `--yes` does not skip that:

```
mix ash_vault.destroy_keys MyApp.Accounts.Organization --tenant <org_id>
```

## Where to go next

* [Architecture](../topics/architecture.md) — what the five layers do and why the envelope
  carries a key version
* [Tenant-scoped encryption](../topics/tenant-scoped-encryption.md) — how the tenant
  becomes a key, and the scope-agreement rule the verifier enforces
* [Crypto-erasure](../topics/crypto-erasure.md) — the guarantee in detail, plus the
  operational checklist to run through before you rely on it
* [Threat model](../topics/threat-model.md) — read the non-goals before you promise anyone
  anything
* [Operations](../topics/operations.md) — provider setup, backups, and every error
* [Migrating from plaintext](../topics/migrating-from-plaintext.md) — if the column already
  has data in it

## Notes and gotchas

**If you are not multitenant**, use the global scope. Both the vault and the resource must
say so — the verifier requires the resource to restate a non-default scope:

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Local,
    scope: AshVault.Scopes.Global
end

ash_vault do
  vault MyApp.Vault
  scope :global
  encrypt :email
end
```

One key lineage for the whole application, so rotation and erasure are application-wide.

**You cannot filter or sort on an encrypted field.** The decrypt calculation is
`filterable?: false, sortable?: false`, because randomized AEAD ciphertext supports
neither. See [Searchable fields](../topics/searchable-fields.md).

**Every read and write needs a tenant**, including background jobs and mix tasks. Without
one you get `AshVault.Errors.MissingScope`:

```
Cannot encrypt MyApp.Accounts.User.email because no Ash tenant was present.

This resource uses tenant-scoped encryption.
Pass a tenant when executing the Ash action or configure another AshVault scope.
```

**Do not lose the key directory.** In this tutorial it is under `priv/`, which means a
`git clean -xfd` destroys every encrypted value you have written. That is the correct
behaviour — it is just cheaper to learn here than in production.
