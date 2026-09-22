# AshVault

Per-tenant encrypted attributes for [Ash](https://ash-hq.org) resources, with
cryptographic erasure.

AshVault replaces an attribute with an encrypted column plus a decrypt calculation, so
writes and reads look exactly like ordinary Ash while the database only ever holds
ciphertext. Keys live in an external provider — filesystem or OpenBao — addressed by a
*scope*, which is the Ash tenant by default.

## The motivating property

A customer asks to be deleted. You delete the rows. Six weeks later you restore last
month's backup for an unrelated reason, and they are back — not through carelessness, but
because a backup is supposed to contain the state of the database at that time, and that
state included their data. `DELETE` cannot reach backwards into a tarball. Encryption can,
if the keys live somewhere the restore does not: destroy that customer's key and every
copy of their ciphertext — in the live database, in every snapshot, WAL archive, logical
dump and stolen replica that already exists — becomes permanently undecryptable, while
every other customer's rows in the very same tables keep decrypting normally. That is the
one property AshVault is built around, and the reason the key provider records a
**tombstone** rather than merely deleting: a destroyed scope must never be silently
re-created by the next write.

## Example

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end

defmodule MyApp.Accounts.User do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault

    encrypt :email
    encrypt :ssn, encrypt_nil?: false

    decrypt_by_default [:email]
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :email, :string, public?: true
    attribute :ssn, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end
```

Write and read as usual:

```elixir
user =
  MyApp.Accounts.User
  |> Ash.Changeset.for_create(:create, %{org_id: org.id, email: "ada@example.com"},
    tenant: org.id
  )
  |> Ash.create!()

user.email
#=> "ada@example.com"
```

What is actually in the column:

```elixir
%{rows: [[blob]]} = MyApp.Repo.query!("SELECT encrypted_email FROM users LIMIT 1")

<<"AV", 1::8, _rest::binary>> = blob
String.contains?(blob, "ada@example.com")
#=> false
```

And erasure:

```elixir
:ok = AshVault.destroy_keys!(MyApp.Vault, org.id)

Ash.read(MyApp.Accounts.User, tenant: org.id)
#=> {:error, %Ash.Error.Invalid{errors: [%AshVault.Errors.KeyDestroyed{}]}}
```

The row is still there. It is unreadable, in the live database and in every backup, for
good.

## What it gives you

* **AES-256-GCM** with a fresh nonce per value, and a versioned self-describing envelope
  carrying the cipher id and the key version.
* **Ciphertext bound to `scope | resource | field`** through AEAD associated data, so a
  blob cannot be relocated between tenants, resources or columns — it fails
  authentication instead of silently decrypting into the wrong place.
* **Rotation without re-encryption.** The envelope names the key version that opens it, so
  rotating a scope's key is one API call and touches no rows.
* **Per-scope cryptographic erasure**, with tombstones that fail closed.
* **A distinguishable error taxonomy.** `KeyDestroyed`, `KeyNotFound`,
  `ProviderUnavailable`, `CiphertextIntegrityFailed`, `KeySizeMismatch` are different errors
  because the correct human response to each is different. An outage never looks like
  erasure; erasure never looks like tampering.
* **Operator tooling**: `mix ash_vault.backfill`, `.verify`, `.key_info`, `.rotate`,
  `.destroy_keys`, `.local.init`.
* **Pluggable everything** — key provider, cipher, envelope, scope, rotation policy — each
  a small behaviour with a documented contract and a shared test suite.

## Providers

| Provider | When to use it | Key store | Survives restart | Multi-node | Setup |
|---|---|---|---|---|---|
| `AshVault.KeyProviders.Memory` | tests, and only tests | process memory | **no** | no | add to your supervision tree |
| `AshVault.KeyProviders.Local` | single-node deployments, homelab, dev with persistence | files on disk, mode 0600 | yes | **no** | `mix ash_vault.local.init <root>` |
| `AshVault.KeyProviders.OpenBao` | production, multi-node | OpenBao/Vault transit | yes | yes | `AshVault.KeyProviders.OpenBao.setup/0` |

The requirement that decides this: **the key store must be a different system from the
database**, so a database restore cannot restore keys. `Local` satisfies it with a
directory on another volume, excluded from the database backup job. `Memory` cannot —
it forgets everything on restart, so in production it is not a key store, it is a
countdown to total data loss. `OpenBao` is the answer for anything with more than one
node, or anything where losing a disk should not lose every customer's data.

## Installation

```elixir
def deps do
  [
    {:ash_vault, "~> 0.1.0"}
  ]
end
```

```elixir
# .formatter.exs
[import_deps: [:ash, :ash_postgres, :ash_vault]]
```

Then follow [Getting started](documentation/tutorials/getting-started.md) — pick a
provider, define a vault, add `ash_vault` to a resource, and confirm the column holds
ciphertext.

## Documentation

**Tutorial**

* [Getting started](documentation/tutorials/getting-started.md)

**Topics**

* [Architecture](documentation/topics/architecture.md) — the five layers, the envelope, the AAD, `AshVault.Context`
* [Tenant-scoped encryption](documentation/topics/tenant-scoped-encryption.md) — how a tenant becomes a key
* [Rotation](documentation/topics/rotation.md) — rotation vs re-encryption vs erasure
* [Crypto-erasure](documentation/topics/crypto-erasure.md) — the guarantee, the tombstone, the checklist
* [Migrating from plaintext](documentation/topics/migrating-from-plaintext.md) — expand / backfill / cut over / contract
* [Searchable fields](documentation/topics/searchable-fields.md) — not in v1; the design and its disclosure tradeoff
* [Threat model](documentation/topics/threat-model.md) — including the non-goals
* [Operations](documentation/topics/operations.md) — providers, backups, mix tasks, every error

**How-to**

* [Writing a key provider](documentation/how-to/writing-a-key-provider.md)
* [Writing a cipher](documentation/how-to/writing-a-cipher.md)
* [Writing a scope](documentation/how-to/writing-a-scope.md)
* [Writing a rotation policy](documentation/how-to/writing-a-rotation-policy.md)

**Design decisions**

* [ADR 0001 — AshVault does not build on `Cloak.Vault`](docs/adr/0001-no-cloak-vault.md)

## What it does not do

Read [the threat model](documentation/topics/threat-model.md) before promising anyone
anything. In short, AshVault does not defend against a compromised application process
(plaintext is in BEAM memory whenever it is encrypted or decrypted), does not erase
plaintext that already escaped through logs, warehouses, CDC streams or integrations, does
not hide metadata or ciphertext length, and performs no authorization of its own —
`Ash.Policy.Authorizer` and field policies do that.

It also cannot filter or sort on an encrypted field: randomized AEAD ciphertext supports
neither, and the decrypt calculation is `filterable?: false, sortable?: false`. Searchable
fields (`searchable?`, `unique?`) are specified but **rejected at compile time** in v1.

## Development

```
mix deps.get
mix test              # no Docker required
mix test.all          # adds the :postgres and :openbao suites
mix docs
```

The `:postgres` and `:openbao` suites need a PostgreSQL on `localhost:5432` and an OpenBao
on `http://127.0.0.1:8200`; both are excluded by default so `mix test` is green without
them.

## License

See `LICENSE`.
