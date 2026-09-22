# Operations

Everything an operator needs: which provider to run, how to set it up, what to back up,
what never to back up, the mix tasks, and how to read every error AshVault can produce.

## Choosing a provider

| Provider | Use it for | Key store | Survives restart | Multi-node |
|---|---|---|---|---|
| `AshVault.KeyProviders.Memory` | tests, a first look | process memory | **no** | no |
| `AshVault.KeyProviders.Local` | single-node deployments, homelab, dev with persistence | files on disk | yes | **no** |
| `AshVault.KeyProviders.OpenBao` | production, multi-node | OpenBao/Vault transit | yes | yes |

The requirement that actually decides this is: **the key store must be a different system
from the database**. Not a different schema, not another table — a different system, with
its own credentials, that a database restore cannot reach. `Local` satisfies that with a
directory on another volume; `Memory` cannot (it forgets everything on restart, so in
production it is not a key store, it is a countdown to total data loss).

### `Memory`

```elixir
# config/dev.exs and config/test.exs
config :my_app, start_memory_key_provider?: true

# lib/my_app/application.ex — a runtime flag, not Mix.env/0, because Mix is not
# available in a release.
children =
  [MyApp.Repo] ++
    if Application.get_env(:my_app, :start_memory_key_provider?, false) do
      [AshVault.KeyProviders.Memory]
    else
      []
    end
```

AshVault deliberately does not start it for you. In tests, start a uniquely-named instance
per test where you can:

```elixir
start_supervised!({AshVault.KeyProviders.Memory, name: Memory})
```

(the `AshVault.KeyProvider` callbacks take no server name, so a vault always talks to the
default-named instance — hence `name: Memory` in tests that go through a vault).

### `Local`

One-time operator setup, with the key volume **mounted**:

```
mix ash_vault.local.init /var/lib/my_app/ash_vault_keys
```

```
Initialised AshVault key root: /var/lib/my_app/ash_vault_keys
  mode:     0700
  sentinel: .ash_vault_root

Back this directory up separately from the database, and exclude it from the
database backup job. See the AshVault.KeyProviders.Local moduledoc.
```

Then:

```elixir
# config/runtime.exs
config :my_app, AshVault.KeyProviders.Local,
  root: "/var/lib/my_app/ash_vault_keys",
  key_bytes: 32

# lib/my_app/application.ex
children = [MyApp.Repo] ++ MyApp.Vault.child_specs()

# a deploy step — `init_root!/1` on the configured root, idempotent
:ok = MyApp.Vault.setup()
```

The provider **never creates its own key root**, and refuses to start without the
`.ash_vault_root` sentinel:

```
AshVault.KeyProviders.Local key root /var/lib/my_app/ash_vault_keys exists but holds no
.ash_vault_root sentinel, so it is either uninitialised or not the volume you think it is.

AshVault.KeyProviders.Local never creates its own key root. If it did, a key volume that
failed to mount would be silently replaced by an empty directory on the underlying
filesystem: no tombstones, no key material, and a fresh version 1 minted for every
tenant that was ever crypto-erased.

Initialise the root once, explicitly, as the operator:

    mix ash_vault.local.init /var/lib/my_app/ash_vault_keys
```

> #### Do not run `ash_vault.local.init` to make a startup error go away {: .error}
>
> If the provider refuses to start on a root you *know* was initialised, the sentinel is
> missing because the **volume** is missing. Running the task then creates a second, empty
> key store over the top of the mount point and resurrects every destroyed tenant. Check
> the mount first. That refusal is the safety mechanism, not an inconvenience.

`mix ash_vault.local.init --force` overrides the "non-empty directory with no sentinel"
refusal. You want that approximately never.

On-disk layout, so you can find things:

```
<root>/
  .ash_vault_root         # sentinel
  <scope_dir>/            # Base.url_encode64(scope, padding: false)
    meta.json             # {"current": 2, "versions": {"1": "...", "2": "..."}}
    v1.key                # raw key bytes, mode 0600
    v2.key
  <scope_dir>.tombstone   # presence == destroyed; sits BESIDE the directory
```

`AshVault.KeyProviders.Local.scope_dir/1` maps a tenant to its directory:

```elixir
iex> AshVault.KeyProviders.Local.scope_dir("acme")
"YWNtZQ"
```

The provider logs loudly (and starts anyway) if the root is group- or world-accessible:

```
AshVault.KeyProviders.Local key root /var/lib/my_app/keys has mode 0755, which is
group- or world-accessible.

Key material is readable by other users on this machine. Run:

    chmod 0700 /var/lib/my_app/keys

Starting anyway.
```

`Local` is **single-node**. Two nodes sharing one NFS or SMB mount will race on
`meta.json` and can mint conflicting versions. Use OpenBao.

### `OpenBao`

```elixir
# config/runtime.exs
config :my_app, AshVault.KeyProviders.OpenBao,
  address: System.fetch_env!("BAO_ADDR"),
  token: {:system, "BAO_TOKEN"},
  transit_mount: "transit",
  kv_mount: "ashvault",
  key_type: "aes256-gcm96",
  receive_timeout: 5_000,
  max_retries: 2
```

`:token` accepts a literal binary, `{:system, "VAR"}`, or a zero-arity function. The
provider is stateless — there is nothing to add to your supervision tree.

One-time operator setup, which mounts the KV-v2 engine that holds tombstones:

```elixir
:ok = MyApp.Vault.setup()     # or AshVault.KeyProviders.OpenBao.setup()
```

> #### A `mix` task does not start your application {: .warning}
>
> `OpenBao` speaks HTTP through `req`, whose `Finch` pool is started by the `:req`
> application. A `mix` task with `@requirements ["app.config"]` configures the
> application without starting it, and a release command may not have started it either.
>
> Call `Application.ensure_all_started(:req)` first. If you forget, AshVault says so
> precisely — `%AshVault.Errors.ProviderUnavailable{reason: {:not_started, :req}}`, whose
> message states that this is **not** an outage, that the server was never contacted, and
> what to add where. It is deliberately not reported as a transport failure, which is
> what an unreachable server looks like.

or equivalently, outside the app:

```
bao secrets enable -path=ashvault -version=2 kv
bao secrets enable transit
```

> #### The KV mount is never created on a read path {: .error}
>
> A missing KV mount answers `404 "no handler for route ..."` — status-identical to "no
> tombstone here". Mounting it and retrying would find a freshly created, empty store and
> report every destroyed scope as intact. The provider therefore reports a missing mount
> as `ProviderUnavailable` and stops. Mounting belongs in `setup/0`, run once, by you.

The app's token needs transit read/create/rotate/delete **and** the
`transit/export/encryption-key/*` capability, plus read/write on `ashvault/data/tombstones/*`.
Nothing else in your infrastructure should hold the export capability — it is the ability
to read raw key material.

Find a tenant's transit key name:

```elixir
iex> AshVault.KeyProviders.OpenBao.key_name("acme")
"ashvault_YWNtZQ"
```

Semantics worth knowing:

* `destroy/1` returns `:ok` only when the transit key is **confirmed absent** by a fresh
  read *and* the tombstone write succeeded. It never infers "there was nothing to delete"
  from an error message.
* `rotate/1` on a scope with no key mints version 1 and returns `{:ok, 1}`.
* A wrong or expired token yields `403 permission denied` on every endpoint, which is
  always `ProviderUnavailable` — never `:destroyed`.

> #### The token can reach your APM through Finch telemetry {: .warning}
>
> AshVault never logs the token, never puts it in an error struct, and never puts it in an
> exception message. But the token is sent as the `x-vault-token` header, so it sits in the
> `Req.Request` and `Finch.Request` structs for the life of the call. `Req`'s `Inspect`
> redacts only `authorization`, and Finch's `[:finch, :request, :start | :stop | :exception]`
> telemetry metadata carries request headers verbatim. **If you attach handlers to those
> events, filter `x-vault-token` out of the metadata yourself.** Nothing inside AshVault
> can do it for you.

## What to back up, and what never to back up

**Back up the key store. Separately. Deliberately. With its own retention policy.**

**Never let the key store and the database land in the same backup, tarball, snapshot or
volume clone.** If one restore brings back both, crypto-erasure is defeated and the
library's central promise is void. For `Local` this means the key root is excluded from the
database backup job *and* is not on a volume you snapshot with the database. For OpenBao it
is automatic — the keys were never in PostgreSQL.

This is a real, sharp tradeoff with no free answer:

* Keeping key backups makes erasure harder. Every retained copy of the key store can
  resurrect a destroyed subject, so your key-backup retention window is the real lifetime
  of a "destroyed" key.
* Keeping no key backups makes data loss easy. Losing the key store destroys every
  encrypted value in the database, permanently, with no recovery path.

Decide which risk you are underwriting, write it down, and test the restore. Then test the
*other* restore: database back, keys not — and confirm a destroyed scope stays destroyed.
That is what `test/acceptance/backup_restore_test.exs` does, and it is the check that
proves the deployment, not just the library.

Also worth knowing: `Local` fsyncs every key file and every `meta.json` before renaming it
into place, but OTP offers no way to fsync a *directory* (`:file.open/2` on one returns
`{:error, :eisdir}`), so directory-entry durability is left to the filesystem's own
ordering. And overwrite-before-unlink guarantees nothing on CoW or log-structured media —
see [Crypto-erasure](crypto-erasure.md).

## The mix tasks

All of them require the app runtime and a reachable key provider, check the provider before
doing anything, exit non-zero on failure, and print one `key=value` line per unit of
progress with a human summary last.

Shared flags: `--tenant TENANT`, `--all-tenants` (a string naming a zero-arity function,
such as `MyApp.Accounts.list_tenant_ids` plus `/0`, that returns a list), `--domain MODULE` (inferred from `:ash_domains` when omitted), `--yes`. Pass
`--tenant` **or** `--all-tenants`, never both; pass neither for a `scope :global` resource.

| Task | Purpose | Destructive |
|---|---|---|
| `mix ash_vault.local.init` | create and initialise a `Local` key root | no |
| `mix ash_vault.key_info` | show key name, version, timestamps, tombstone state | no |
| `mix ash_vault.rotate` | mint a new key version | no |
| `mix ash_vault.backfill` | encrypt an existing plaintext column, online | no |
| `mix ash_vault.verify` | decrypt a sample and compare to the plaintext column | no |
| `mix ash_vault.destroy_keys` | cryptographic erasure | **YES — irreversible** |

### `mix ash_vault.key_info`

```
mix ash_vault.key_info MyApp.Accounts.Organization --tenant acme
```

```
ash_vault.key_info=scope resource=MyApp.Accounts.Organization tenant=acme scope=acme \
  vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao key_name=ashvault_YWNtZQ \
  status=active version=3 created_at=2026-02-01T10:12:00Z versions=1,2,3
MyApp.Vault: scope acme is active at key version 3 (3 version(s) retained).
```

`status` is `active`, `not_minted` or `destroyed`. It is read-only in the strongest sense:
it **never mints key material**. `current_key/1` mints version 1 on first use, so an unused
scope is probed with `get_key/2` first and reported `not_minted` without creating anything.
A destroyed scope exits 0 — a tombstone is a legitimate answer, not a failure.

### `mix ash_vault.rotate`

See [Rotation](rotation.md). Not destructive; old ciphertext keeps decrypting.

### `mix ash_vault.destroy_keys`

See [Crypto-erasure](crypto-erasure.md). Requires typing the scope back; `--yes` does not
skip that and there is no `--force`.

### `mix ash_vault.backfill` and `mix ash_vault.verify`

See [Migrating from plaintext](migrating-from-plaintext.md).

## The error taxonomy

Eleven errors. Every one of them is a Splode error with `class: :invalid`, so Ash wraps
them correctly and they arrive from `Ash.read/2` and `Ash.create/2` as ordinary Ash errors
rather than 500s. The whole point of having eleven rather than one is that the response
differs.

| Error | What it means | First response |
|---|---|---|
| `KeyDestroyed` | the key was crypto-erased; the data is gone by design | close the ticket |
| `KeyNotFound` | no key and no tombstone for this scope/version | investigate the key store |
| `ProviderUnavailable` | the key backend could not be reached | retry, then page |
| `CiphertextIntegrityFailed` | **ciphertext integrity, not access control.** The stored bytes failed their AEAD tag check: modified, or read under a different key/tenant/resource/field. Nothing to do with actors, policies or `AshAuthentication` — AshVault authorizes nothing | treat as tampering unless a deploy explains it |
| `KeySizeMismatch` | the provider's key size disagrees with the cipher | fix the config; retrying cannot help |
| `MissingScope` | no tenant reached a tenant-scoped field | pass a tenant |
| `InvalidScope` | a custom scope module returned a non-binary | fix the scope module |
| `InvalidCiphertext` | the column is not an AshVault envelope | check the column and the backfill |
| `UnsupportedEnvelope` | the envelope version is newer than this build | deploy a newer AshVault |
| `UnsupportedCipher` | the envelope names an unregistered cipher | register it |
| `SerializationFailed` | the value does not fit the attribute's type | fix the value or the type |

### `AshVault.Errors.KeyDestroyed` — the data is gone, by design

```
Encryption key for scope "acme" (version 1) has been destroyed.

This data was cryptographically erased and cannot be recovered.
```

**Meaning:** someone ran a crypto-erasure for this scope. The provider's tombstone is
doing its job.

**Do:** close the ticket. Confirm against your deletion runbook that this scope was meant
to be erased. If it was not, you have an incident — but not a recoverable one; the data is
unreadable and no restore of the *database* will change that.

**Do not** interpret this as corruption or as an attack. Destruction is checked *before*
any decryption is attempted, so this never means "the bytes are wrong".

### `AshVault.Errors.KeyNotFound` — investigate

```
No encryption key found for scope "acme" (version 2).
```

**Meaning:** the provider has no such key **and no tombstone**. This is not erasure and not
an outage.

**Do:** check you are asking with the right scope key — a changed tenant identifier, a
custom `to_scope_key/2`, a `--tenant` typo. Then check the store itself: a deleted key
file, a `meta.json` referencing a version whose key material is gone, a restored key store
older than the rows. `mix ash_vault.key_info` tells you what the provider thinks exists.

### `AshVault.Errors.ProviderUnavailable` — retry, then page

```
Key provider AshVault.KeyProviders.OpenBao is unavailable: %Req.TransportError{reason: :econnrefused}.
```

**Meaning:** transport or backend failure. **This is the only retryable error in the list.**

**Do:** retry. If it persists: check the key store is up and reachable, the token is valid
and unexpired (a `403` shows up here, as `reason: :forbidden`), the KV mount exists for
OpenBao, the volume is mounted for `Local`. It also covers *corrupt or unreadable* state —
a truncated `meta.json`, an unreadable tombstone — which is deliberate: a tombstone read
that cannot complete is never answered with "not destroyed".

**Do not** conclude anything about erasure from this. An outage must never look like
erasure, and erasure must never look like an outage.

### `AshVault.Errors.CiphertextIntegrityFailed` — the bytes do not verify

```
Ciphertext for MyApp.Accounts.User.email failed its integrity check (key version 1).

The stored bytes were modified, were encrypted for a different tenant, resource or
field, or were encrypted with a different key.

This is not an authorization error. AshVault performs no authorization; if this
operation reached the crypto layer, Ash had already authorized it.
```

**Meaning:** the AEAD tag did not verify. This is *ciphertext integrity*, not access
control: the "authentication" in AEAD is the bytes authenticating themselves, and the
error is unrelated to `AshAuthentication`, `Ash.Policy.Authorizer` or the actor. Three
realistic causes, in order of likelihood:

1. **Different associated data.** The ciphertext is being read under a different scope,
   resource or field than it was written under. A relocated blob (which is the attack this
   catches), a renamed resource module, or a changed scope key.
2. **The wrong key.** Usually a key store restored from a different point in time, or two
   environments pointed at each other.
3. **Actual tampering.** Someone with database write access modified the column.

**Do:** check for a recent module rename or scope-key change first — those are the boring
answers. Then check which key store the app is pointed at. Only then treat it as
tampering — but if the value was not touched by a deploy, treat it as tampering, because
that is exactly what this error is for.

### `AshVault.Errors.KeySizeMismatch` — fix the config; retrying cannot help

```
Key size mismatch: AshVault.Ciphers.AES.GCM requires 32-byte keys, but
AshVault.KeyProviders.Local supplied 16 bytes.

This is a configuration fault, not tampering and not an outage. Retrying will not
help. Check the provider's `:key_bytes` (or OpenBao's `:key_type`) against the
vault's `:cipher`.
```

**Meaning:** a `key_bytes:` disagreeing with the cipher, an OpenBao `key_type:
aes128-gcm96` under a 256-bit cipher, or a truncated key file.

**Do:** fix the configuration. It is deliberately neither `CiphertextIntegrityFailed` (which
would tell you your data was tampered with, for a typo) nor `ProviderUnavailable` (which
would have you retry a permanent misconfiguration forever).

`AshVault.Vault.verify_key_sizes!/2` catches the statically-determinable cases at compile
time, with:

```
MyApp.Vault is misconfigured: its key provider and cipher disagree on key size.

  MyApp.KeyProvider.key_bytes() == 16
  AshVault.Ciphers.AES.GCM.key_bytes()   == 32

Every encryption would fail with AshVault.Errors.KeySizeMismatch.
```

It cannot catch a provider whose size depends on runtime config, which is why the runtime
error exists.

### `AshVault.Errors.MissingScope` — pass a tenant

```
Cannot encrypt MyApp.Accounts.User.email because no Ash tenant was present.

This resource uses tenant-scoped encryption.
Pass a tenant when executing the Ash action or configure another AshVault scope.
```

**Meaning:** the scope could not be resolved. Almost always a background job, migration or
mix task running without a tenant.

**Do:** pass `tenant:` to the Ash call, or `--tenant` / `--all-tenants` to the task. The
message's verb tracks the operation, so a read says "Cannot decrypt". A **different**
message, naming `:unsupported_tenant_shape`, means a tenant *was* passed in a shape the
scope module cannot reduce to a stable key — see
[Tenant-scoped encryption](tenant-scoped-encryption.md).

### `AshVault.Errors.InvalidScope` — a custom scope module is wrong

```
MyApp.Scopes.Custom.resolve!/1 returned a 2-tuple, which is not a binary.

AshVault scope keys must be binaries: they name key material in the provider and are
bound into every ciphertext's associated data, so they have to be stable across
processes, releases and OTP upgrades.
```

**Do:** fix the scope module. Only reachable with a custom `AshVault.Scope`.

The returned term is **described, not printed** (`AshVault.Scope.describe/1`): a scope
term is usually a tenant, and a loaded tenant record is full of customer PII that has no
business in an error this one ends up in a log and an APM trace. The shape is the whole
diagnosis; read the offending value in your own scope module, under a debugger, against
data you are allowed to see.

### `AshVault.Errors.InvalidCiphertext` — the column is not an AshVault envelope

```
Value is not a valid AshVault envelope: :bad_magic.
```

`:reason` is `:empty`, `:bad_magic`, `:not_a_binary`, or a decode-specific term.

**Meaning:** the stored bytes are not an envelope at all. Usually a column that was never
backfilled, a column written by something other than AshVault, or a value mangled in
transit (a `bytea` that went through a text round trip).

**Do:** look at the raw bytes. A real envelope starts with `"AV"` followed by a version
byte.

### `AshVault.Errors.UnsupportedEnvelope` — this build is too old

```
Unsupported AshVault envelope version: 2.
```

**Meaning:** the magic was right but the version byte is one this build cannot parse.
Deploying an older release over a newer one that wrote a new envelope version. The same
error, carrying `layer: :plaintext`, means the *plaintext* format version (`"AVP"`) was
unrecognised.

**Do:** deploy the build that can read it.

### `AshVault.Errors.UnsupportedCipher` — register it

```
Unsupported cipher: "chacha20_poly1305_v1".

Register it under `config :ash_vault, :ciphers, %{...}` if this build should support it.
```

**Do:** add it back to the registry. Removing a cipher from the registry while rows still
name it is how this happens. See [Writing a cipher](../how-to/writing-a-cipher.md).

### `AshVault.Errors.SerializationFailed` — the value does not fit the type

```
Could not serialize MyApp.Accounts.User.email (type MyApp.Types.Email) for encryption.

{:dump_to_embedded, {:error, [message: {:redacted, :binary}, value: {:redacted, :binary}]}}

The reason above is redacted: `{:redacted, _}` stands where a type-controlled value
was dropped, because that value is the plaintext this error exists to protect.
```

**Meaning:** `Ash.Type.dump_to_embedded/3` (or `cast_from_embedded/3` on the way back)
rejected the value. Not a crypto problem at all.

**Why it is redacted:** the reason is the type's own return value, and the `Ash.Type`
contract lets a type return `{:error, message: ..., value: value}` — where `value` is the
plaintext AshVault was about to encrypt. A custom type that does so would put plaintext
into an `Ash.Error` that gets logged, rendered and shipped to APM, so
`AshVault.Errors.SerializationFailed` rewrites `:reason` at construction: the shape and
the keys survive, and every leaf that is not an atom or an integer becomes
`{:redacted, kind}`. Built-in Ash types return `:error` or `{:error, index: 0}` and are
therefore unaffected — what you see above only happens with a custom type.

**Do:** fix the value or the type. The error still names the resource, the field and the
**type module**, which is where the real message lives — run that type's
`dump_to_embedded/2` against a value you are allowed to look at. On the *read* side this
can also mean the stored term no longer matches the current type; a type change on an
existing encrypted column is a data migration.

## Telemetry and the compliance audit log

AshVault emits `:telemetry` events around every encrypt, every decrypt, and every key
rotation and erasure. There is no `on_decrypt` callback: an audit log, a metric, a trace
span and a debug log all want the same fact, and a callback can only serve one of them.

`AshVault.Telemetry` is the reference for the event names, the measurements and every
metadata key. The short version:

| Prefix | Emitted around | Notable metadata |
|---|---|---|
| `[:ash_vault, :encrypt]` | one field of one record, on write | `:resource`, `:field` |
| `[:ash_vault, :decrypt]` | one field of one record, on read | `:resource`, `:field`, `:vault` |
| `[:ash_vault, :key, :rotate]` | a scope's key is rotated | `:scope`, `:scope_fingerprint`, `:key_version` |
| `[:ash_vault, :key, :destroy]` | **a scope is crypto-erased** | `:scope`, `:scope_fingerprint` |

Each prefix is a `:telemetry.span/3`, so it has `:start`, `:stop` and `:exception` under
it. Every event also carries `:actor_type` and `:actor_id`, and every `:stop` carries
`:result` (`:ok` or `:error`) plus, on failure, `:error` — the error **module**.

Three things to internalise before you write a handler:

* **Watch `:stop`, not `:exception`.** `AshVault.decrypt_value/5` rescues and returns its
  errors, so a read of a crypto-erased tenant is a `:stop` with
  `result: :error, error: AshVault.Errors.KeyDestroyed`. A handler attached only to
  `:exception` sees none of it.
* **`[:ash_vault, :key, :destroy]` is the compliance-critical one.** It is the record that
  an erasure request was actually executed, and the only one whose *absence* is a finding.
* **Nothing in the metadata is a secret, and it is your job to keep it that way.** There is
  no plaintext, no ciphertext, no key material and no actor struct in these events — only
  an `:actor_id`. Do not add any in your handler. (The single exception is the
  `:exception` event, where `:telemetry.span/3`'s own contract puts the raised error struct
  in `:reason`; see `AshVault.Telemetry`.)

### A worked handler

Attach once, at application start, after the repo is up:

```elixir
defmodule MyApp.VaultAudit do
  @moduledoc "Writes an immutable audit row for every AshVault key-lifecycle and decrypt event."

  require Logger

  @events [
    [:ash_vault, :decrypt, :stop],
    [:ash_vault, :key, :rotate, :stop],
    [:ash_vault, :key, :destroy, :stop],
    [:ash_vault, :key, :destroy, :exception]
  ]

  def attach do
    :telemetry.attach_many("my-app-vault-audit", @events, &__MODULE__.handle/4, nil)
  end

  # Telemetry handlers run in the caller's process. Keep this cheap and total: a raise
  # here detaches the handler for the life of the node, and silently stops your audit log.
  def handle(event, measurements, metadata, _config) do
    entry = %{
      # UTC, always. An audit row in server-local time is not an audit row.
      occurred_at: DateTime.utc_now(),
      event: Enum.join(event, "."),
      # Who.
      actor_type: inspect(metadata[:actor_type]),
      actor_id: to_string(metadata[:actor_id] || "system"),
      # What.
      resource: inspect(metadata[:resource]),
      field: to_string(metadata[:field] || ""),
      scope: metadata[:scope],
      key_version: metadata[:key_version],
      # Outcome.
      result: metadata[:result] || :exception,
      error: inspect(metadata[:error]),
      duration_us: System.convert_time_unit(measurements[:duration] || 0, :native, :microsecond)
    }

    MyApp.Repo.insert_all("vault_audit_log", [entry])
  rescue
    error ->
      # Never let the audit log take down the operation it is auditing — but never let it
      # fail silently either.
      Logger.error("vault audit write failed: #{Exception.message(error)}")
  end
end
```

Request-scoped facts an audit regime often also asks for — the client IP, a request id, a
stated purpose for the access — are not in the metadata, because AshVault is not in the
request and cannot invent them. Telemetry handlers run **in the calling process**, so read
them from where your web layer already put them:

```elixir
metadata = Logger.metadata()

entry = Map.merge(entry, %{
  request_id: metadata[:request_id],
  remote_ip: metadata[:remote_ip]
})
```

(and set them there once, in a plug, rather than threading them through Ash).

### The key-lifecycle events carry the raw tenant id

`metadata[:scope]` is the scope key — under the default `AshVault.Scopes.AshTenant` that
is the tenant id. It is not secret, but it is frequently a customer identifier, so the
audit table inherits whatever access controls your other customer data has.

> #### A handler that forwards this metadata onward is forwarding tenant identifiers {: .warning}
>
> `Logger` output from AshVault reports a scope as `AshVault.Scope.fingerprint/1`, a
> truncated SHA-256, precisely because a tenant id is frequently PII. The
> `[:ash_vault, :key, :rotate]` and `[:ash_vault, :key, :destroy]` telemetry events
> deliberately do **not**: they carry the raw `:scope`, because the compliance record of
> an erasure has to be able to name the tenant it erased, and a fingerprint cannot.
>
> Telemetry metadata is copied verbatim into third-party APMs by most handlers anybody
> actually writes. **If you forward these events to an external service — an APM, a
> log shipper, an error reporter — you are sending it your tenant ids.** Both events
> also carry `:scope_fingerprint` so that a handler which must report outward has
> something safe to report, but it is a convenience, not a mitigation: the raw `:scope`
> is still in the same map, and a handler that copies the metadata wholesale sends it.
>
> Either drop `:scope` explicitly in the handler and forward `:scope_fingerprint`, or
> treat the destination as a place that holds customer data. An internal audit table,
> which is what the worked handler above writes to, is the case where the raw scope is
> the point.

Two notes on what you will *not* find in these events, both deliberate and both explained
in `AshVault.Telemetry`: the encrypt and decrypt events carry no `:scope` (resolving it
would run your `AshVault.Scope` module a second time per operation, and it is allowed to
have side effects and to raise), and no `:key_version` (it is inside the envelope). If your
audit requirement needs the tenant on every field read, correlate on Ash's own
`[:ash, :*]` spans, which carry it, or use a scope module you know is pure and read the
tenant from your request context.

### Volume

`[:ash_vault, :decrypt]` fires once per encrypted field per record. A list endpoint
returning 100 users with 3 encrypted fields emits 300 spans. Auditing every decrypt is what
some regimes ask for, and it is also how you fill a disk. Decide explicitly: many
deployments log the key-lifecycle events in full and sample or aggregate the decrypts.

### Retention

Retention is a decision you make with your own counsel; AshVault has no opinion and this
is not legal advice. The figures ash_cloak's
[security considerations](https://deepwiki.com/ash-project/ash_cloak/6.2-security-considerations)
cite, reproduced here as the starting point for that conversation rather than as a
requirement from us:

| Regime | Figure ash_cloak cites |
|---|---|
| HIPAA | 6 years |
| PCI-DSS | 1 year, with 3 months immediately available |
| GDPR | the duration of processing |

Whatever you choose, note the interaction with crypto-erasure that is specific to this
library: **the audit log survives the erasure it records.** That is the point of it — you
must be able to demonstrate that a deletion happened — but it means the audit table is one
more place a destroyed subject's identifiers live on. Keep identifiers in it, not data, and
make sure its retention window is one you can defend to the same subject.

## Monitoring

At minimum, alert differently on these three, because the correct human response differs:

* `ProviderUnavailable` → page. Encryption and decryption are both down.
* `CiphertextIntegrityFailed` → investigate. Either a deploy changed a module name or a scope
  key, or someone is writing to your database.
* `KeyDestroyed` → do not page. Expected after an erasure; a spike of it for a scope not in
  your deletion runbook is worth a look.

`KeySizeMismatch` and `InvalidScope` should fail your deploy, not your pager — they are
configuration faults that will affect every operation uniformly.


## Crash dumps and core dumps

A BEAM crash dump is a complete picture of process memory at the moment of the crash. If a
node dies while any key material is resident — which is every moment between fetching a key
and finishing the operation, and the whole cache lifetime if caching is on — that material can
land in `erl_crash.dump` as an ordinary file on disk, outside every protection this library
provides. The same is true of an OS core dump.

This is not hypothetical. Developing AshVault produced two crash dumps, 11 MB and 12 MB, from
crashed test runs — one in the project root and one under `example/` — and one of them
contained references to the key provider modules. Twice, in a project whose entire subject is
key hygiene.

In production:

```sh
# Do not write BEAM crash dumps at all.
export ERL_CRASH_DUMP_SECONDS=0

# Do not write OS core dumps for the beam process.
ulimit -c 0
```

Under systemd, also set `LimitCORE=0` on the unit, and check that no container runtime or
supervisor has re-enabled either.

### AshVault warns about this at boot

Because the unsafe state is the *default* — with `ERL_CRASH_DUMP_SECONDS` unset, OTP writes
the dump — AshVault logs a single `:warning` at application start naming the hazard and the
fix.

It is deliberately narrow, because a library that lectures about host configuration earns
nothing but muted logs:

* **Only when the variable is unset.** Setting it to anything, `0` or `30` alike, is a
  decision, and a decision is respected in silence. The warning is about the absence of one.
* **Only in `:prod`.** A development machine legitimately wants crash dumps, and a warning on
  every test run trains everyone to ignore it. The check is compiled out entirely in other
  environments — it is not a runtime branch.
* **Once, at boot**, never per operation.

To silence it without changing the environment:

```elixir
config :ash_vault, warn_on_crash_dumps?: false
```

Note what the warning does **not** cover: it cannot read `ulimit -c`, so an OS core dump is
still your responsibility, and a silenced warning is not a statement that this node is safe.
`ERL_CRASH_DUMP_SECONDS=0` disables one of the two hazards on this page.

If you must keep crash dumps for debugging, treat them with exactly the care you give the key
store: restricted directory, short retention, never shipped to a log aggregator or an APM, and
never committed. Add `erl_crash.dump` to `.gitignore` in any application that depends on
AshVault.

The same reasoning applies to swap. Key material can be paged to disk and survive there long
after the process ends. The Rust key cache `mlock`s its buffers to prevent this; the
pure-Elixir cache and the BEAM heap generally cannot. Encrypted swap is the answer at the
operating-system level.

## Related

* [Crypto-erasure](crypto-erasure.md) — the operational checklist
* [Rotation](rotation.md)
* [Migrating from plaintext](migrating-from-plaintext.md)
* `documentation/adr/0002-distinguishable-crypto-errors.md` — why the taxonomy above is granular
  rather than a single generic "decryption failed", and what a public API owes its users
  as a result
* `AshVault.Errors`, `AshVault.Telemetry`, `AshVault.KeyProviders.Local`,
  `AshVault.KeyProviders.OpenBao`
