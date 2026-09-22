# Writing a key provider

A key provider is the authoritative store of key material. It is the component that makes
crypto-erasure real, because it is the one thing that is deliberately *not* in your
database backup. Getting it wrong is how erasure becomes silent data loss.

Read this whole page before writing one, then run the shared contract suite
(`test/support/key_provider_cases.ex`) against your implementation.

## The contract

```elixir
@type scope :: term()          # always a binary in practice — see below
@type version :: non_neg_integer()
@type key_info :: %{version: version(), key: binary(), created_at: DateTime.t()}

@callback current_key(scope()) :: {:ok, key_info()} | {:error, term()}
@callback get_key(scope(), version()) ::
            {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
@callback rotate(scope()) :: {:ok, version()} | {:error, term()}
@callback destroy(scope()) :: :ok | {:error, term()}
@callback key_bytes() :: pos_integer()      # optional, defaults to 32
```

Semantics every implementation must honour:

* `current_key/1` **mints** the scope's key material on first use, at version 1. Callers
  never create a scope's key explicitly — there is no `create_key/1`.
* `get_key/2` returns historical versions. Rotation retains them; that is what lets old
  ciphertext keep decrypting.
* `rotate/1` on a scope that has never been used mints version 1 and returns `{:ok, 1}`.
* `destroy/1` is a **tombstone**, not a delete. See below.
* `destroy/1` on a scope that never had a key still records the tombstone and returns
  `:ok`.
* Scopes are binaries. Reject anything else with an `ArgumentError`.
* `key_bytes/0` is optional; `AshVault.KeyProvider.key_bytes/1` falls back to 32.

Error terms are mapped onto AshVault errors in exactly one place,
`AshVault.Vault.Runtime`:

| Your return | What the caller sees |
|---|---|
| `{:error, :destroyed}` | `AshVault.Errors.KeyDestroyed` |
| `{:error, :not_found}` | `AshVault.Errors.KeyNotFound` |
| `{:error, anything_else}` | `AshVault.Errors.ProviderUnavailable` (retryable) |

So the three-way distinction is entirely in your hands.

## Failure modes that matter

These are not hypotheticals. Every one of them was a real finding against AshVault's own
providers, and each has a named case in the contract suite.

### 1. Tombstones must fail closed

Deleting key material leaves the scope *absent*, and absent looks exactly like
never-used. A `current_key/1` that cannot positively determine "no tombstone" and mints a
fresh version 1 anyway has resurrected an erased tenant. That tenant then writes new rows
under the new key while every pre-existing row is unreadable — and nothing anywhere
records that an erasure was ever attempted.

So: a tombstone read that **cannot complete** is never answered with "not destroyed".

* `AshVault.KeyProviders.Local` uses `File.stat/1`, not `File.exists?/1`. `File.exists?/1`
  returns `false` for *any* failure — `:eacces` on a mode-000 parent, `:eio` on a failing
  disk, `:estale` on NFS, `:eloop`. Only a positive `:enoent` counts as absence; anything
  else is `ProviderUnavailable`.
* `AshVault.KeyProviders.OpenBao` demands a **positive identification of the response
  body** in both directions: `200` counts as destroyed only when the body is a map with a
  map at `"data"`; `404` counts as absent only when the body is a map with an `"errors"`
  key whose list is empty. An HTML error page from an ingress mid-reload is
  `ProviderUnavailable`, not "not destroyed" — and not "destroyed" either.

Related: **never auto-provision the store that holds your tombstones on a read path.** A
freshly created, empty tombstone store reads as "nothing was ever destroyed" for every
scope you have. That is fail-open by construction. Provisioning belongs in explicit
operator setup (`AshVault.KeyProviders.OpenBao.setup/0`,
`mix ash_vault.local.init`). Creating the store in order to *write* a tombstone is
defensible — it cannot lose an erasure.

And: **never create your own key root.** If your key store is a directory on its own
volume (which is what you should be telling operators to do) and that volume fails to
mount, a `File.mkdir_p!/1` in `init/1` builds an empty store on the underlying
filesystem, reports itself healthy, and resurrects every tenant you ever erased. No
attacker needed — a reordered systemd unit is enough. `Local` requires an
operator-created `.ash_vault_root` sentinel and refuses to start without it, with this
message:

```
AshVault.KeyProviders.Local key root /srv/keys exists but holds no .ash_vault_root
sentinel, so it is either uninitialised or not the volume you think it is.

AshVault.KeyProviders.Local never creates its own key root. If it did, a key volume that
failed to mount would be silently replaced by an empty directory on the underlying
filesystem: no tombstones, no key material, and a fresh version 1 minted for every
tenant that was ever crypto-erased.
```

### 2. Ordering: tombstone first, then shred

If you shred key material and *then* write the tombstone, the window between the two — an
ENOSPC, an EACCES, a read-only remount, a process crash — leaves the scope with no keys
**and** no tombstone. The next `current_key/1` mints a fresh version 1; existing rows say
`key_version: 1`, so `get_key/2` hands back the *new* v1 key, the tag check fails, and the
caller is told `AshVault.Errors.CiphertextIntegrityFailed` — erasure wearing the costume of
tampering.

Tombstone-first fails safe: the worst case is a scope marked destroyed whose key files
linger, and the provider refuses to serve them anyway. Optionally rewrite the tombstone
with a `shredded_at` once the shred completes, so an interrupted destroy is visible to an
operator.

### 3. `:destroyed` must never be conflated with `:not_found` or an outage

Three distinct answers, three distinct causes, three distinct operator responses:

* `:destroyed` — deliberate erasure. Close the ticket; the data is gone by design.
* `:not_found` — the provider has no such key *and no tombstone*. Corruption, a wrong
  scope key, a key file deleted by hand. Investigate.
* anything else — an outage. Page someone, then retry.

Concretely, this means:

* corrupt or truncated metadata → `ProviderUnavailable`, **never** `:destroyed`;
* metadata that references a version whose key material is missing → `:not_found`, never
  `:destroyed`;
* a wrong or expired credential (OpenBao answers `403 permission denied` on every
  endpoint) → `ProviderUnavailable`, never `:destroyed`;
* never infer "there was nothing to delete" from an *error message*. AshVault's OpenBao
  provider once matched the bare substring `"not found"` — which also appears in policy
  denials and proxy-surfaced 400s — and so reported `destroy/1` as `:ok` without ever
  issuing the delete. It now re-reads the key and requires a **positive absence** before
  writing the tombstone; if the key is still there, `destroy/1` returns `{:error, _}`.

Validate `version` too. It is public API: a caller passing `"../../../etc/ssl/private/x"`
must get `{:error, :not_found}`, not a file read. Guard with
`is_integer(version) and version > 0`.

### 4. `created_at` must never be fabricated

Returning `DateTime.utc_now()` when the real creation time is unavailable produces a key
that is never older than any `max_age`, so age-based rotation silently never fires and
nothing logs a reason. Return `{:error, ...}` instead:

```elixir
{:error, %AshVault.Errors.ProviderUnavailable{reason: :malformed_key_metadata}}
```

`created_at` must be stable across two `current_key/1` calls and must not move backwards
across a `rotate/1`.

### 5. Key size

Hand back exactly the bytes you claim. A truncated key file, a `key_bytes: 16` in config,
an OpenBao `key_type: "aes128-gcm96"` under a 256-bit cipher — all of them used to reach
the cipher unchecked and be reported as *tampering* on decrypt and as a *retryable
outage* on encrypt. Reject a key of the wrong size as `ProviderUnavailable` rather than
passing short bytes on; `AshVault.Vault.Runtime` raises
`AshVault.Errors.KeySizeMismatch` when it sees one anyway, which is at least the truth.

### 6. Key material must not reach a log

A `GenServer` whose state holds raw keys emits every one of them in a SASL crash report,
straight into your log aggregator and any APM handler attached to it. Implement
`format_status/1`:

```elixir
@impl GenServer
def format_status(status) do
  Map.update(status, :state, nil, fn state -> %{state | keys: :redacted} end)
end
```

## A worked example

A provider backed by a table in an *external* database — enough to show every rule. Note
that if you put this table in the same database as your encrypted rows, you have
defeated the entire point: a restore brings back both.

```elixir
defmodule MyApp.KeyProviders.Sql do
  @moduledoc """
  Keys in a dedicated PostgreSQL database, separate from the application database.

  The `ash_vault_keys` and `ash_vault_tombstones` tables MUST live in a database that is
  not part of the application database's backup domain. If one restore brings back both,
  crypto-erasure is void.
  """

  @behaviour AshVault.KeyProvider

  alias AshVault.Errors.ProviderUnavailable

  @key_bytes 32

  @impl AshVault.KeyProvider
  def key_bytes, do: @key_bytes

  @impl AshVault.KeyProvider
  def current_key(scope) when is_binary(scope) do
    with :absent <- tombstone(scope) do
      case latest(scope) do
        {:ok, nil} -> mint(scope, 1)
        {:ok, row} -> {:ok, %{version: row.version, key: row.key, created_at: row.created_at}}
        {:error, reason} -> {:error, unavailable(reason)}
      end
    else
      :destroyed -> {:error, :destroyed}
      {:unavailable, reason} -> {:error, unavailable(reason)}
    end
  end

  def current_key(scope), do: raise_non_binary(scope)

  @impl AshVault.KeyProvider
  def get_key(scope, version) when is_binary(scope) and is_integer(version) and version > 0 do
    with :absent <- tombstone(scope) do
      case fetch(scope, version) do
        {:ok, nil} -> {:error, :not_found}
        # A key of the wrong size is a corrupt store, not tampering. Never hand
        # short bytes to the cipher.
        {:ok, %{key: key}} when byte_size(key) != @key_bytes ->
          {:error, unavailable({:bad_key_size, byte_size(key)})}

        {:ok, %{key: key}} -> {:ok, key}
        {:error, reason} -> {:error, unavailable(reason)}
      end
    else
      :destroyed -> {:error, :destroyed}
      {:unavailable, reason} -> {:error, unavailable(reason)}
    end
  end

  def get_key(scope, _version) when is_binary(scope), do: {:error, :not_found}
  def get_key(scope, _version), do: raise_non_binary(scope)

  @impl AshVault.KeyProvider
  def rotate(scope) when is_binary(scope) do
    with :absent <- tombstone(scope) do
      case latest(scope) do
        {:ok, nil} -> with {:ok, %{version: v}} <- mint(scope, 1), do: {:ok, v}
        {:ok, row} -> with {:ok, %{version: v}} <- mint(scope, row.version + 1), do: {:ok, v}
        {:error, reason} -> {:error, unavailable(reason)}
      end
    else
      :destroyed -> {:error, :destroyed}
      {:unavailable, reason} -> {:error, unavailable(reason)}
    end
  end

  def rotate(scope), do: raise_non_binary(scope)

  @impl AshVault.KeyProvider
  def destroy(scope) when is_binary(scope) do
    # Tombstone FIRST. A crash after the delete but before the tombstone would leave
    # the scope with no keys and no record, and the next current_key/1 would mint a
    # fresh v1 — silent, undetectable data loss reported as CiphertextIntegrityFailed.
    with :ok <- write_tombstone(scope),
         :ok <- delete_keys(scope),
         :destroyed <- tombstone(scope) do
      :ok
    else
      {:error, reason} -> {:error, unavailable(reason)}
      # The tombstone did not read back as destroyed: do not claim an erasure.
      other -> {:error, unavailable({:tombstone_unconfirmed, other})}
    end
  end

  def destroy(scope), do: raise_non_binary(scope)

  # Fails closed: only a positive absence counts as "not destroyed".
  defp tombstone(scope) do
    case query_tombstone(scope) do
      {:ok, nil} -> :absent
      {:ok, _row} -> :destroyed
      {:error, reason} -> {:unavailable, reason}
    end
  end

  defp mint(scope, version) do
    key = :crypto.strong_rand_bytes(@key_bytes)
    created_at = DateTime.utc_now() |> DateTime.truncate(:second)

    case insert(scope, version, key, created_at) do
      :ok -> {:ok, %{version: version, key: key, created_at: created_at}}
      {:error, reason} -> {:error, unavailable(reason)}
    end
  end

  defp unavailable(reason),
    do: ProviderUnavailable.exception(provider: __MODULE__, reason: reason)

  defp raise_non_binary(scope) do
    raise ArgumentError,
          "#{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}"
  end
end
```

`insert/4`, `latest/1`, `fetch/2`, `delete_keys/1`, `query_tombstone/1` and
`write_tombstone/1` are yours; each returns `{:ok, row_or_nil}`, `:ok` or
`{:error, reason}`. Note what the shape buys you: every database failure becomes
`ProviderUnavailable`, and nothing anywhere can turn one into `:destroyed` or `:not_found`.

Then point a vault at it:

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: MyApp.KeyProviders.Sql
end
```

## Run the contract suite

`test/support/key_provider_cases.ex` is a `__using__` macro holding the cases every
provider must pass. Copy it into your own project (or depend on AshVault's test support)
and wire it up:

```elixir
defmodule MyApp.KeyProviders.SqlTest do
  use ExUnit.Case, async: true

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_provider/1

  def start_provider(_context) do
    %{
      provider: MyApp.KeyProviders.Sql,
      scope: fn -> "scope_#{System.unique_integer([:positive])}" end
    }
  end
end
```

The setup callback returns `:provider` (a module, or `{module, server}` when the instance
is not default-named), `:scope` (a zero-arity generator of fresh scopes), and optionally
`:key_bytes`.

The cases, and the rule each one pins down:

| Case | Rule |
|---|---|
| first `current_key` mints version 1 | minting is implicit |
| `current_key` is stable across calls | no re-minting |
| different scopes get different keys | scope isolation |
| `rotate` mints v2 and v1 stays fetchable | history is retained |
| `get_key` for an unknown version returns `:not_found` | not `:destroyed` |
| `get_key` on an unknown scope returns `:not_found` | not `:destroyed` |
| `destroy` makes `current_key` and `get_key` both `:destroyed` | tombstone covers both |
| `destroy` is idempotent | re-running is safe |
| `destroy` works on a scope that never had a key | tombstone anyway |
| **a destroyed scope never re-mints** | the central promise |
| **a non-binary scope is rejected identically by every provider** | no `term_to_binary` scope keys |
| `rotate` on a scope that has never been used returns `{:ok, 1}` | consistent with minting |
| a zero, negative or non-integer version is `:not_found` | version is validated, not interpolated |
| **`created_at` is stable across calls and never moves backwards on rotate** | no fabricated timestamps |
| destroying one scope leaves others untouched | erasure is scoped |

Add your own tests for whatever your backing store can do that these cannot express —
`Local`, for example, additionally asserts that keys and tombstones survive a provider
restart, that a corrupt `meta.json` is `ProviderUnavailable` rather than `:destroyed`, and
that making the root unwritable mid-destroy does **not** let the next `current_key/1`
return `{:ok, %{version: 1}}`.

## Related

* `AshVault.KeyProvider`, `AshVault.KeyProviders.Local`, `AshVault.KeyProviders.OpenBao`
* [Crypto-erasure](../topics/crypto-erasure.md) — what your tombstone is promising
* [Operations](../topics/operations.md) — what operators do with your errors
