# Review findings to fix — consolidated

From a security audit and a code review of the crypto core + providers.
Ranked by whether the finding breaks the central promise:
*destroying a customer's keys makes historical ciphertext permanently undecryptable.*

Several findings are the SAME bug class: **a missing or unreadable tombstone read as
"not destroyed"**. Tombstone reads must fail CLOSED, everywhere, without exception.

---

## P0 — breaks the central promise

### 1. Local: unmounted key root silently resurrects every destroyed tenant
`lib/ash_vault/key_providers/local.ex:278`

`init/1` runs `File.mkdir_p!(root)` unconditionally. If `:root` is a mount point (exactly what
the moduledoc tells operators to use) and the volume fails to mount — reordered systemd unit,
degraded array, NFS server not up yet — the provider creates the directory on the *underlying*
filesystem, starts clean, and reports healthy. Every tombstone is invisible; every destroyed
tenant is live again and minting fresh v1 keys. No attacker, no race: a boot-order bug.

**Fix:** do not create the root. Require it to exist AND contain an operator-created sentinel
file; refuse to start otherwise. A sentinel alone is not enough — a fresh install also has an
empty root, so the sentinel must never be auto-created. Add `mix ash_vault.local.init` as the
explicit setup step.

### 2. OpenBao: the tombstone store is auto-created on the READ path
`lib/ash_vault/key_providers/open_bao.ex:350`

`check_tombstone` sees `404 "no handler for route"`, calls `ensure_kv_mount()` which **creates
the KV engine empty**, retries, gets the genuine-absence shape `404 {"errors":[]}`, and returns
`:absent`. Every destroyed tenant resurrects. Auto-provisioning the store that holds your
tombstones is fail-open by construction. The moduledoc (lines 50-52) claims the opposite of what
the code does.

**Fix:** on any READ path a missing mount is `ProviderUnavailable`, full stop — delete the
mount-and-retry at 350-351. Mounting belongs in explicit operator setup only.
(`write_tombstone`'s retry at 372 is defensible and may stay.)

### 3. Local: `destroyed?/2` fails open on every stat error but ENOENT
`lib/ash_vault/key_providers/local.ex:490`

`File.exists?/1` returns `false` for ANY failure, not just absence — verified: parent directory
at mode 000 gives tombstone present but `File.exists?` false, `File.stat` `{:error, :eacces}`.
Also `:eio` (failing disk), `:estale` (NFS), `:eloop`. During any such window a destroyed scope
mints a fresh key.

**Fix:** `File.stat/1` — `{:ok, _}` destroyed, `{:error, :enoent}` absent, **anything else**
`ProviderUnavailable`.

### 4. OpenBao: tombstone decided from status code without validating the body
`lib/ash_vault/key_providers/open_bao.ex:328` and `:356`

- Resurrection direction (356): `errors(response) == [] -> :absent`, and `errors/1` returns `[]`
  for any body that is not a parsed JSON map — an ingress HTML 404 during a config reload, a
  gateway error page. Destroyed tenant reads as intact.
- Outage-as-erasure direction (328): `status: 200 -> {:error, :destroyed}` with no body check.
  A proxy returning 200 at the tombstone path makes EVERY scope report `KeyDestroyed`. Fails
  closed, but it is exactly the confusion threat-model §8 promises against.

**Fix:** require positive identification both ways. 200 → destroyed only when the body is a map
with a map at `"data"`. 404 → `:absent` only when the body is a map with an `"errors"` key whose
list is empty; everything else `ProviderUnavailable`. Verified safe: a genuinely absent KV-v2
secret returns exactly `404 {"errors":[]}`.

### 5. OpenBao: `destroy/1` can report `:ok` without deleting the transit key
`lib/ash_vault/key_providers/open_bao.ex:236` (and the identical branch at `:256`)

The 400 branch is on the `deletion_allowed` CONFIG call, before any delete is issued.
`missing_key?` matches the bare substring `"not found"` (line 458) — which also appears in policy
denials and proxy-surfaced 400s. On a match `delete_transit_key` returns `:ok` and
**`issue_delete/1` never runs**; `destroy/1` writes the tombstone and reports success. The key
still exists and is still exportable, while the operator closes the deletion ticket.

**Fix:** replace message parsing with a STATE CHECK — after the delete, re-read
`GET /v1/transit/keys/<name>` and require a positive absence before writing the tombstone.
Return `{:error, _}` if the key is still there. Drop the bare `"not found"` regex from the
erasure path entirely.

### 6. Truncated GCM authentication tags are accepted → deterministic forgery
`lib/ash_vault/ciphers/aes_gcm.ex:64` with `lib/ash_vault/envelope/v1.ex:75`

**Verified empirically on this machine (OTP 29):** `:crypto.crypto_one_time_aead` accepts 1, 2,
4, 8 and 12-byte tags and returns plaintext, comparing only the leading N bytes. Only a 0-byte
tag is rejected.

The envelope accepts any `tag_len` 0-255 straight from the database. GCM is CTR mode, so an
attacker with DB write access XORs the ciphertext with `known XOR desired` to get arbitrary
chosen plaintext, sets `tag_len: 1`, and enumerates 0x00-0xFF. **Success guaranteed within 256
read attempts.** Breaks threat-model §6 outright.

**Fix:** in `decrypt/3`, before calling `:crypto`, require `byte_size(tag) == 16` and
`byte_size(nonce) == 12`; return `{:error, :auth_failed}` otherwise. The cipher already exposes
`tag_bytes/0` and `nonce_bytes/0`. Add a test that forges a short-tag envelope and asserts it is
rejected.

### 7. Local: destroy shreds key material BEFORE writing the tombstone
`lib/ash_vault/key_providers/local.ex:403-409` (OpenBao has the same shape at `:185`)

If the tombstone write fails after the shred (ENOSPC, EACCES, read-only remount) — or the process
crashes between the two — the scope has no keys AND no tombstone. The next `current_key/1` mints
a fresh **v1**. Existing rows carry `key_version: 1`, so `get_key/2` returns the NEW v1 key, the
tag check fails, and the caller gets **`AuthenticationFailed`** — violating the core spec's
hardest rule that erasure must never look like tampering.

**This was my spec's fault** — docs/LOCAL_PROVIDER_SPEC.md mandated that order and has now been
corrected to tombstone-first.

**Fix:** write the tombstone (or a `.destroying` / `{"state":"in_progress"}` marker) BEFORE
shredding, and have `destroyed?` treat the marker as destroyed. Optionally rewrite it with a
`shredded_at` on completion so an interrupted destroy is visible.
Required test: shred, `File.chmod!(root, 0o500)`, assert `{:error, _}` from destroy, then assert
the NEXT `current_key/1` does **not** return `{:ok, %{version: 1}}`.

---

## P1 — correctness and operability

### 8. Provider/cipher key-size mismatch is unvalidated, then reported as two different lies
`lib/ash_vault/key_provider.ex:47-54`, `lib/ash_vault/vault/runtime.ex:59-61` and `:99-104`

`KeyProvider.key_bytes/1` has **zero callers**. Reachable via `key_bytes: 16` in config, OpenBao
`key_type: "aes128-gcm96"`, or a truncated `v1.key` on disk (`Local.do_get_key/3` returns whatever
bytes the file holds, no length check).

- Decrypt: `{:error, {:invalid_key_size, n}}` is caught by the generic `{:error, _}` clause →
  raises **`AuthenticationFailed`**. A config typo is reported as "your data was tampered with".
- Encrypt: raises `ProviderUnavailable` naming the CIPHER as the "provider", for an error its own
  moduledoc calls retryable. Operators retry a permanent misconfiguration forever.

**Fix:** (a) validate `KeyProvider.key_bytes(provider) == cipher.key_bytes()` at compile time in
the `use AshVault.Vault` macro, naming both numbers; (b) match `{:error, {:invalid_key_size, n}}`
explicitly in both runtime branches and raise a distinct non-retryable error; (c) `Local` must
reject a key file whose size ≠ `state.key_bytes` as `ProviderUnavailable`, not hand short bytes
to the cipher.

### 9. Three providers disagree on non-binary scopes; OpenBao uses `term_to_binary`
`lib/ash_vault/key_providers/open_bao.ex:529`

Local raises, Memory accepts any term, OpenBao `:erlang.term_to_binary/1`s it — making the transit
key name AND the tombstone path functions of the OTP external term format. An OTP encoding change
relocates both: tombstone absent → scope resurrects with a fresh key, all existing ciphertext
becomes `KeyNotFound`. Directly violates CORE_SPEC §6.

**Fix:** narrow `@type scope :: binary()`, drop OpenBao's fallback, enforce the invariant once in
`Runtime.encrypt!/decrypt!` right after `scope.resolve!(ctx)` so a bad custom Scope fails in one
place with a clear message. Add a contract case asserting all providers reject a non-binary scope
identically.

### 10. `MissingScope` message hardcodes "no Ash tenant was present" and ignores `:reason`
`lib/ash_vault/errors.ex:35-42`, raised from `lib/ash_vault/scopes/ash_tenant.ex:73-81`

When the reason is `:unsupported_tenant_shape` the operator — who DID pass a tenant, in a shape
with no `:id` — reads "no Ash tenant was present" and hunts a missing tenant that is not missing.
The `vars: [tenant: inspect(tenant)]` assembled at ash_tenant.ex:79 is never read.
Also says "Cannot **encrypt**" on the decrypt path.

**Fix:** branch `message/1` on `reason`; for the shape case say what was received and which shapes
are accepted, naming `to_scope_key/2` as the extension point. Carry the operation
(`:encrypt`/`:decrypt`) so the verb is right. Assert `Exception.message/1` for every reason value.

### 11. OpenBao fabricates `created_at: DateTime.utc_now()` when metadata is missing
`lib/ash_vault/key_providers/open_bao.ex:305-321`

A key whose `created_at` is always "now" is never older than `max_age`, so age-based rotation
never fires and nothing logs. Local explicitly refuses to do this (`local.ex:467-470`) — the two
providers disagree on a rule one of them wrote down as load-bearing.

**Fix:** return `{:error, unavailable(:malformed_key_metadata)}` instead. Add a contract case
asserting `created_at` is stable across two `current_key/1` calls and increases across `rotate/1`.

### 12. `rotate_best_effort` swallows `{:error, :destroyed}`
`lib/ash_vault/vault/runtime.ex:227-239`

A write racing a `destroy!` logs a warning and encrypts under the pre-destroy key. The write
"succeeds" and stores ciphertext nobody can ever read.
**Fix:** match `{:error, :destroyed}` explicitly and re-raise `KeyDestroyed`.

### 13. Memory GenServer state holds every tenant's raw key with no `format_status/1`
`lib/ash_vault/key_providers/memory.ex:145-152`

Any crash emits a SASL report containing all key material into logs and APM.
**Fix:** `format_status/1` returning `keys: :redacted`. (Local's state is clean.)

### 14. OpenBao token printed in full by anything inspecting the request
`lib/ash_vault/key_providers/open_bao.ex:417`

Req's `Inspect` redacts only the `authorization` header (`deps/req/lib/req/request.ex:1158-1166`);
`x-vault-token` is emitted verbatim. Finch telemetry metadata carries the request headers, and APM
handlers routinely record metadata verbatim. `Req.request/1` at :424 is also unwrapped, so a raise
inside a Req step escapes as a non-AshVault exception.

**Fix:** wrap `Req.request/1` in try/rescue/catch → `ProviderUnavailable`; redact the token header
for telemetry; and soften the moduledoc's "never inspected" claim to what the code can guarantee.

### 15. Local `get_key/2` interpolates an unvalidated version into a path
`lib/ash_vault/key_providers/local.ex:623`

`"v#{version}.key"` — not reachable from database bytes (the envelope field is a 32-bit int), but
`get_key/2` is public API and a caller passing `"../../../etc/ssl/private/server"` reads any
`.key` file the process can reach. OpenBao guards this at :140; Local does not.
**Fix:** same `is_integer(version) and version > 0` guard.

---

## P2 — test quality (the tests pass but do not prove what they claim)

16. **Cross-scope decrypt proves key difference, not AEAD binding** (`vault_test.exs:104-114`).
    Use the existing fixed-key `FailingRotateProvider` so the key is identical and only the AAD
    differs. (Cross-field `:116-122` and cross-resource `:124-130` are genuine.)
17. **Envelope fuzz accepts any error shape** (`envelope_test.exs:114-143`) — `match?({:error, %{}})`
    passes on a misclassification. Assert the specific struct based on magic/version.
18. **Destroy irreversibility under-tested at vault level** (`vault_test.exs:248-257` is one failed
    decrypt). Missing everywhere: the failed-tombstone-write path (#7); `rotate/1` on a fresh scope
    returning `{:ok, 1}` for all three providers; `get_key(scope, 0)` and negative versions in the
    shared suite; an end-to-end `UnsupportedCipher` (runtime.ex:84-87 is uncovered).
19. **No vault-level test runs over `Local` or `OpenBao`** — every vault test uses Memory. Add a
    `Local` end-to-end roundtrip (encrypt → restart provider → decrypt → destroy → `KeyDestroyed`);
    needs no Docker.
20. `Envelope.V1.encode/1` raises `FunctionClauseError` on an over-long nonce/tag or
    `key_version > 2^32-1`, while an over-long cipher id gets a clean `ArgumentError`. Make them
    symmetric; add the `2^32` case.

---

## Explicitly sound — do not "fix"

Envelope parsing is genuinely total (no atom exhaustion, no decompression, no length-driven
allocation). Cipher registry is binary-keyed so encode/decode cannot drift. Nonces are fresh
`strong_rand_bytes(12)` per encryption, never counter-derived — no reuse vector. AAD correctly
binds scope|resource|field and relocation between tenants/resources/fields fails. Scope encoding is
injective in both providers (the spec's dash-collision bug is correctly absent from the code).
Memory tombstones are MapSet-backed with no fail-open. `Runtime`'s error taxonomy keeps
`:destroyed` / `:not_found` / transport distinct and checks destruction before decrypting.
Wrong token → 403 → `ProviderUnavailable`, never `:destroyed`. No key material reaches a log line
or error struct in the core. `inspect(resource)` in the AAD is a deliberate documented tradeoff.
