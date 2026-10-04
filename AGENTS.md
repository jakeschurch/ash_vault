# Agent Instructions

This project uses **bd** (beads) for issue tracking — see the Beads section at the end.

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Branching

**Never commit directly to `main`.** Branch for every task, including docs, chores and
CI iteration, and open a PR. This applies even when the tree is green and the change
looks trivial.

## Build & Test

The host has **no C toolchain** — no `cc`, `gcc` or `ld` — so anything with a NIF
cannot link outside the dev shell. Run everything through it:

```bash
nix develop --command bash -c '<command>'      # default: native tooling, host BEAM
nix develop .#full --command bash -c '<cmd>'   # pinned Elixir/OTP, differs from host
```

```bash
mix test                                    # no services needed
mix test test/ash_vault/lookup_test.exs:42  # one file / one test
mix test.all                                # alias: --include postgres --include openbao
cd ash_vault_rustler && mix test            # the Rust NIF package
mix format                                  # Spark DSL locals come from .formatter.exs
mix docs                                    # must stay at zero warnings
```

Adding a DSL option means adding it to `spark_locals_without_parens` in
`.formatter.exs`. A new guide or public module must also be listed in `docs/0`
(`extras` / `groups_for_modules`) in `mix.exs`. A change to public behavior must also
update `usage-rules.md` / `usage-rules/*.md`, which ship to consumers via `usage_rules`. In `ash_vault_rustler`,
`ASH_VAULT_RUSTLER_BUILD=1` builds the NIF from source instead of downloading the
precompiled artifact.

Services the tagged suites expect: PostgreSQL on `localhost:5432` (`postgres`/`postgres`)
and OpenBao on `127.0.0.1:8200`.

**Run the postgres suites alone.** `test/support/db.ex` truncates shared tables and the
acceptance suite drops and recreates the database, so two concurrent runs corrupt each
other — every failure looks like missing rows. Override the database per run with
`ASHVAULT_TEST_DB`; it refuses any name not starting with `ash_vault_test`.

## Architecture

```
Ash resource --> AshVault extension --> AshVault.Vault --> KeyProvider
                 (DSL, transformers,    (scope, AAD,       (Memory, Local,
                  change, calculation)   envelope, cipher)   OpenBao, OpenBaoTransit)
```

The property the whole library exists for: destroying a scope's keys makes its
ciphertext permanently undecryptable, and **restoring a database backup cannot undo
that**, because the keys were never in the database.

How it fits together:

- **Compile time.** `Transformers.SetupEncryption` deletes each encrypted attribute and
  replaces it with a private `encrypted_<name>` binary column, a same-named calculation
  backed by `Calculations.Decrypt`, and an action argument that `Changes.Encrypt`
  consumes. Removing the attribute is what keeps plaintext out of the database. It must
  run after Ash's `DefaultAccept`; otherwise it rewrites no actions and nothing gets
  encrypted, with no error.
- **Runtime.** `use AshVault.Vault` generates thin delegations to `Vault.Runtime`. The
  `Scope` (default: the Ash tenant) selects the keyring. AEAD associated data binds
  `scope | resource | field`. `Envelope.V1` (`"AV", 1, ...`) records the cipher and key
  version, so rotation needs no re-encryption.
- **Searchable fields** add a deterministic `<name>_lookup` HMAC column and a
  `:by_<name>` read. The token key comes from `KeyProvider.lookup_key/1`, a separate
  per-scope secret that never rotates, HKDF'd per resource and field. Deriving it from the
  rotating DEK would make lookups stop matching after a rotation, and nothing would raise.
- **Key purposes.** Data keys, `:mac` keys (`Vault.mac!/2`) and the lookup key are
  separate keyrings. `destroy/1` erases all of them under one tombstone.
- **Macaroons.** A `macaroon` entity generates `:mint_<name>` and `:<name>_by_token`
  actions for attenuable bearer tokens signed under the scope's `:mac` keyring
  (`lib/ash_vault/macaroon/`). Authorize-phase caveats are enforced only by
  `AshVault.Checks.MacaroonAllows`.
- **`KeyProviders.Cached`** (vault `cache:` option) is off by default on purpose, because
  a cache weakens erasure. `ash_vault_rustler` is an optional sibling Mix project. It
  provides a NIF key cache and cipher that keep keys off the BEAM heap so eviction can
  zero them.
- **Operator tooling** lives in `lib/mix/tasks/ash_vault.*` (rotate, destroy_keys,
  backfill, verify, key_info, local.init).

## Conventions

- **Tombstone reads fail closed.** A missing, unreadable or ambiguous tombstone is
  `ProviderUnavailable` — never "not destroyed". Four fail-open reads shipped once and
  silently resurrected erased tenants; do not add a fifth.
- **Never conflate the error taxonomy.** `KeyDestroyed`, `KeyNotFound`,
  `ProviderUnavailable` and `CiphertextIntegrityFailed` mean different things and demand
  opposite operator responses. An outage must never look like erasure.
- **No plaintext or key material in errors, logs or telemetry.** Redact at construction,
  not at render — `inspect/1` and Ash's error aggregation read the struct directly.
- **Watch for silent failures.** Every dangerous bug this project has had returned a
  wrong-but-plausible result and raised nothing. Prefer an error over an empty result.
- **Design docs** live in `documentation/internal/`; shipped guides in
  `documentation/topics|tutorials|how-to`; ADRs in `documentation/adr/`.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
