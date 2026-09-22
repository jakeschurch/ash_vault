---
name: ashvault-audit-focus
description: AshVault audits are scoped to silent failures (wrong-but-plausible results, no error raised); loud failures are explicitly out of scope
metadata:
  type: project
---

AshVault reviews target ONE bug class: **silent failures** — a code path that returns a
wrong-but-plausible result with nothing raised. Compile errors, exceptions and failed
assertions are explicitly out of scope and should not be reported.

**Why:** every genuinely dangerous bug this project has shipped was silent — shred-before-
tombstone, non-injective transit key names, truncated GCM tags accepted, four fail-open
tombstone reads, `backfill --verify` leaking plaintext in its stats map. Each returned a
plausible result. `docs/REVIEW_FINDINGS.md` holds 20 already-fixed findings; do not
re-report them.

**How to apply:** rank findings by how long the wrong answer would survive unnoticed in
production, not by CVSS. A bug that surfaces on the next request is low rank here; one that
corrupts a year of writes (or a whole migration) is P0. Prove findings with a runnable
script rather than an argument. See [[ashvault-dev-env]].
