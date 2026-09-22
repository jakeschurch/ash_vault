---
name: ashvault-dev-env
description: How to run AshVault code and suites — nix dev shell, service endpoints, suite isolation rules
metadata:
  type: reference
---

Toolchain comes from the nix dev shell; run everything as
`nix develop --command bash -c '<cmd>'` from the repo root (the flake is only resolvable
from inside the project, so `cd`-ing to a scratchpad first breaks it — use absolute script
paths instead).

  * ad-hoc proof scripts: `MIX_ENV=test mix run /abs/path/script.exs` picks up `test/support/*`
  * PostgreSQL localhost:5432 (postgres/postgres, DB `ash_vault_test`) — `mix test --include postgres`
  * OpenBao 127.0.0.1:8200, token `ashvault-root` — `mix test --include openbao`

Run postgres suites **alone**; concurrent runs truncate each other's tables. Never touch
`foundry_dev`.
