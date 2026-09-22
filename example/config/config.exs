import Config

# ── Which key provider? ──────────────────────────────────────────────────────────
#
# The demo runs against either key provider without touching a resource:
#
#     ASHVAULT_PROVIDER=openbao   (default) key material in OpenBao transit
#     ASHVAULT_PROVIDER=local               key material in a directory on disk
#
# Both satisfy the property the library exists for — the keys live in a system that
# is *not* the PostgreSQL database, so a `pg_dump`/restore cycle cannot bring back
# a destroyed key. See `Example.Vault`.
config :example, key_provider: System.get_env("ASHVAULT_PROVIDER", "openbao")

config :example, ash_domains: [Example.Accounts]

config :example, Example.Repo,
  username: System.get_env("PGUSER", "postgres"),
  password: System.get_env("PGPASSWORD", "postgres"),
  hostname: System.get_env("PGHOST", "localhost"),
  port: String.to_integer(System.get_env("PGPORT", "5432")),
  # This example only ever names this database. It never touches `foundry_dev`
  # or `ash_vault_test`.
  database: "ash_vault_example",
  pool_size: 10

# NOTE (API wart): provider configuration is read from the `:ash_vault` application
# key, not from the host application's. An app embedding AshVault therefore has to
# write config under someone else's OTP app name.
config :ash_vault, AshVault.KeyProviders.OpenBao,
  address: System.get_env("BAO_ADDR", "http://127.0.0.1:8200"),
  token: System.get_env("BAO_TOKEN", "ashvault-root"),
  transit_mount: "transit",
  kv_mount: "ashvault"

config :ash_vault, AshVault.KeyProviders.Local,
  # Deliberately NOT under the project directory, and never inside a PostgreSQL
  # backup. If the key directory ends up in the same tarball as the database dump,
  # crypto-erasure is defeated and this library's central promise is void.
  root: System.get_env("ASHVAULT_LOCAL_ROOT", "/tmp/ash_vault_example_keys")

config :ash, default_string_length_count: :codepoints
config :ash, policies: [no_filter_static_forbidden_reads?: false]

config :logger, level: :warning

config :example, ecto_repos: [Example.Repo]
