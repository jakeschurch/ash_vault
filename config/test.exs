import Config

config :ash_vault, ash_domains: [AshVault.Test.Domain]

config :ash_vault, AshVault.Test.Repo,
  username: System.get_env("PGUSER", "postgres"),
  password: System.get_env("PGPASSWORD", "postgres"),
  hostname: System.get_env("PGHOST", "localhost"),
  port: String.to_integer(System.get_env("PGPORT", "5432")),
  # Never `foundry_dev`. The harness creates this database and truncates its tables.
  #
  # `ASHVAULT_TEST_DB` exists because `AshVault.Test.Db.reset!/0` truncates shared tables:
  # two `mix test` runs against the same database wipe each other mid-suite, which looks
  # like flaky code and is not. Point a second, concurrent run at its own database rather
  # than debugging the phantom failures.
  database: System.get_env("ASHVAULT_TEST_DB", "ash_vault_test"),
  pool_size: 10,
  show_sensitive_data_on_connection_error: true

config :ash, disable_async?: true

config :logger, level: :warning
