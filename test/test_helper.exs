backend = System.get_env("ASHVAULT_BACKEND", "memory")
ExUnit.start(exclude: [:postgres, :openbao, :openbao_plugin])

case backend do
  "memory" ->
    :ok

  "openbao" ->
    ExUnit.configure(
      include:
        Enum.uniq([:postgres, :openbao, :openbao_plugin | ExUnit.configuration()[:include] || []])
    )

  _ ->
    raise ArgumentError, "ASHVAULT_BACKEND must be memory or openbao"
end

included = ExUnit.configuration() |> Keyword.get(:include, [])

# `:openbao` is load-bearing here, not just `:postgres`. The acceptance suites carry
# `@moduletag :postgres` *and* an `:openbao`-tagged describe block; ExUnit's include
# wins over exclude, so `mix test --include openbao` runs those tests and they need the
# repo started. Setting up only on `:postgres` left them failing with "could not lookup
# Ecto repo" on a run that never asked for Postgres.
if :postgres in included or :openbao in included do
  AshVault.Test.Db.setup!()
end
