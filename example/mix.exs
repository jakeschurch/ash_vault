defmodule Example.MixProject do
  use Mix.Project

  def project do
    [
      app: :example,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Example.Application, []}
    ]
  end

  defp aliases do
    [
      # One-shot: create the database, apply the schema, mount OpenBao's KV engine.
      setup: ["example.setup"],
      demo: ["example.demo"]
    ]
  end

  defp deps do
    [
      {:ash_vault, path: ".."},
      {:ash, "~> 3.37 and >= 3.37.2"},
      {:ash_postgres, "~> 2.15 and >= 2.15.2"},
      # Ash.Policy.Authorizer needs a SAT solver at runtime. The parent declares it
      # `only: [:dev, :test]`, so it does not reach us through the path dep.
      {:simple_sat, "~> 0.1"},
      # Password hashing for the sign-in step. The parent library declares it
      # `only: [:dev, :test]` — AshVault must never depend on ash_authentication at
      # runtime — so, like `simple_sat`, it does not reach us through the path dep.
      # Assent 0.3 support requires the AshAuthentication 5 release candidate.
      {:ash_authentication, "~> 5.0.0-rc.15"},
      {:jason, "~> 1.4"}
    ]
  end
end
