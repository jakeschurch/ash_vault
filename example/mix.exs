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
      {:ash, "~> 3.0"},
      {:ash_postgres, "~> 2.0"},
      # Ash.Policy.Authorizer needs a SAT solver at runtime. The parent declares it
      # `only: [:dev, :test]`, so it does not reach us through the path dep.
      {:simple_sat, "~> 0.1"},
      {:jason, "~> 1.4"}
    ]
  end
end
