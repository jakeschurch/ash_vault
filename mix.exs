defmodule AshVault.MixProject do
  use Mix.Project

  def project do
    [
      app: :ash_vault,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {AshVault.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ash, "~> 3.0"},
      {:spark, "~> 2.0"},
      {:jason, "~> 1.4"},
      {:ash_postgres, "~> 2.0", only: [:dev, :test]},
      {:ash_cloak, "~> 0.1", only: [:dev, :test]},
      {:cloak, "~> 1.1", only: [:dev, :test]},
      {:req, "~> 0.5"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
