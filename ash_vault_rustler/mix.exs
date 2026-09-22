defmodule AshVaultRustler.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :ash_vault_rustler,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "AshVaultRustler",
      description:
        "A Rust-backed AshVault key cache and AES-256-GCM cipher that hold key material " <>
          "outside the BEAM heap, so eviction can actually zero it.",
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  # `test/parent_support/` holds one symlink: the parent's `key_provider_cases.ex`. It is
  # the *same file* the parent runs, not a copy, because a copied contract suite drifts
  # and a drifted contract suite is worse than none. A symlink rather than pointing
  # `elixirc_paths` at `../test/support` because Mix only accepts directories there, and
  # the parent's other support files pull in ash_postgres, Ecto and the test repo — none
  # of which this package depends on.
  defp elixirc_paths(:test), do: ["lib", "test/support", "test/parent_support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:ash_vault, path: ".."},
      {:rustler, "~> 0.38"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      groups_for_modules: [
        "Cache backend": [AshVaultRustler.KeyCache],
        Cipher: [AshVaultRustler.Cipher],
        "Opaque keys": [AshVaultRustler.KeyProviders.Opaque],
        Internals: [AshVaultRustler.Native]
      ]
    ]
  end
end
