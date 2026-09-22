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
      aliases: aliases(),
      package: package(),
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
      # Not `optional: true` even though only one of the two is used per build: the
      # `use` in `AshVaultRustler.Native` is chosen at COMPILE time from an environment
      # variable, so whichever one the switch picks has to already be there. See
      # `AshVaultRustler.Native` for the switch and the README for the release steps.
      {:rustler, "~> 0.38"},
      {:rustler_precompiled, "~> 0.8"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  # `checksum-Elixir.AshVaultRustler.Native.exs` is what makes a downloaded `.so`
  # verifiable rather than merely convenient, so it ships in the package and is committed
  # to the repo. Regenerate it with `mix nif.checksum` after a release build.
  defp package do
    [
      files: ~w(lib native/ashvault_nif/src native/ashvault_nif/Cargo.* .formatter.exs
                mix.exs README.md checksum-*.exs),
      licenses: ["MIT"]
    ]
  end

  defp aliases do
    [
      "nif.checksum": ["rustler_precompiled.download AshVaultRustler.Native --all --print"]
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
