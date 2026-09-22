defmodule AshVault.MixProject do
  use Mix.Project

  def project do
    [
      app: :ash_vault,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),
      name: "AshVault",
      description:
        "Per-tenant encrypted attributes for Ash resources, with cryptographic erasure.",
      source_url: "https://github.com/jakeschurch/ash_vault",
      docs: docs()
    ]
  end

  defp docs do
    [
      main: "getting-started",
      extras: [
        "documentation/tutorials/getting-started.md",
        "documentation/topics/architecture.md",
        "documentation/topics/tenant-scoped-encryption.md",
        "documentation/topics/rotation.md",
        "documentation/topics/crypto-erasure.md",
        "documentation/topics/migrating-from-plaintext.md",
        "documentation/topics/two-vaults.md",
        "documentation/topics/searchable-fields.md",
        "documentation/topics/threat-model.md",
        "documentation/topics/operations.md",
        "documentation/how-to/writing-a-key-provider.md",
        "documentation/how-to/writing-a-cipher.md",
        "documentation/how-to/writing-a-scope.md",
        "documentation/how-to/writing-a-rotation-policy.md",
        "docs/adr/0001-no-cloak-vault.md",
        "docs/adr/0002-distinguishable-crypto-errors.md",
        "README.md"
      ],
      groups_for_extras: [
        Tutorials: ~r"documentation/tutorials/",
        Topics: ~r"documentation/topics/",
        "How-to": ~r"documentation/how-to/",
        "Design decisions": ~r"docs/adr/"
      ],
      groups_for_modules: [
        Extension: [
          AshVault,
          AshVault.Dsl,
          AshVault.Info,
          AshVault.Encrypted,
          AshVault.Serializer,
          AshVault.Telemetry
        ],
        "Extension internals": [
          AshVault.Changes.Encrypt,
          AshVault.Calculations.Decrypt,
          AshVault.Actions.RotateKey,
          AshVault.Actions.DestroyKeys,
          AshVault.Context.Builder,
          AshVault.Transformers.ExpandAttributes,
          AshVault.Transformers.SetupEncryption,
          AshVault.Verifiers.VerifyVault
        ],
        "Crypto core": [
          AshVault.Vault,
          AshVault.Vault.Runtime,
          AshVault.Context,
          AshVault.Cipher,
          AshVault.Ciphers.AES.GCM,
          AshVault.Envelope,
          AshVault.Envelope.V1
        ],
        "Key providers": [
          AshVault.KeyProvider,
          AshVault.KeyProviders.Memory,
          AshVault.KeyProviders.Local,
          AshVault.KeyProviders.OpenBao
        ],
        Scopes: [
          AshVault.Scope,
          AshVault.Scopes.AshTenant,
          AshVault.Scopes.Global
        ],
        Rotation: [
          AshVault.RotationPolicy,
          AshVault.RotationPolicies.Manual
        ],
        Migration: [
          AshVault.Backfill
        ],
        Errors: [
          AshVault.Errors,
          AshVault.Errors.CiphertextIntegrityFailed,
          AshVault.Errors.InvalidCiphertext,
          AshVault.Errors.InvalidScope,
          AshVault.Errors.KeyDestroyed,
          AshVault.Errors.KeyNotFound,
          AshVault.Errors.KeySizeMismatch,
          AshVault.Errors.MissingScope,
          AshVault.Errors.ProviderUnavailable,
          AshVault.Errors.SerializationFailed,
          AshVault.Errors.UnsupportedCipher,
          AshVault.Errors.UnsupportedEnvelope
        ]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {AshVault.Application, []}
    ]
  end

  defp aliases do
    [
      "test.all": ["test --include postgres --include openbao"],
      "test.ci": ["test"],
      "spark.formatter": "spark.formatter --extensions AshVault"
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
      {:simple_sat, "~> 0.1", only: [:dev, :test]},
      {:sourceror, "~> 1.0", only: [:dev, :test]},
      {:ash_cloak, "~> 0.1", only: [:dev, :test]},
      {:cloak, "~> 1.1", only: [:dev, :test]},
      {:req, "~> 0.5"},
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
