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
      package: package(),
      docs: docs()
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "Source" => "https://github.com/jakeschurch/ash_vault",
        "Changelog" => "https://github.com/jakeschurch/ash_vault/blob/main/CHANGELOG.md"
      },
      # `documentation/internal/` is deliberately absent: design specs and review notes,
      # not shipped guides.
      files: ~w(
        lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*
        usage-rules.md usage-rules
        documentation/tutorials documentation/topics documentation/how-to documentation/adr
      )
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
        "documentation/topics/legacy-expand.md",
        "documentation/topics/two-vaults.md",
        "documentation/topics/searchable-fields.md",
        "documentation/topics/key-purposes-and-macs.md",
        "documentation/topics/macaroons.md",
        "documentation/topics/threat-model.md",
        "documentation/topics/operations.md",
        "documentation/how-to/openbao-in-kubernetes.md",
        "documentation/how-to/writing-a-key-provider.md",
        "documentation/how-to/writing-a-cipher.md",
        "documentation/how-to/writing-a-scope.md",
        "documentation/how-to/writing-a-rotation-policy.md",
        "documentation/adr/0001-no-cloak-vault.md",
        "documentation/adr/0002-distinguishable-crypto-errors.md",
        "README.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        Tutorials: ~r"documentation/tutorials/",
        Topics: ~r"documentation/topics/",
        "How-to": ~r"documentation/how-to/",
        "Design decisions": ~r"documentation/adr/"
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
          AshVault.Changes.MirrorLegacy,
          AshVault.Preparations.PreferVaultCopy,
          AshVault.DecryptFor,
          AshVault.Calculations.Decrypt,
          AshVault.Actions.RotateKey,
          AshVault.Actions.DestroyKeys,
          AshVault.Context.Builder,
          AshVault.Transformers.ExpandAttributes,
          AshVault.Transformers.SetupEncryption,
          AshVault.Transformers.SetupMacaroons,
          AshVault.Verifiers.VerifyVault,
          AshVault.Verifiers.VerifyMacaroons
        ],
        Macaroons: [
          AshVault.Macaroon,
          AshVault.Macaroon.Caveat,
          AshVault.Macaroon.Caveats.ActionIn,
          AshVault.Macaroon.Ttl,
          AshVault.Macaroon.KeyWindow,
          AshVault.Macaroon.CheckContext,
          AshVault.Macaroon.Verified,
          AshVault.Checks.MacaroonAllows,
          AshVault.Macaroon.Preparations.Verify,
          AshVault.Macaroon.Actions.Mint,
          AshVault.Macaroon.Runtime,
          AshVault.Macaroon.Envelope,
          AshVault.Macaroon.CaveatCodec,
          AshVault.Macaroon.Chain,
          AshVault.Macaroon.Clock,
          AshVault.Macaroon.Definition,
          AshVault.Macaroon.CaveatDefinition
        ],
        "Crypto core": [
          AshVault.Vault,
          AshVault.Vault.Runtime,
          AshVault.Context,
          AshVault.Cipher,
          AshVault.Ciphers.AES.GCM,
          AshVault.Mac,
          AshVault.Macs.HmacSha256,
          AshVault.Macs.OpenBaoTransit,
          AshVault.Envelope,
          AshVault.Envelope.V1
        ],
        "Key providers": [
          AshVault.KeyProvider,
          AshVault.KeyProviders.Memory,
          AshVault.KeyProviders.Local,
          AshVault.KeyProviders.OpenBao,
          AshVault.KeyProviders.OpenBao.KubernetesAuth
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
          AshVault.Errors.ProviderForbidden,
          AshVault.Errors.SerializationFailed,
          AshVault.Errors.UnsupportedCipher,
          AshVault.Errors.UnsupportedEnvelope,
          AshVault.Errors.InvalidMac,
          AshVault.Errors.PurposeUnsupported,
          AshVault.Errors.InvalidMacaroon,
          AshVault.Errors.MacaroonRevoked
        ]
      ]
    ]
  end

  # Aliases run in `:dev` unless told otherwise, and `mix test` refuses to run there, so
  # without this `mix test.all` and `mix test.ci` fail before running a single test.
  def cli do
    [preferred_envs: ["test.all": :test, "test.ci": :test]]
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
      # dev/test only: AshVault must never depend on it at runtime. It exists here so
      # the searchable-field compatibility claim can be proved, not assumed.
      {:ash_authentication, "~> 4.0", only: [:dev, :test]},
      {:cloak, "~> 1.1", only: [:dev, :test]},
      {:req, "~> 0.5"},
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:usage_rules, "~> 1.2", only: :dev, runtime: false}
    ]
  end
end
