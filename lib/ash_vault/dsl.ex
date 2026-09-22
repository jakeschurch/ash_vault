defmodule AshVault.Dsl do
  @moduledoc """
  The `ash_vault` DSL section, as consumed by `use Spark.Dsl.Extension` in `AshVault`.

      use Ash.Resource, extensions: [AshVault]

      ash_vault do
        vault MyApp.Vault
        scope :tenant

        encrypt :email
        encrypt :ssn, encrypt_nil?: false

        decrypt_by_default [:email]
      end

  `attributes [:email, :ssn]` is sugar for a list of `encrypt` entities with default
  options; `AshVault.Transformers.ExpandAttributes` expands it.
  """

  @encrypt %Spark.Dsl.Entity{
    name: :encrypt,
    describe: "Encrypt a single attribute of this resource.",
    examples: ["encrypt :email", "encrypt :ssn, encrypt_nil?: false"],
    target: AshVault.Encrypted,
    args: [:name],
    schema: [
      name: [type: :atom, required: true, doc: "The attribute to encrypt."],
      encrypt_nil?: [
        type: :boolean,
        doc: "Encrypt `nil` instead of storing SQL NULL. Defaults to the section-level setting."
      ],
      searchable?: [
        type: :boolean,
        default: false,
        doc: "Also store a keyed HMAC lookup token. Post-v1; rejected by the verifier for now."
      ],
      unique?: [
        type: :boolean,
        default: false,
        doc: "Add a unique identity on the lookup token. Requires `searchable?`. Post-v1."
      ],
      backfill_from: [
        type: :atom,
        doc: "Existing plaintext attribute to read during a migration backfill."
      ]
    ]
  }

  @key_lifecycle %Spark.Dsl.Section{
    name: :key_lifecycle,
    describe: "Generate generic actions for key rotation and cryptographic erasure.",
    schema: [
      rotate: [type: :atom, doc: "Name of a generic action that rotates this scope's key."],
      destroy: [type: :atom, doc: "Name of a generic action that destroys this scope's keys."]
    ]
  }

  @ash_vault %Spark.Dsl.Section{
    name: :ash_vault,
    describe: "Configure encrypted attributes for this resource.",
    entities: [@encrypt],
    sections: [@key_lifecycle],
    schema: [
      vault: [
        type: {:or, [{:behaviour, AshVault.Vault}, :mfa, {:fun, 2}]},
        required: true,
        doc:
          "The vault to encrypt and decrypt with. A module using `AshVault.Vault`, an MFA, " <>
            "or a `fun/2` of `(resource, context) -> vault_module`."
      ],
      scope: [
        type: {:or, [{:in, [:tenant, :global]}, {:behaviour, AshVault.Scope}]},
        default: :tenant,
        doc:
          "The *key* scope: `:tenant` (`AshVault.Scopes.AshTenant`), `:global` " <>
            "(`AshVault.Scopes.Global`), or an `AshVault.Scope` module. Unrelated to `Ash.Scope`."
      ],
      attributes: [
        type: {:wrap_list, :atom},
        default: [],
        doc: "Shorthand for a list of `encrypt` entities with default options."
      ],
      decrypt_by_default: [
        type: {:wrap_list, :atom},
        default: [],
        doc: "Encrypted fields whose decrypt calculation is loaded automatically."
      ],
      encrypt_nil?: [
        type: :boolean,
        default: true,
        doc: "Encrypt `nil` rather than storing SQL NULL. Overridable per field."
      ],
      scope_owner?: [
        type: :boolean,
        default: false,
        doc:
          "This resource *is* the scope (the tenant/organization). Required for `key_lifecycle`."
      ]
    ]
  }

  @doc "The `ash_vault` section definition."
  @spec sections() :: [Spark.Dsl.Section.t()]
  def sections, do: [@ash_vault]
end
