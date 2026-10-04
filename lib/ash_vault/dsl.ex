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

  A `macaroon` entity declares an attenuable bearer token for the resource's records;
  see `AshVault.Macaroon` and [Macaroons](macaroons.md).
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
        doc:
          "Also store a deterministic `<name>_lookup` HMAC token, so the field can be " <>
            "filtered on. Leaks equality within the scope — see `AshVault.Lookup`."
      ],
      unique?: [
        type: :boolean,
        default: false,
        doc: "Add a unique identity on the lookup token, per tenant. Requires `searchable?`."
      ],
      pre_check_with: [
        type: {:behaviour, Ash.Domain},
        doc:
          "Domain to pre-check the generated unique identity against, in a before_action " <>
            "hook. Required for `unique?: true` on a data layer that cannot enforce " <>
            "uniqueness itself (ETS, Mnesia); it costs a read on every write."
      ],
      normalize: [
        type: {:or, [{:in, [:none, :downcase, :downcase_trim]}, :mfa, {:fun, 1}]},
        default: :none,
        doc:
          "How a searchable value is normalized before hashing (and before encrypting). " <>
            "Changing it after rows exist invalidates every stored token."
      ],
      backfill_from: [
        type: :atom,
        doc: "Existing plaintext attribute to read during a migration backfill."
      ]
    ]
  }

  @caveat %Spark.Dsl.Entity{
    name: :caveat,
    describe: """
    Declare a caveat a token may carry. Every caveat a token carries must be declared,
    and every one must admit the request; see `AshVault.Macaroon.Caveat`.
    """,
    examples: [
      "caveat :ip, :string, check: MyApp.Caveats.Ip",
      """
      caveat :actions, {:array, :string},
        phase: :authorize,
        check: AshVault.Macaroon.Caveats.ActionIn
      """
    ],
    target: AshVault.Macaroon.CaveatDefinition,
    args: [:name, :type],
    identifier: :name,
    schema: [
      name: [type: :atom, required: true, doc: "The caveat's name, as it appears in tokens."],
      type: [
        type: :any,
        required: true,
        doc:
          "The value type: `:string`, `:integer`, `:boolean`, `:utc_datetime`, " <>
            "`:utc_datetime_usec`, `{:array, :string}` or `{:array, :integer}`."
      ],
      constraints: [type: :keyword_list, default: [], doc: "Constraints for casting on mint."],
      check: [
        type:
          {:spark_function_behaviour, AshVault.Macaroon.Caveat,
           {AshVault.Macaroon.Caveat.Function, 2}},
        required: true,
        doc:
          "An `AshVault.Macaroon.Caveat` module, `{module, opts}`, or a " <>
            "`fn value, check_context -> ... end`."
      ],
      phase: [
        type: {:in, [:verify, :authorize]},
        default: :verify,
        doc:
          "`:verify` checks run in the verifying read, once the record is loaded. " <>
            "`:authorize` checks run in `AshVault.Checks.MacaroonAllows`, against the " <>
            "action being authorized — and only there."
      ]
    ]
  }

  @macaroon %Spark.Dsl.Entity{
    name: :macaroon,
    describe: """
    Declare a macaroon: an attenuable bearer token naming one record of this resource,
    signed under the scope's `:mac` key. Generates a mint action and a verifying read
    action, each with a code interface. See [Macaroons](macaroons.md).
    """,
    examples: [
      """
      macaroon :api do
        prefix "myapp"
        identity :id
        revoked_when expr(not is_nil(revoked_at))
        default_ttl 86_400
        caveat :ip, :string, check: MyApp.Caveats.Ip
      end
      """
    ],
    target: AshVault.Macaroon.Definition,
    imports: [Ash.Expr],
    args: [:name],
    identifier: :name,
    entities: [caveats: [@caveat]],
    schema: [
      name: [type: :atom, required: true, doc: "The macaroon's name."],
      prefix: [
        type: :string,
        required: true,
        doc:
          "The token prefix: 2-32 characters of `[a-z][a-z0-9]*`. Make it distinctive " <>
            "so secret scanners can recognise a leaked token."
      ],
      identity: [
        type: :atom,
        required: true,
        doc:
          "How a token names its record: the (single) primary key attribute, or an " <>
            "identity with exactly one key."
      ],
      revoked_when: [
        type: :any,
        doc:
          "An expression over the record. The token verifies only while it evaluates " <>
            "to exactly `false`; `true`, `nil` or an error all revoke."
      ],
      default_ttl: [
        type: {:or, [:pos_integer, {:in, [:infinity]}]},
        required: true,
        doc: "Lifetime of a minted token in seconds, or `:infinity` for no expiry caveat."
      ],
      accepted_key_versions: [
        type: {:or, [:pos_integer, {:in, [:all]}]},
        default: 1,
        doc:
          "How many of the most recent `:mac` key versions are accepted. With the " <>
            "default `1`, rotating the scope's `:mac` keyring revokes every outstanding " <>
            "token of this macaroon in that scope."
      ],
      mint_action: [type: :atom, doc: "Name of the generated mint action. `:mint_<name>`."],
      read_action: [
        type: :atom,
        doc: "Name of the generated verifying read action. `:<name>_by_token`."
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
    entities: [@encrypt, @macaroon],
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
