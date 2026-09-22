defmodule AshVault.Extension.VerifierTest do
  # Not async: each test compiles a module.
  use ExUnit.Case, async: false

  defp define!(name, ash_vault_block, extra \\ "") do
    Code.eval_string("""
    defmodule #{name} do
      use Ash.Resource,
        domain: AshVault.Test.Domain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshVault]

      ash_vault do
    #{ash_vault_block}
      end

      attributes do
        uuid_primary_key :id
        attribute :email, :string, public?: true
        attribute :legacy_email, :string, public?: true
        attribute :name, :string, public?: true
      end

      actions do
        default_accept :*
        defaults [:read, :destroy, create: :*, update: :*]
      end

    #{extra}
    end
    """)
  end

  defp assert_dsl_error(message_fragment, fun) do
    error = assert_raise Spark.Error.DslError, fun
    assert Exception.message(error) =~ message_fragment
    error
  end

  # Verifiers run in `__verify_spark_dsl__/1` during Elixir's post-compilation module
  # check, so they surface as a checker diagnostic rather than an exception out of
  # `Code.eval_string/1`. Define the module (swallowing that diagnostic) and call the
  # verifier directly on its DSL state.
  defp verify(name, ash_vault_block, extra \\ "") do
    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      define!(name, ash_vault_block, extra)
    end)

    AshVault.Verifiers.VerifyVault.verify(name.spark_dsl_config())
  end

  defp assert_verifier_error(name, ash_vault_block, message_fragment, extra \\ "") do
    assert {:error, %Spark.Error.DslError{} = error} = verify(name, ash_vault_block, extra)
    assert Exception.message(error) =~ message_fragment
    error
  end

  describe "vault" do
    test "a module that is not an AshVault vault is rejected" do
      assert_verifier_error(
        Verify.BadVault,
        "    vault AshVault.Test.NotAVault\n    encrypt :email",
        "does not export encrypt!/2"
      )
    end

    test "a real vault is accepted" do
      assert :ok = verify(Verify.GoodVault, "    vault AshVault.Test.Vault\n    encrypt :email")
    end
  end

  describe "searchable fields" do
    test "a provider with no lookup_key/1 is rejected, naming the provider" do
      error =
        assert_verifier_error(
          Verify.NoLookupKey,
          "    vault AshVault.Test.Support.NoLookupVault\n" <>
            "    encrypt :email, searchable?: true",
          "does not implement `AshVault.KeyProvider.lookup_key/1`"
        )

      message = Exception.message(error)
      assert message =~ "AshVault.Test.Support.NoLookupProvider"
      assert message =~ "[:email]"
      # The message must say WHY the key is separate, not just that it is missing.
      assert message =~ "never the encryption key"
    end

    test "a provider that implements it is accepted" do
      assert :ok =
               verify(
                 Verify.WithLookupKey,
                 "    vault AshVault.Test.Vault\n    encrypt :email, searchable?: true"
               )
    end

    test "a non-searchable field on a provider with no lookup_key/1 is fine" do
      assert :ok =
               verify(
                 Verify.NoLookupKeyUnsearchable,
                 "    vault AshVault.Test.Support.NoLookupVault\n    encrypt :email"
               )
    end
  end

  describe "scope agreement" do
    test "a :global resource pointed at a tenant-scoped vault is rejected" do
      assert_verifier_error(
        Verify.ScopeMismatch,
        "    vault AshVault.Test.Vault\n    scope :global\n    encrypt :email",
        "rotation and cryptographic erasure act on the wrong keys"
      )
    end

    test "a non-default vault scope must be restated on the resource" do
      # Spark materializes schema defaults into the DSL state, so there is no way to tell
      # a written `scope :tenant` from the default one. AshVault chooses strictness: the
      # resource has to say which scope it is on when the vault is not on the default.
      assert_verifier_error(
        Verify.ScopeDefaulted,
        "    vault AshVault.Test.GlobalVault\n    encrypt :email",
        "rotation and cryptographic erasure act on the wrong keys"
      )
    end

    test "a :global resource with a globally-scoped vault is accepted" do
      assert :ok =
               verify(
                 Verify.ScopeAgrees,
                 "    vault AshVault.Test.GlobalVault\n    scope :global\n    encrypt :email"
               )
    end
  end

  describe "decrypt_by_default" do
    test "must name encrypted fields" do
      assert_verifier_error(
        Verify.BadDecryptByDefault,
        "    vault AshVault.Test.Vault\n    encrypt :email\n    decrypt_by_default [:name]",
        "is not an encrypted field"
      )
    end
  end

  describe "backfill_from" do
    test "must name an existing attribute" do
      assert_verifier_error(
        Verify.BadBackfill,
        "    vault AshVault.Test.Vault\n    encrypt :email, backfill_from: :nope",
        "does not name an existing attribute"
      )
    end

    test "an existing attribute is accepted" do
      assert :ok =
               verify(
                 Verify.GoodBackfill,
                 "    vault AshVault.Test.Vault\n    encrypt :email, backfill_from: :legacy_email"
               )
    end
  end

  describe "key_lifecycle" do
    test "requires scope_owner? true" do
      assert_verifier_error(
        Verify.LifecycleWithoutOwner,
        """
            vault AshVault.Test.Vault
            encrypt :email

            key_lifecycle do
              rotate :rotate_key
            end
        """,
        "requires `scope_owner? true`"
      )
    end
  end

  describe "transformer rejections" do
    test "an attribute that does not exist" do
      assert_dsl_error("No attribute called :nope found", fn ->
        define!(Verify.NoSuchAttribute, "    vault AshVault.Test.Vault\n    encrypt :nope")
      end)
    end

    test "a primary key attribute" do
      assert_dsl_error("cannot encrypt primary key attribute", fn ->
        define!(Verify.PrimaryKey, "    vault AshVault.Test.Vault\n    encrypt :id")
      end)
    end

    test "`unique?` without `searchable?`" do
      assert_dsl_error("requires `searchable?: true`", fn ->
        define!(Verify.Unique, "    vault AshVault.Test.Vault\n    encrypt :email, unique?: true")
      end)
    end

    test "a non-binary searchable field with no custom normalizer" do
      assert_dsl_error("needs a `normalize:` that returns a binary", fn ->
        Code.eval_string("""
        defmodule Verify.SearchableNonBinary do
          use Ash.Resource,
            domain: AshVault.Test.Domain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshVault]

          ash_vault do
            vault AshVault.Test.Vault
            encrypt :age, searchable?: true
          end

          attributes do
            uuid_primary_key :id
            attribute :age, :integer, public?: true
          end

          actions do
            default_accept :*
            defaults [:read, :destroy, create: :*, update: :*]
          end
        end
        """)
      end)
    end

    test "an existing <field>_lookup sibling attribute" do
      assert_dsl_error("email_lookup sibling attribute", fn ->
        Code.eval_string("""
        defmodule Verify.LookupSibling do
          use Ash.Resource,
            domain: AshVault.Test.Domain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshVault]

          ash_vault do
            vault AshVault.Test.Vault
            encrypt :email, searchable?: true
          end

          attributes do
            uuid_primary_key :id
            attribute :email, :string, public?: true
            attribute :email_lookup, :binary, public?: true
          end

          actions do
            default_accept :*
            defaults [:read, :destroy, create: :*, update: :*]
          end
        end
        """)
      end)
    end

    test "duplicate encrypt entries" do
      assert_dsl_error("duplicate `encrypt` entries", fn ->
        define!(
          Verify.Duplicate,
          "    vault AshVault.Test.Vault\n    encrypt :email\n    encrypt :email"
        )
      end)
    end

    test "an existing encrypted_ sibling attribute" do
      assert_dsl_error("sibling attribute", fn ->
        Code.eval_string("""
        defmodule Verify.ExistingSibling do
          use Ash.Resource,
            domain: AshVault.Test.Domain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshVault]

          ash_vault do
            vault AshVault.Test.Vault
            encrypt :email
          end

          attributes do
            uuid_primary_key :id
            attribute :email, :string, public?: true
            attribute :encrypted_email, :binary, public?: true
          end

          actions do
            default_accept :*
            defaults [:read, :destroy, create: :*, update: :*]
          end
        end
        """)
      end)
    end
  end

  # Encrypting an attribute silently voids guarantees the rest of the resource declared
  # on it. These are the two constructs neither Ash nor AshPostgres catches.
  describe "constructs an encrypted attribute voids" do
    # Postgres, not ETS, and deliberately so: an ETS resource happens to fail on this
    # shape via `Ash.DataLayer.Verifiers.RequirePreCheckWith`, which needs an identity to
    # declare `pre_check_with`. Postgres enforces identities with a real unique index and
    # needs no pre-check, so it is the Postgres shape that compiles silently — and the
    # one a real application has.
    defp define_postgres!(name, body) do
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.eval_string("""
        defmodule #{name} do
          use Ash.Resource,
            domain: AshVault.Test.Domain,
            data_layer: AshPostgres.DataLayer,
            extensions: [AshVault],
            validate_domain_inclusion?: false

          ash_vault do
            vault AshVault.Test.Vault
            scope :tenant
            encrypt :email
          end

          attributes do
            uuid_primary_key :id
            attribute :org_id, :uuid, allow_nil?: false, public?: true
            attribute :email, :string, public?: true
          end

          actions do
            default_accept :*
            defaults [:read, create: :*]
          end

        #{body}
        end
        """)
      end)

      name.spark_dsl_config()
    end

    test "a unique identity on the encrypted attribute is rejected" do
      dsl =
        define_postgres!(Verify.PlaintextIdentity, """
          postgres do
            table "search_users"
            repo AshVault.Test.Repo
          end

          identities do
            identity :unique_email, [:email]
          end
        """)

      # The construct really is invisible to Ash: its own identity verifier accepts the
      # key because `:email` is a calculation now
      # (deps/ash/lib/ash/resource/verifiers/verify_identities.ex:16). If this ever starts
      # returning an error, AshVault's check has become redundant.
      assert :ok = Ash.Resource.Verifiers.VerifyIdentityFields.verify(dsl)

      assert {:error, %Spark.Error.DslError{} = error} =
               AshVault.Verifiers.VerifyVault.verify(dsl)

      message = Exception.message(error)
      assert message =~ "identity :unique_email, [:email]"
      assert message =~ "enforces nothing"
      assert message =~ "searchable?: true, unique?: true"
      assert message =~ "email_lookup"
      assert error.path == [:identities, :unique_email]
    end

    test "the identity AshVault generates for unique?: true does not trip the check" do
      # `SearchUser` is `encrypt :email, searchable?: true, unique?: true`, so it carries a
      # generated `:email_lookup_unique` identity. Keyed on the token, never the field.
      assert :ok =
               AshVault.Verifiers.VerifyVault.verify(AshVault.Test.SearchUser.spark_dsl_config())

      assert [:email_lookup] ==
               AshVault.Test.SearchUser
               |> Ash.Resource.Info.identity(:email_lookup_unique)
               |> Map.fetch!(:keys)
    end

    test "a postgres custom index on the encrypted attribute is rejected" do
      dsl =
        define_postgres!(Verify.PlaintextCustomIndex, """
          postgres do
            table "search_users"
            repo AshVault.Test.Repo

            custom_indexes do
              index [:email], unique: true
            end
          end
        """)

      assert {:error, %Spark.Error.DslError{} = error} =
               AshVault.Verifiers.VerifyVault.verify(dsl)

      message = Exception.message(error)
      assert message =~ "custom index"
      assert message =~ "[:email]"
      assert message =~ "fresh nonce per write"
      assert message =~ "email_lookup"
      assert error.path == [:postgres, :custom_indexes]
    end

    test "a custom index on an untouched column is fine" do
      dsl =
        define_postgres!(Verify.CleanCustomIndex, """
          postgres do
            table "search_users"
            repo AshVault.Test.Repo

            custom_indexes do
              index [:org_id]
            end
          end
        """)

      assert :ok = AshVault.Verifiers.VerifyVault.verify(dsl)
    end

    # Not AshVault's to catch — asserted here so that if Ash ever stops catching them,
    # this suite says so rather than the gap reopening silently.
    test "a relationship source_attribute is already caught by Ash" do
      dsl =
        define_postgres!(Verify.PlaintextRelationship, """
          postgres do
            table "search_users"
            repo AshVault.Test.Repo
          end

          relationships do
            belongs_to :org, AshVault.Test.Organization,
              source_attribute: :email,
              destination_attribute: :id,
              attribute_type: :string,
              define_attribute?: false
          end
        """)

      error =
        assert_raise Spark.Error.DslError, fn ->
          Ash.Resource.Verifiers.ValidateRelationshipAttributes.verify(dsl)
        end

      assert Exception.message(error) =~ "expects source attribute `email` to be defined"
    end

    test "the multitenancy attribute is already caught by Ash" do
      dsl =
        define_postgres!(Verify.PlaintextTenantAttribute, """
          postgres do
            table "search_users"
            repo AshVault.Test.Repo
          end

          multitenancy do
            strategy :attribute
            attribute :email
          end
        """)

      assert {:error, %Spark.Error.DslError{} = error} =
               Ash.Resource.Verifiers.ValidateMultitenancy.verify(dsl)

      assert Exception.message(error) =~
               "Attribute email used in multitenancy configuration does not exist"
    end
  end
end
