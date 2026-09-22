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
end
