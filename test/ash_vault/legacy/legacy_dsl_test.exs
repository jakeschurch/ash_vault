defmodule AshVault.Legacy.LegacyDslTest do
  # Not async: each test compiles a module.
  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory

  defp source(name, encrypt, actions, attributes \\ "") do
    """
    defmodule #{name} do
      use Ash.Resource,
        domain: AshVault.Test.Domain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshVault]

      ash_vault do
        vault AshVault.Test.GlobalVault
        scope :global
        #{encrypt}
      end

      attributes do
        uuid_primary_key :id
        attribute :name, :string, public?: true
        attribute :token, :binary, public?: true
        #{attributes}
      end

      identities do
        identity :unique_name, [:name], pre_check_with: AshVault.Test.Domain
      end

      actions do
        default_accept :*
        defaults [:read, :destroy, create: :*]
        #{actions}
      end
    end
    """
  end

  defp verify(name, encrypt, actions, attributes \\ "") do
    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      Code.eval_string(source(name, encrypt, actions, attributes))
    end)

    AshVault.Verifiers.VerifyVault.verify(name.spark_dsl_config())
  end

  defp assert_verifier_error(name, encrypt, actions, fragment) do
    assert {:error, %Spark.Error.DslError{} = error} = verify(name, encrypt, actions)
    assert Exception.message(error) =~ fragment
  end

  @legacy "encrypt :token, legacy: AshVault.Test.LegacyBinary"

  test "an expression write to the legacy attribute is a compile-time error" do
    assert_verifier_error(
      AshVault.LegacyDsl.Expression,
      @legacy,
      """
      update :bump do
        change atomic_update(:token, expr(token))
      end
      """,
      "cannot be encrypted from an expression"
    )
  end

  test "an upsert that keeps the ciphertext on conflict is a compile-time error" do
    assert_verifier_error(
      AshVault.LegacyDsl.StaleUpsert,
      @legacy,
      """
      create :upsert do
        upsert? true
        upsert_identity :unique_name
        upsert_fields {:replace_all_except, [:encrypted_vault_token]}
      end
      """,
      "the AshVault copy would go stale"
    )
  end

  test "an upsert listing only the legacy column gets the ciphertext column added" do
    assert :ok =
             verify(
               AshVault.LegacyDsl.Upsert,
               @legacy,
               """
               create :upsert do
                 upsert? true
                 upsert_identity :unique_name
                 upsert_fields [:token]
               end
               """
             )

    assert Ash.Resource.Info.action(AshVault.LegacyDsl.Upsert, :upsert).upsert_fields ==
             [:token, :encrypted_vault_token]
  end

  test "stored_as without legacy is refused" do
    assert_verifier_error(
      AshVault.LegacyDsl.StoredAsAlone,
      "encrypt :token, stored_as: :vault_token",
      "",
      "only supported together with `legacy:`"
    )
  end

  test "a hand-declared AshVault copy is refused: AshVault owns it" do
    error =
      assert_raise Spark.Error.DslError, fn ->
        ExUnit.CaptureIO.capture_io(:stderr, fn ->
          Code.eval_string(
            source(
              AshVault.LegacyDsl.HandDeclared,
              @legacy,
              "",
              "attribute :vault_token, :binary"
            )
          )
        end)
      end

    assert Exception.message(error) =~ "AshVault owns the AshVault copy"
  end

  describe "decrypt_for without legacy (end state)" do
    setup do
      start_supervised!({Memory, name: Memory})
      :ok
    end

    test "admitted actors decrypt; everyone else gets a forbidden field" do
      record =
        AshVault.Test.EtsDecryptForDoc
        |> Ash.Changeset.for_create(:create, %{token: "secret"})
        |> Ash.create!()

      admin = %AshVault.Test.Admin{role: :admin}
      member = %AshVault.Test.Admin{role: :member}

      assert Ash.load!(record, :token, actor: admin).token == "secret"
      assert %Ash.ForbiddenField{} = Ash.load!(record, :token, actor: member).token
      assert %Ash.ForbiddenField{} = Ash.load!(record, :token, actor: nil, authorize?: true).token
      assert Ash.load!(record, :token, authorize?: false).token == "secret"
    end
  end
end
