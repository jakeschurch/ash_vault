defmodule AshVaultTest do
  use ExUnit.Case, async: true

  doctest AshVault

  describe "encrypted_field_name/1" do
    test "is the single source of the backing attribute naming scheme" do
      assert AshVault.encrypted_field_name(:email) == :encrypted_email
      assert AshVault.encrypted_field_name(:ssn) == :encrypted_ssn
    end
  end

  describe "extension wiring" do
    test "exposes the ash_vault section" do
      assert [%Spark.Dsl.Section{name: :ash_vault}] = AshVault.sections()
    end

    test "runs ExpandAttributes before SetupEncryption" do
      transformers = AshVault.transformers()

      assert AshVault.Transformers.ExpandAttributes in transformers
      assert AshVault.Transformers.SetupEncryption in transformers

      assert Enum.find_index(transformers, &(&1 == AshVault.Transformers.ExpandAttributes)) <
               Enum.find_index(transformers, &(&1 == AshVault.Transformers.SetupEncryption))
    end

    test "registers the vault verifier" do
      assert AshVault.Verifiers.VerifyVault in AshVault.verifiers()
    end
  end
end
