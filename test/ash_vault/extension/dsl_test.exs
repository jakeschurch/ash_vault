defmodule AshVault.Extension.DslTest do
  use ExUnit.Case, async: true

  alias AshVault.Encrypted
  alias AshVault.Test.Contact
  alias AshVault.Test.EtsNote
  alias AshVault.Test.Organization
  alias AshVault.Test.User

  describe "generated option readers" do
    test "reads the vault, scope and flags" do
      assert AshVault.Info.ash_vault_vault!(User) == AshVault.Test.Vault
      assert AshVault.Info.ash_vault_scope!(User) == :tenant
      assert AshVault.Info.ash_vault_encrypt_nil?(User)
      refute AshVault.Info.ash_vault_scope_owner?(User)
      assert AshVault.Info.ash_vault_decrypt_by_default!(User) == [:email]
    end

    test "key_lifecycle lives in its own nested section" do
      assert AshVault.Info.ash_vault_key_lifecycle_rotate(Organization) == {:ok, :rotate_key}
      assert AshVault.Info.ash_vault_key_lifecycle_destroy(Organization) == {:ok, :destroy_keys}
      assert AshVault.Info.ash_vault_scope_owner?(Organization)
    end

    test "entity reader is named after the section path, not the entity" do
      assert function_exported?(AshVault.Info, :ash_vault, 1)
      refute function_exported?(AshVault.Info, :ash_vault_encrypt, 1)
    end
  end

  describe "encrypted_fields/1" do
    test "returns explicit entities and expanded sugar, entities first" do
      assert AshVault.Info.encrypted_field_names(User) == [
               :email,
               :ssn,
               :profile,
               :contacts,
               :tags
             ]
    end

    test "carries per-field options" do
      assert %Encrypted{name: :ssn, encrypt_nil?: false} =
               AshVault.Info.encrypted_field(User, :ssn)

      assert %Encrypted{name: :email, encrypt_nil?: nil} =
               AshVault.Info.encrypted_field(User, :email)

      assert is_nil(AshVault.Info.encrypted_field(User, :name))
    end

    test "sugar-only resources expand too" do
      assert AshVault.Info.encrypted_field_names(Contact) == [:phone]
    end
  end

  describe "encrypt_nil?/2" do
    test "resolves the per-field override against the section default" do
      assert AshVault.Info.encrypt_nil?(User, :email)
      refute AshVault.Info.encrypt_nil?(User, :ssn)
    end
  end

  describe "scope_module/1" do
    test "maps the shorthands onto scope modules" do
      assert AshVault.Info.scope_module(User) == AshVault.Scopes.AshTenant
      assert AshVault.Info.scope_module(EtsNote) == AshVault.Scopes.Global
    end
  end

  describe "vault!/2" do
    test "returns a plain module unchanged" do
      assert AshVault.Info.vault!(User, %{}) == AshVault.Test.Vault
    end
  end
end
