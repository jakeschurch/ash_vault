defmodule AshVault.Extension.TransformerTest do
  use ExUnit.Case, async: true

  alias AshVault.Test.Contact
  alias AshVault.Test.Organization
  alias AshVault.Test.User

  describe "attribute replacement" do
    test "the plaintext attribute is gone — there is no column to write" do
      for field <- [:email, :ssn, :profile, :tags, :contacts] do
        assert is_nil(Ash.Resource.Info.attribute(User, field)),
               "#{field} is still an attribute; the data layer could persist plaintext"
      end
    end

    test "the backing ciphertext attribute is private, sensitive and always nullable" do
      attribute = Ash.Resource.Info.attribute(User, :encrypted_email)

      assert attribute.type == Ash.Type.Binary
      refute attribute.public?
      assert attribute.sensitive?
      assert attribute.allow_nil?
      assert attribute.description == "Encrypted email"
    end

    test "allow_nil? is true even for a non-nullable source attribute" do
      # Deviation from ash_cloak, which copies attribute.allow_nil? onto the column and
      # so cannot support `encrypt_nil?: false` on a non-nullable attribute.
      assert Ash.Resource.Info.attribute(User, :encrypted_ssn).allow_nil?
    end
  end

  describe "decrypt calculation" do
    test "keeps the original name, type and constraints" do
      calculation = Ash.Resource.Info.calculation(User, :email)

      assert calculation.type == Ash.Type.String
      assert calculation.constraints == [trim?: true, allow_empty?: false]

      assert calculation.calculation ==
               {AshVault.Calculations.Decrypt, [field: :encrypted_email, plain_field: :email]}
    end

    test "is sensitive and neither filterable nor sortable" do
      calculation = Ash.Resource.Info.calculation(User, :email)

      assert calculation.sensitive?
      refute calculation.filterable?
      refute calculation.sortable?
    end

    test "carries the array and embedded types through unchanged" do
      assert Ash.Resource.Info.calculation(User, :tags).type == {:array, Ash.Type.String}
      assert Ash.Resource.Info.calculation(User, :profile).type == AshVault.Test.Profile

      assert Ash.Resource.Info.calculation(User, :contacts).type ==
               {:array, AshVault.Test.Profile}
    end

    test "multitenancy stays at the default (:enforce)" do
      assert is_nil(Ash.Resource.Info.calculation(User, :email).multitenancy)
    end
  end

  describe "action rewriting" do
    # This is the load-bearing test. `SetupEncryption` must run AFTER
    # `Ash.Resource.Transformers.DefaultAccept`, or `attr.name in action.accept` is false
    # everywhere and zero actions get rewritten. And `replace_entity/4` uses
    # `Map.replace_lazy`, so it silently no-ops when the section path key is absent.
    # Either failure mode leaves `accept` intact, which is exactly what this asserts against.
    test "every accepting action lost the attribute and gained the argument and change" do
      for action_name <- [:create, :update, :update_atomic],
          field <- [:email, :ssn, :profile, :tags, :contacts] do
        action = Ash.Resource.Info.action(User, action_name)

        refute field in action.accept,
               "#{action_name} still accepts #{field}: the transformer did not run or " <>
                 "replace_entity/4 silently no-opped"

        assert Enum.any?(action.arguments, &(&1.name == field)),
               "#{action_name} has no #{field} argument"

        assert Enum.any?(action.changes, fn change ->
                 change.change == {AshVault.Changes.Encrypt, [field: field]}
               end),
               "#{action_name} did not receive the encrypt change for #{field}"
      end
    end

    test "the argument is sensitive, so plaintext never reaches inspect or error messages" do
      argument =
        User
        |> Ash.Resource.Info.action(:create)
        |> Map.fetch!(:arguments)
        |> Enum.find(&(&1.name == :email))

      assert argument.sensitive?
      assert argument.type == Ash.Type.String
      assert argument.constraints == [trim?: true, allow_empty?: false]
    end

    test "non-encrypted attributes keep their place in accept" do
      action = Ash.Resource.Info.action(User, :create)

      assert :name in action.accept
      assert :org_id in action.accept
    end

    test "transformer ordering is declared against DefaultAccept" do
      assert AshVault.Transformers.SetupEncryption.after?(Ash.Resource.Transformers.DefaultAccept)
      refute AshVault.Transformers.SetupEncryption.after?(SomeOtherTransformer)

      assert AshVault.Transformers.ExpandAttributes.before?(AshVault.Transformers.SetupEncryption)
    end
  end

  describe "attributes sugar" do
    test "is expanded into a real entity and rewrites actions like any other" do
      assert is_nil(Ash.Resource.Info.attribute(Contact, :phone))
      assert Ash.Resource.Info.attribute(Contact, :encrypted_phone)
      assert Ash.Resource.Info.calculation(Contact, :phone)

      action = Ash.Resource.Info.action(Contact, :create)
      refute :phone in action.accept
      assert Enum.any?(action.arguments, &(&1.name == :phone))
    end
  end

  describe "decrypt_by_default" do
    test "adds a resource-level Load change and Build preparation" do
      assert Enum.any?(Ash.Resource.Info.changes(User), fn change ->
               change.change == {Ash.Resource.Change.Load, target: [:email]}
             end)

      assert Enum.any?(Ash.Resource.Info.preparations(User), fn preparation ->
               preparation.preparation ==
                 {Ash.Resource.Preparation.Build, options: [load: [:email]]}
             end)
    end

    test "is not added when the list is empty" do
      refute Enum.any?(Ash.Resource.Info.changes(Contact), fn change ->
               match?({Ash.Resource.Change.Load, _}, change.change)
             end)
    end
  end

  describe "key_lifecycle actions" do
    test "generic actions are generated on the scope owner" do
      rotate = Ash.Resource.Info.action(Organization, :rotate_key)
      destroy = Ash.Resource.Info.action(Organization, :destroy_keys)

      assert rotate.type == :action
      assert rotate.run == {AshVault.Actions.RotateKey, []}
      assert rotate.returns == Ash.Type.Integer

      assert destroy.type == :action
      assert destroy.run == {AshVault.Actions.DestroyKeys, []}

      # Deliberately not `Ash.Type.Atom` returning `:ok`, which `Ash.run_action/1`
      # wrapped into the eyebrow-raising `{:ok, :ok}`.
      assert destroy.returns == Ash.Type.Struct
      assert destroy.constraints[:instance_of] == AshVault.Erasure
    end

    test "no lifecycle actions on a resource that is not the scope owner" do
      assert is_nil(Ash.Resource.Info.action(User, :rotate_key))
      assert is_nil(Ash.Resource.Info.action(User, :destroy_keys))
    end
  end
end
