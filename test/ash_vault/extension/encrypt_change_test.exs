defmodule AshVault.Extension.EncryptChangeTest do
  # Not async: the `AshVault.KeyProvider` callbacks take no server name, so every vault
  # talks to the default-named Memory provider. Each test starts a fresh one.
  use ExUnit.Case, async: false

  alias AshVault.Errors.MissingScope
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsNote
  alias AshVault.Test.EtsTicket
  alias AshVault.Test.EtsUser

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp create!(attrs, tenant \\ "acme") do
    EtsUser
    |> Ash.Changeset.for_create(
      :create,
      Map.merge(%{org_id: tenant, name: "n"}, Map.new(attrs)),
      tenant: tenant
    )
    |> Ash.create!()
  end

  describe "write path" do
    test "the ciphertext lands in the backing attribute, not a plaintext one" do
      user = create!(%{email: "a@b.c"})

      assert <<"AV", 1::8, _rest::binary>> = Map.get(user, :encrypted_email)
      refute Map.has_key?(user, :email) and is_binary(Map.get(user, :email))
    end

    test "round-trips scalars, arrays, embedded resources and arrays of embedded resources" do
      user =
        create!(%{
          email: "a@b.c",
          tags: ["x", "y"],
          profile: %{nickname: "nick", age: 7},
          contacts: [%{nickname: "c1", age: 1}, %{nickname: "c2", age: 2}]
        })

      loaded = Ash.load!(user, [:email, :tags, :profile, :contacts], tenant: "acme")

      assert loaded.email == "a@b.c"
      assert loaded.tags == ["x", "y"]
      assert loaded.profile.nickname == "nick"
      assert loaded.profile.age == 7
      assert Enum.map(loaded.contacts, & &1.nickname) == ["c1", "c2"]
    end

    test "a globally scoped resource round-trips too" do
      note = EtsNote |> Ash.Changeset.for_create(:create, %{body: "hello"}) |> Ash.create!()

      assert <<"AV", 1::8, _::binary>> = Map.get(note, :encrypted_body)
      assert Ash.load!(note, [:body]).body == "hello"
    end
  end

  describe "dynamic vaults" do
    test "a fun/2 vault is resolved on both paths, with the same normalized context" do
      Process.register(self(), :ash_vault_dynamic_vault_probe)

      user =
        AshVault.Test.EtsDynamicVaultUser
        |> Ash.Changeset.for_create(:create, %{org_id: "acme", email: "a@b.c"}, tenant: "acme")
        |> Ash.create!()

      assert_received {:dynamic_vault_context, write_context}

      assert Ash.load!(user, [:email], tenant: "acme").email == "a@b.c"

      assert_received {:dynamic_vault_context, read_context}

      for context <- [write_context, read_context] do
        assert is_map(context)
        refute is_struct(context)
        assert context.tenant == "acme"
        assert Map.has_key?(context, :actor)
        assert Map.has_key?(context, :source_context)
      end

      assert write_context.phase == :write
      assert read_context.phase == :read
    after
      Process.unregister(:ash_vault_dynamic_vault_probe)
    end
  end

  describe "nil handling" do
    test "encrypt_nil?: true stores a non-null ciphertext for nil" do
      user = create!(%{email: nil})

      assert is_binary(Map.get(user, :encrypted_email))
      assert Ash.load!(user, [:email], tenant: "acme").email == nil
    end

    test "encrypt_nil?: false stores NULL for nil and reads back nil" do
      user = create!(%{ssn: nil})

      assert is_nil(Map.get(user, :encrypted_ssn))
      assert Ash.load!(user, [:ssn], tenant: "acme").ssn == nil
    end

    test "encrypt_nil?: false still encrypts a present value" do
      user = create!(%{ssn: "123-45-6789"})

      assert <<"AV", 1::8, _::binary>> = Map.get(user, :encrypted_ssn)
      assert Ash.load!(user, [:ssn], tenant: "acme").ssn == "123-45-6789"
    end
  end

  describe "partial updates" do
    test "an absent argument leaves existing ciphertext untouched" do
      user = create!(%{email: "a@b.c", ssn: "123", tags: ["x"]})

      before_email = Map.get(user, :encrypted_email)
      before_tags = Map.get(user, :encrypted_tags)

      updated =
        user
        |> Ash.Changeset.for_update(:update, %{ssn: "456"}, tenant: "acme")
        |> Ash.update!()

      assert Map.get(updated, :encrypted_email) == before_email
      assert Map.get(updated, :encrypted_tags) == before_tags
      refute Map.get(updated, :encrypted_ssn) == Map.get(user, :encrypted_ssn)

      loaded = Ash.load!(updated, [:email, :ssn, :tags], tenant: "acme")
      assert loaded.email == "a@b.c"
      assert loaded.ssn == "456"
      assert loaded.tags == ["x"]
    end

    test "re-encrypting the same value produces different bytes (random nonce)" do
      user = create!(%{email: "a@b.c"})

      updated =
        user
        |> Ash.Changeset.for_update(:update, %{email: "a@b.c"}, tenant: "acme")
        |> Ash.update!()

      refute Map.get(updated, :encrypted_email) == Map.get(user, :encrypted_email)
      assert Ash.load!(updated, [:email], tenant: "acme").email == "a@b.c"
    end
  end

  describe "scrubbing" do
    test "change/3 removes the plaintext from arguments and params" do
      test_pid = self()

      EtsUser
      |> Ash.Changeset.for_create(:create, %{org_id: "acme", email: "a@b.c"}, tenant: "acme")
      |> Ash.Changeset.after_action(fn changeset, record ->
        send(test_pid, {:changeset, changeset})
        {:ok, record}
      end)
      |> Ash.create!()

      assert_received {:changeset, changeset}

      refute Map.has_key?(changeset.arguments, :email)
      refute Map.has_key?(changeset.params, :email)
      refute Map.has_key?(changeset.params, "email")
      refute inspect(changeset.arguments) =~ "a@b.c"
    end

    test "atomic/3 hands back a scrubbed changeset alongside the atomic map" do
      user = create!(%{email: "a@b.c"})

      changeset =
        Ash.Changeset.for_update(user, :update, %{email: "new@b.c"}, tenant: "acme")

      context = %Ash.Resource.Change.Context{
        actor: nil,
        tenant: "acme",
        authorize?: false,
        tracer: nil,
        source_context: %{}
      }

      assert {:atomic, scrubbed, %{encrypted_email: blob}} =
               AshVault.Changes.Encrypt.atomic(changeset, [field: :email], context)

      refute Map.has_key?(scrubbed.arguments, :email)
      refute Map.has_key?(scrubbed.params, :email)
      refute Map.has_key?(scrubbed.params, "email")
      refute inspect(scrubbed.arguments) =~ "new@b.c"

      assert <<"AV", 1::8, _::binary>> = blob
    end

    test "atomic/3 leaves the changeset alone when the argument is absent" do
      user = create!(%{email: "a@b.c"})

      changeset = Ash.Changeset.for_update(user, :update, %{ssn: "1"}, tenant: "acme")

      context = %Ash.Resource.Change.Context{
        actor: nil,
        tenant: "acme",
        authorize?: false,
        tracer: nil,
        source_context: %{}
      }

      assert {:ok, ^changeset} =
               AshVault.Changes.Encrypt.atomic(changeset, [field: :email], context)
    end
  end

  describe "error surfacing" do
    test "a missing tenant is a changeset error, not a raise out of before_action" do
      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               EtsTicket
               |> Ash.Changeset.for_create(:create, %{secret: "s3cret"})
               |> Ash.create()

      assert Enum.any?(errors, &match?(%MissingScope{}, &1))
    end

    test "the MissingScope message tells the operator what to do" do
      {:error, %Ash.Error.Invalid{errors: errors}} =
        EtsTicket
        |> Ash.Changeset.for_create(:create, %{secret: "s3cret"})
        |> Ash.create()

      message = errors |> Enum.find(&match?(%MissingScope{}, &1)) |> Exception.message()

      assert message =~ "no Ash tenant was present"
      assert message =~ "tenant-scoped encryption"
    end
  end

  describe "context construction" do
    test "source_context is refreshed from the changeset at hook-run time" do
      # `for_create` snapshots source_context before a caller can set_context/2, so the
      # change has to rebuild it inside the hook or this value never arrives.
      user =
        EtsUser
        |> Ash.Changeset.for_create(:create, %{org_id: "acme", email: "a@b.c"}, tenant: "acme")
        |> Ash.Changeset.set_context(%{late_addition: :arrived})
        |> Ash.Changeset.before_action(fn changeset ->
          context =
            AshVault.Context.Builder.from_changeset(changeset, :email, %{
              tenant: nil,
              actor: nil,
              source_context: changeset.context
            })

          send(self(), {:ash_context, context.ash_context})
          changeset
        end)
        |> Ash.create!()

      assert_received {:ash_context, ash_context}
      assert ash_context.source_context[:late_addition] == :arrived
      assert ash_context.tenant == "acme"
      assert ash_context.phase == :write
      assert is_struct(user)
    end
  end
end
