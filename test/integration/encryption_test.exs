defmodule AshVault.Integration.EncryptionTest do
  @moduledoc """
  The EXTENSION_SPEC §11 acceptance tests, against a real PostgreSQL.
  """

  use ExUnit.Case, async: false

  @moduletag :postgres

  alias AshVault.Errors.AuthenticationFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Contact
  alias AshVault.Test.Db
  alias AshVault.Test.Repo
  alias AshVault.Test.User

  @acme "11111111-1111-1111-1111-111111111111"
  @other "22222222-2222-2222-2222-222222222222"

  setup do
    start_supervised!({Memory, name: Memory})
    Db.reset!()
    :ok
  end

  defp create!(attrs, tenant \\ @acme) do
    User
    |> Ash.Changeset.for_create(
      :create,
      Map.merge(%{org_id: tenant, name: "n"}, Map.new(attrs)),
      tenant: tenant,
      authorize?: false
    )
    |> Ash.create!()
  end

  defp read!(tenant \\ @acme, load \\ [:email]) do
    User
    |> Ash.Query.load(load)
    |> Ash.read!(tenant: tenant, authorize?: false)
  end

  defp raw(sql, params \\ []) do
    Repo.query!(sql, params).rows
  end

  describe "round trip" do
    test "create then read returns the plaintext" do
      create!(%{email: "a@b.c"})

      assert [%{email: "a@b.c"}] = read!()
    end

    test "embedded, array and array-of-embedded attributes round-trip" do
      create!(%{
        email: "a@b.c",
        profile: %{nickname: "nick", age: 7},
        tags: ["x", "y"],
        contacts: [%{nickname: "c1", age: 1}, %{nickname: "c2", age: 2}]
      })

      [user] = read!(@acme, [:email, :profile, :tags, :contacts])

      assert user.profile.nickname == "nick"
      assert user.profile.age == 7
      assert user.tags == ["x", "y"]
      assert Enum.map(user.contacts, & &1.nickname) == ["c1", "c2"]
    end

    test "decrypt_by_default loads :email without an explicit load" do
      create!(%{email: "a@b.c"})

      assert [%{email: "a@b.c"}] = Ash.read!(User, tenant: @acme, authorize?: false)
    end
  end

  describe "what is actually on disk" do
    test "the column holds an AshVault envelope and no trace of the plaintext" do
      plaintext = "supersecret@example.com"
      ssn = "123-45-6789"
      create!(%{email: plaintext, ssn: ssn})

      [[email_blob, ssn_blob]] = raw("SELECT encrypted_email, encrypted_ssn FROM users")

      assert <<"AV", 1::8, _rest::binary>> = email_blob
      assert <<"AV", 1::8, _rest::binary>> = ssn_blob

      refute email_blob =~ plaintext
      refute ssn_blob =~ ssn
      refute email_blob =~ "supersecret"
      refute email_blob =~ "example.com"
    end

    test "there is no plaintext column at all" do
      assert [] =
               raw(
                 "SELECT column_name FROM information_schema.columns " <>
                   "WHERE table_name = 'users' AND column_name IN ('email', 'ssn', 'profile', 'tags', 'contacts')"
               )
    end

    test "the whole table dumps without leaking the plaintext" do
      create!(%{email: "needle@example.com", tags: ["needle-tag"]})

      dump =
        raw("SELECT users::text FROM users")
        |> List.flatten()
        |> Enum.join()

      refute dump =~ "needle@example.com"
      refute dump =~ "needle-tag"
    end
  end

  describe "updates" do
    test "updating one field leaves the others' ciphertext byte-identical" do
      user = create!(%{email: "a@b.c", ssn: "123", tags: ["x"]})

      [[before_email, before_tags]] = raw("SELECT encrypted_email, encrypted_tags FROM users")

      user
      |> Ash.Changeset.for_update(:update, %{ssn: "456"}, tenant: @acme, authorize?: false)
      |> Ash.update!()

      [[after_email, after_tags]] = raw("SELECT encrypted_email, encrypted_tags FROM users")

      assert after_email == before_email
      assert after_tags == before_tags
      assert [%{email: "a@b.c", ssn: "456"}] = read!(@acme, [:email, :ssn])
    end

    test "a partial update does not clobber ciphertext" do
      user = create!(%{email: "a@b.c", ssn: "123"})

      user
      |> Ash.Changeset.for_update(:update, %{name: "renamed"}, tenant: @acme, authorize?: false)
      |> Ash.update!()

      assert [%{email: "a@b.c", ssn: "123", name: "renamed"}] = read!(@acme, [:email, :ssn])
    end

    test "the atomic update path encrypts and round-trips too" do
      user = create!(%{email: "a@b.c"})

      user
      |> Ash.Changeset.for_update(:update_atomic, %{email: "new@b.c"},
        tenant: @acme,
        authorize?: false
      )
      |> Ash.update!()

      [[blob]] = raw("SELECT encrypted_email FROM users")
      assert <<"AV", 1::8, _::binary>> = blob
      refute blob =~ "new@b.c"

      assert [%{email: "new@b.c"}] = read!()
    end
  end

  describe "nil handling" do
    test "encrypt_nil?: true writes a non-NULL ciphertext" do
      create!(%{email: nil})

      assert [[blob]] = raw("SELECT encrypted_email FROM users")
      assert <<"AV", 1::8, _::binary>> = blob
      assert [%{email: nil}] = read!()
    end

    test "encrypt_nil?: false writes SQL NULL and reads back nil" do
      create!(%{ssn: nil})

      assert [[nil]] = raw("SELECT encrypted_ssn FROM users")
      assert [%{ssn: nil}] = read!(@acme, [:ssn])
    end
  end

  describe "tenancy" do
    test "each tenant reads its own value" do
      create!(%{email: "acme@b.c"}, @acme)
      create!(%{email: "other@b.c"}, @other)

      assert [%{email: "acme@b.c"}] = read!(@acme)
      assert [%{email: "other@b.c"}] = read!(@other)
    end

    test "one tenant key spans resources, but the AAD still separates their ciphertext" do
      create!(%{email: "a@b.c"}, @acme)

      contact =
        Contact
        |> Ash.Changeset.for_create(:create, %{org_id: @acme, phone: "555-0100"}, tenant: @acme)
        |> Ash.create!()

      assert Ash.load!(contact, [:phone], tenant: @acme).phone == "555-0100"

      # Same key scope, different AAD: moving one blob into the other fails.
      [[email_blob]] = raw("SELECT encrypted_email FROM users")
      raw("UPDATE contacts SET encrypted_phone = $1", [email_blob])

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               Contact |> Ash.Query.load([:phone]) |> Ash.read(tenant: @acme)

      assert Enum.any?(errors, &match?(%AuthenticationFailed{}, &1))
    end
  end

  describe "ciphertext substitution" do
    test "cross-tenant substitution fails with AuthenticationFailed" do
      create!(%{email: "acme@b.c"}, @acme)
      create!(%{email: "other@b.c"}, @other)

      [[other_blob]] = raw("SELECT encrypted_email FROM users WHERE org_id = $1", [uuid(@other)])

      raw("UPDATE users SET encrypted_email = $1 WHERE org_id = $2", [other_blob, uuid(@acme)])

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               User |> Ash.Query.load([:email]) |> Ash.read(tenant: @acme, authorize?: false)

      assert Enum.any?(errors, &match?(%AuthenticationFailed{}, &1))
      refute Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
    end

    test "cross-field substitution fails with AuthenticationFailed" do
      create!(%{email: "a@b.c", ssn: "123-45-6789"})

      raw("UPDATE users SET encrypted_email = encrypted_ssn")

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               User |> Ash.Query.load([:email]) |> Ash.read(tenant: @acme, authorize?: false)

      assert Enum.any?(errors, &match?(%AuthenticationFailed{}, &1))
    end
  end

  describe "cryptographic erasure" do
    test "a destroyed tenant reads back KeyDestroyed while others keep working" do
      create!(%{email: "acme@b.c"}, @acme)
      create!(%{email: "other@b.c"}, @other)

      :ok = AshVault.destroy_keys!(AshVault.Test.Vault, @acme)

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               User |> Ash.Query.load([:email]) |> Ash.read(tenant: @acme, authorize?: false)

      assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
      refute Enum.any?(errors, &match?(%AuthenticationFailed{}, &1))

      assert [%{email: "other@b.c"}] = read!(@other)
    end

    test "the rows are still there — only the key is gone" do
      create!(%{email: "acme@b.c"}, @acme)
      :ok = AshVault.destroy_keys!(AshVault.Test.Vault, @acme)

      assert [[1]] = raw("SELECT count(*) FROM users")
    end
  end

  describe "key_lifecycle actions" do
    test "rotate mints a new key version; old rows keep decrypting" do
      create!(%{email: "before@b.c"}, @acme)
      [[before_blob]] = raw("SELECT encrypted_email FROM users")
      assert {:ok, %{key_version: 1}} = AshVault.Envelope.decode(before_blob)

      assert {:ok, 2} =
               AshVault.Test.Organization
               |> Ash.ActionInput.for_action(:rotate_key, %{}, tenant: @acme)
               |> Ash.run_action()

      after_user = create!(%{email: "after@b.c"}, @acme)

      [[after_blob]] =
        raw("SELECT encrypted_email FROM users WHERE id = $1", [uuid(after_user.id)])

      assert {:ok, %{key_version: 2}} = AshVault.Envelope.decode(after_blob)

      # The pre-rotation row still carries version 1 and still decrypts.
      assert {:ok, %{key_version: 1}} = AshVault.Envelope.decode(before_blob)

      emails = read!() |> Enum.map(& &1.email) |> Enum.sort()
      assert emails == ["after@b.c", "before@b.c"]
    end

    test "destroy_keys crypto-erases the scope" do
      create!(%{email: "a@b.c"}, @acme)

      assert {:ok, :ok} =
               AshVault.Test.Organization
               |> Ash.ActionInput.for_action(:destroy_keys, %{}, tenant: @acme)
               |> Ash.run_action()

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               User |> Ash.Query.load([:email]) |> Ash.read(tenant: @acme, authorize?: false)

      assert Enum.any?(errors, &match?(%KeyDestroyed{}, &1))
    end
  end

  describe "field policies" do
    test "denying the decrypted field leaves the rest of the record readable" do
      create!(%{email: "a@b.c", ssn: "123"})

      assert {:ok, [user]} =
               User
               |> Ash.Query.load([:email, :ssn])
               |> Ash.read(tenant: @acme, actor: %{admin?: false})

      assert %Ash.ForbiddenField{} = user.email
      assert user.ssn == "123"
      assert user.name == "n"
    end

    test "an authorized actor still sees the decrypted field" do
      create!(%{email: "a@b.c"})

      assert {:ok, [user]} =
               User
               |> Ash.Query.load([:email])
               |> Ash.read(tenant: @acme, actor: %{admin?: true})

      assert user.email == "a@b.c"
    end
  end

  defp uuid(string), do: Ecto.UUID.dump!(string)
end
