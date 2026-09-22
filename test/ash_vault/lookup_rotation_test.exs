defmodule AshVault.LookupRotationTest do
  @moduledoc """
  The regression guard for the one failure mode that would ship silently.

  If a lookup token were derived from the rotating data encryption key, then
  `AshVault.rotate_key!/2` would change every future token while every stored token still
  reflected the old key. Existing rows would stop matching their own value. Nothing would
  raise. `unique?` would stop preventing duplicates. Users could not log in.

  It would pass any test that writes a row and immediately reads it back, which is why
  this file exists separately and asserts the property two ways: at the provider
  contract, and end to end through Ash.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsAccount

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp create!(org, email) do
    EtsAccount
    |> Ash.Changeset.for_create(:create, %{org_id: org, email: email})
    |> Ash.create!(tenant: org)
  end

  defp lookup_token(record), do: Map.fetch!(record, :email_lookup)

  describe "the provider contract" do
    test "rotate/1 does not change the lookup key" do
      scope = "rotation_scope"

      assert {:ok, before} = Memory.lookup_key(scope)
      assert {:ok, %{version: 1}} = Memory.current_key(scope)

      assert {:ok, 2} = Memory.rotate(scope)
      assert {:ok, 3} = Memory.rotate(scope)

      assert {:ok, ^before} = Memory.lookup_key(scope)
    end

    test "the lookup key is not any version of the data key" do
      scope = "separation_scope"

      assert {:ok, lookup} = Memory.lookup_key(scope)
      assert {:ok, %{key: v1}} = Memory.current_key(scope)
      assert {:ok, 2} = Memory.rotate(scope)
      assert {:ok, %{key: v2}} = Memory.current_key(scope)

      refute lookup == v1
      refute lookup == v2
    end

    test "destroy/1 destroys the lookup key too" do
      scope = "destroyed_scope"

      assert {:ok, _key} = Memory.lookup_key(scope)
      assert :ok = Memory.destroy(scope)

      # Never a freshly minted secret: erasure has to erase the ability to confirm a
      # guess about the subject, not just the ability to decrypt.
      assert {:error, :destroyed} = Memory.lookup_key(scope)
    end
  end

  describe "end to end" do
    test "rotating the key does not change any row's token, and lookups keep matching" do
      org = "rotating_org"

      before_rotation = create!(org, "before@example.com")
      assert {:ok, 2} = AshVault.rotate_key!(AshVault.Test.Vault, org)
      after_rotation = create!(org, "after@example.com")

      # The row written before the rotation still carries a token that a fresh lookup
      # computes identically — this is the assertion that fails if the lookup key ever
      # becomes a function of the data key.
      assert [%{id: found}] =
               EtsAccount
               |> AshVault.Query.filter_by(:email, "before@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert found == before_rotation.id

      assert [%{id: found}] =
               EtsAccount
               |> AshVault.Query.filter_by(:email, "after@example.com", tenant: org)
               |> Ash.read!(tenant: org)

      assert found == after_rotation.id

      # And the ciphertext really did move to the new key version, so the rotation was
      # not a no-op that would make the test above vacuous.
      assert {:ok, %{version: 2}} = Memory.current_key(org)
    end

    test "two rows of the same value written across a rotation share a token" do
      org = "same_value_org"

      first = create!(org, "same@example.com")
      assert {:ok, 2} = AshVault.rotate_key!(AshVault.Test.Vault, org)
      second = create!(org, "same@example.com")

      assert lookup_token(first) == lookup_token(second)

      assert [_, _] =
               EtsAccount
               |> AshVault.Query.filter_by(:email, "same@example.com", tenant: org)
               |> Ash.read!(tenant: org)
    end
  end
end
