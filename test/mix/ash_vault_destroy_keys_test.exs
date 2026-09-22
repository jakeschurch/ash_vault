defmodule Mix.Tasks.AshVault.DestroyKeysTest do
  @moduledoc """
  `mix ash_vault.destroy_keys` — the irreversible one.

  The behaviours pinned here are the safety rails: the operator must type the scope back,
  `--yes` does not stand in for that, there is no `--force`, the tombstone is re-read
  before success is claimed, and a second run is a no-op that exits 0.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsUser

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp scope!, do: "tenant-#{System.unique_integer([:positive])}"

  defp seeded_scope! do
    scope = scope!()

    EtsUser
    |> Ash.Changeset.for_create(:create, %{org_id: scope, email: "doomed@example.com"},
      tenant: scope
    )
    |> Ash.create!()

    scope
  end

  defp destroy(argv, input) do
    capture_io(input, fn -> Mix.Tasks.AshVault.DestroyKeys.run(argv) end)
  end

  test "prints the blast radius, requires the scope typed back, and confirms the tombstone" do
    scope = seeded_scope!()

    output =
      destroy(["AshVault.Test.EtsUser", "--tenant", scope], scope <> "\n")

    assert output =~ "ash_vault.destroy_keys=target"
    assert output =~ "status=active"
    assert output =~ "version=1"
    assert output =~ "undecryptable=AshVault.Test.EtsUser.email"
    assert output =~ "undecryptable=AshVault.Test.EtsUser.ssn"
    assert output =~ "IRREVERSIBLE CRYPTOGRAPHIC ERASURE"
    assert output =~ "Type the scope back to confirm (#{scope})"
    assert output =~ "ash_vault.destroy_keys=done"
    assert output =~ "tombstone=confirmed"
    assert output =~ "DESTROYED AshVault.Test.Vault scope #{scope}"

    assert {:error, :destroyed} = Memory.current_key(scope)
  end

  test "the data really is unreadable afterwards" do
    scope = seeded_scope!()

    destroy(["AshVault.Test.EtsUser", "--tenant", scope], scope <> "\n")

    assert {:error, error} =
             EtsUser |> Ash.Query.load(:email) |> Ash.read(tenant: scope, authorize?: false)

    assert %AshVault.Errors.KeyDestroyed{} = Ash.Error.to_error_class(error).errors |> hd()
  end

  test "a mistyped scope destroys nothing" do
    scope = seeded_scope!()

    assert_raise Mix.Error, ~r/scope confirmation did not match/, fn ->
      destroy(["AshVault.Test.EtsUser", "--tenant", scope], "not-the-scope\n")
    end

    assert {:ok, %{version: 1}} = Memory.current_key(scope)
  end

  test "--yes does not stand in for typing the scope back" do
    scope = seeded_scope!()

    assert_raise Mix.Error, ~r/scope confirmation did not match/, fn ->
      destroy(["AshVault.Test.EtsUser", "--tenant", scope, "--yes"], "\n")
    end

    assert {:ok, %{version: 1}} = Memory.current_key(scope)
  end

  test "there is no --force" do
    scope = seeded_scope!()

    assert_raise OptionParser.ParseError, ~r/--force/, fn ->
      destroy(["AshVault.Test.EtsUser", "--tenant", scope, "--force"], "")
    end

    assert {:ok, %{version: 1}} = Memory.current_key(scope)
  end

  test "an already-destroyed scope reports that and exits 0" do
    scope = seeded_scope!()
    destroy(["AshVault.Test.EtsUser", "--tenant", scope], scope <> "\n")

    output = destroy(["AshVault.Test.EtsUser", "--tenant", scope], "")

    assert output =~ "status=already_destroyed"
    assert output =~ "was already destroyed. Nothing to do."
    refute output =~ "Type the scope back"
  end

  test "refuses a scope that has never had a key" do
    assert_raise Mix.Error, ~r/no key to destroy/, fn ->
      destroy(["AshVault.Test.EtsUser", "--tenant", scope!()], "")
    end
  end

  test "reports every key version it destroyed" do
    scope = seeded_scope!()
    {:ok, 2} = Memory.rotate(scope)
    {:ok, 3} = Memory.rotate(scope)

    output = destroy(["AshVault.Test.EtsUser", "--tenant", scope], scope <> "\n")

    assert output =~ "versions=1,2,3"
    assert output =~ "versions_destroyed=3"
  end

  test "requires a tenant for a tenant-scoped resource" do
    assert_raise Mix.Error, ~r/--tenant/, fn ->
      destroy(["AshVault.Test.EtsUser"], "")
    end
  end
end
