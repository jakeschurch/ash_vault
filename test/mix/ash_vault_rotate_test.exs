defmodule Mix.Tasks.AshVault.RotateTest do
  @moduledoc "`mix ash_vault.rotate` — new key version, old ciphertext still readable."

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  require Ash.Query

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsUser

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp rotate(argv), do: capture_io(fn -> Mix.Tasks.AshVault.Rotate.run(argv) end)

  test "mints the next version and reports both" do
    scope = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(scope)

    output = rotate(["AshVault.Test.EtsUser", "--tenant", scope, "--yes"])

    assert output =~ "ash_vault.rotate=done"
    assert output =~ "old_version=1 new_version=2"
    assert output =~ "key version 1 -> 2"
    assert {:ok, %{version: 2}} = Memory.current_key(scope)
  end

  test "rotates an unused scope from nothing to version 1" do
    scope = "tenant-#{System.unique_integer([:positive])}"

    output = rotate(["AshVault.Test.EtsUser", "--tenant", scope, "--yes"])

    assert output =~ "old_version=- new_version=1"
  end

  test "values written before the rotation still decrypt afterwards" do
    scope = "tenant-#{System.unique_integer([:positive])}"

    user =
      EtsUser
      |> Ash.Changeset.for_create(:create, %{org_id: scope, email: "before@example.com"},
        tenant: scope
      )
      |> Ash.create!()

    rotate(["AshVault.Test.EtsUser", "--tenant", scope, "--yes"])

    [reloaded] =
      EtsUser
      |> Ash.Query.filter(id == ^user.id)
      |> Ash.Query.load(:email)
      |> Ash.read!(tenant: scope, authorize?: false)

    assert reloaded.email == "before@example.com"

    newer =
      EtsUser
      |> Ash.Changeset.for_create(:create, %{org_id: scope, email: "after@example.com"},
        tenant: scope
      )
      |> Ash.create!()

    [reloaded_newer] =
      EtsUser
      |> Ash.Query.filter(id == ^newer.id)
      |> Ash.Query.load(:email)
      |> Ash.read!(tenant: scope, authorize?: false)

    assert reloaded_newer.email == "after@example.com"
  end

  test "refuses to rotate a destroyed scope" do
    scope = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(scope)
    :ok = Memory.destroy(scope)

    assert_raise Mix.Error, ~r/has been destroyed/, fn ->
      rotate(["AshVault.Test.EtsUser", "--tenant", scope, "--yes"])
    end
  end

  test "--all-tenants rotates each tenant" do
    a = "tenant-#{System.unique_integer([:positive])}"
    b = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(a)
    {:ok, _} = Memory.current_key(b)
    :persistent_term.put({__MODULE__, :tenants}, [a, b])

    output =
      rotate([
        "AshVault.Test.EtsUser",
        "--all-tenants",
        "Mix.Tasks.AshVault.RotateTest.tenants/0",
        "--yes"
      ])

    assert output =~ "scope=#{a}"
    assert output =~ "scope=#{b}"
    assert {:ok, %{version: 2}} = Memory.current_key(a)
    assert {:ok, %{version: 2}} = Memory.current_key(b)
  end

  @doc false
  def tenants, do: :persistent_term.get({__MODULE__, :tenants})
end
