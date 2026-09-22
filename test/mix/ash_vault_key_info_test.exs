defmodule Mix.Tasks.AshVault.KeyInfoTest do
  @moduledoc "`mix ash_vault.key_info` — read-only, and never mints key material."

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias AshVault.KeyProviders.Memory

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp key_info(argv), do: capture_io(fn -> Mix.Tasks.AshVault.KeyInfo.run(argv) end)

  test "reports an unused scope without minting a key" do
    scope = "tenant-#{System.unique_integer([:positive])}"

    output = key_info(["AshVault.Test.EtsUser", "--tenant", scope])

    assert output =~ "status=not_minted"
    assert output =~ "has no key yet"

    # Still nothing minted: the task must not have called `current_key/1`.
    assert {:error, :not_found} = Memory.get_key(scope, 1)
  end

  test "reports an active scope with its version, timestamp and retained versions" do
    scope = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(scope)
    {:ok, 2} = Memory.rotate(scope)

    output = key_info(["AshVault.Test.EtsUser", "--tenant", scope])

    assert output =~ "ash_vault.key_info=scope"
    assert output =~ "status=active"
    assert output =~ "version=2"
    assert output =~ "versions=1,2"
    assert output =~ "scope=#{scope}"
    assert output =~ "vault=AshVault.Test.Vault"
    assert output =~ "provider=AshVault.KeyProviders.Memory"
    assert output =~ ~r/created_at=\d{4}-\d{2}-\d{2}T/
    assert output =~ "is active at key version 2 (2 version(s) retained)"
  end

  test "reports a destroyed scope and exits 0" do
    scope = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(scope)
    :ok = Memory.destroy(scope)

    output = key_info(["AshVault.Test.EtsUser", "--tenant", scope])

    assert output =~ "status=destroyed"
    assert output =~ "permanently unrecoverable"
  end

  test "works for a globally scoped resource with no tenant" do
    output = key_info(["AshVault.Test.EtsNote"])

    assert output =~ "scope=global"
    assert output =~ "vault=AshVault.Test.GlobalVault"
  end

  test "--all-tenants reports every tenant" do
    a = "tenant-#{System.unique_integer([:positive])}"
    b = "tenant-#{System.unique_integer([:positive])}"
    {:ok, _} = Memory.current_key(a)
    :persistent_term.put({__MODULE__, :tenants}, [a, b])

    output =
      key_info([
        "AshVault.Test.EtsUser",
        "--all-tenants",
        "Mix.Tasks.AshVault.KeyInfoTest.tenants/0"
      ])

    assert output =~
             "scope=#{a} vault=AshVault.Test.Vault provider=AshVault.KeyProviders.Memory key_name=- status=active"

    assert output =~ "scope=#{b}"
    assert output =~ "status=not_minted"
  end

  @doc false
  def tenants, do: :persistent_term.get({__MODULE__, :tenants})

  test "requires a tenant for a tenant-scoped resource" do
    assert_raise Mix.Error, ~r/--tenant/, fn ->
      key_info(["AshVault.Test.EtsUser"])
    end
  end

  test "rejects a module that is not a resource" do
    assert_raise Mix.Error, ~r/not an Ash resource/, fn ->
      key_info(["AshVault.Test.NotAVault"])
    end
  end
end
