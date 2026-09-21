defmodule AshVault.KeyProviders.MemoryTest do
  use ExUnit.Case, async: true

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_memory/1

  alias AshVault.KeyProviders.Memory

  @doc false
  def start_memory(_context) do
    name = :"ash_vault_memory_#{System.unique_integer([:positive])}"
    start_supervised!({Memory, name: name})

    %{
      provider: {Memory, name},
      scope: fn -> "scope_#{System.unique_integer([:positive])}" end
    }
  end

  describe "memory-specific behaviour" do
    test "key_bytes defaults to 32" do
      assert Memory.key_bytes() == 32
    end

    test "keys are random per scope", %{provider: {Memory, name}} do
      assert {:ok, %{key: a}} = Memory.current_key(name, "a")
      assert {:ok, %{key: b}} = Memory.current_key(name, "b")
      refute a == b
    end

    test "rotating repeatedly keeps the whole history", %{provider: {Memory, name}} do
      assert {:ok, %{version: 1}} = Memory.current_key(name, "hist")
      assert {:ok, 2} = Memory.rotate(name, "hist")
      assert {:ok, 3} = Memory.rotate(name, "hist")

      keys =
        for version <- 1..3 do
          assert {:ok, key} = Memory.get_key(name, "hist", version)
          key
        end

      assert length(Enum.uniq(keys)) == 3
    end

    test "state dies with the process", %{provider: {Memory, name}} do
      assert {:ok, %{key: key}} = Memory.current_key(name, "ephemeral")

      stop_supervised!(Memory)
      start_supervised!({Memory, name: name})

      assert {:ok, %{key: new_key}} = Memory.current_key(name, "ephemeral")
      refute key == new_key
    end

    test "calls against a dead instance surface as a provider error" do
      assert {:error, {:provider_unavailable, _}} =
               Memory.current_key(:ash_vault_memory_never_started, "x")
    end
  end
end
