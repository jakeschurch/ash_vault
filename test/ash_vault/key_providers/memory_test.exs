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

    # Finding 13. Without format_status/1 any crash in this GenServer emits a SASL
    # report carrying every scope's raw key bytes into the logs and into any APM
    # handler attached to them.
    test "key material never appears in a process status report", %{provider: {Memory, name}} do
      assert {:ok, %{key: key}} = Memory.current_key(name, "sensitive")
      assert {:ok, 2} = Memory.rotate(name, "sensitive")
      assert {:ok, %{key: rotated}} = Memory.current_key(name, "sensitive")

      status = :sys.get_status(Process.whereis(name))
      rendered = inspect(status, limit: :infinity, printable_limit: :infinity)

      refute rendered =~ inspect(key)
      refute rendered =~ inspect(rotated)
      refute rendered =~ Base.encode16(key)
      assert rendered =~ ":redacted"

      # The rest of the state is still there to debug with.
      assert rendered =~ "destroyed"
      assert rendered =~ "key_bytes"
    end

    test "calls against a dead instance surface as a provider error" do
      assert {:error, {:provider_unavailable, _}} =
               Memory.current_key(:ash_vault_memory_never_started, "x")
    end
  end
end
