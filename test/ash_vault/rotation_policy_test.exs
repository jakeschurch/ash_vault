defmodule AshVault.RotationPolicyTest do
  use ExUnit.Case, async: true

  alias AshVault.RotationPolicy
  alias AshVault.RotationPolicies.Manual
  alias AshVault.Test.Support.Helpers

  defp key_info(created_at), do: %{version: 1, key: <<0::256>>, created_at: created_at}

  describe "due?/3" do
    test ":manual is never due" do
      policy = %RotationPolicy{strategy: :manual}
      refute RotationPolicy.due?(policy, key_info(~U[1970-01-01 00:00:00Z]))
    end

    test ":provider is never due" do
      policy = %RotationPolicy{strategy: :provider}
      refute RotationPolicy.due?(policy, key_info(~U[1970-01-01 00:00:00Z]))
    end

    test ":age is due once the key is older than max_age" do
      policy = %RotationPolicy{strategy: :age, max_age: Duration.new!(day: 30)}
      now = ~U[2026-01-31 00:00:00Z]

      assert RotationPolicy.due?(policy, key_info(~U[2025-12-01 00:00:00Z]), now)
      refute RotationPolicy.due?(policy, key_info(~U[2026-01-30 00:00:00Z]), now)
    end

    test ":age without a max_age is never due" do
      policy = %RotationPolicy{strategy: :age}
      refute RotationPolicy.due?(policy, key_info(~U[1970-01-01 00:00:00Z]))
    end
  end

  describe "AshVault.RotationPolicies.Manual" do
    test "always returns the manual policy" do
      assert %RotationPolicy{strategy: :manual, rotate_on_write?: false, max_age: nil} =
               Manual.policy("acme", Helpers.context())
    end
  end
end
