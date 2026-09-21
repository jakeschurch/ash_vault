defmodule AshVault.Scopes.AshTenantTest do
  use ExUnit.Case, async: true

  alias AshVault.Context
  alias AshVault.Errors.MissingScope
  alias AshVault.Scopes.AshTenant
  alias AshVault.Scopes.Global
  alias AshVault.Test.Support.Resources

  defp context(ash_context) do
    %Context{resource: Resources.User, field: :ssn, ash_context: ash_context}
  end

  defmodule FakeAshContext do
    @moduledoc false
    defstruct [:actor, :tenant, source_context: %{}]
  end

  defmodule Tenant do
    @moduledoc false
    defstruct [:id, :name]
  end

  describe "resolve!/1" do
    test "reads the top-level tenant field of an Ash context struct" do
      ctx = context(%FakeAshContext{tenant: "acme"})
      assert AshTenant.resolve!(ctx) == "acme"
    end

    test "falls back to source_context[:tenant]" do
      ctx = context(%FakeAshContext{tenant: nil, source_context: %{tenant: "acme"}})
      assert AshTenant.resolve!(ctx) == "acme"
    end

    test "works with a plain map" do
      assert AshTenant.resolve!(context(%{tenant: "acme"})) == "acme"
      assert AshTenant.resolve!(context(%{source_context: %{tenant: "acme"}})) == "acme"
    end

    test "normalises atoms, integers and structs with an id" do
      assert AshTenant.resolve!(context(%{tenant: :acme})) == "acme"
      assert AshTenant.resolve!(context(%{tenant: 42})) == "42"
      assert AshTenant.resolve!(context(%{tenant: %Tenant{id: "t_1"}})) == "t_1"
      assert AshTenant.resolve!(context(%{tenant: %Tenant{id: 7}})) == "7"
    end

    test "raises MissingScope when no tenant is present" do
      for ash_context <- [nil, %{}, %{tenant: nil}, %FakeAshContext{}] do
        assert_raise MissingScope, fn -> AshTenant.resolve!(context(ash_context)) end
      end
    end

    test "raises MissingScope for a tenant shape it cannot key stably" do
      error =
        assert_raise MissingScope, fn ->
          AshTenant.resolve!(context(%{tenant: {:weird, :shape}}))
        end

      assert error.reason == :unsupported_tenant_shape
      assert error.scope_module == AshTenant
    end

    test "scope keys are plain binaries, never term_to_binary" do
      scope = AshTenant.resolve!(context(%{tenant: %Tenant{id: "t_1"}}))
      assert is_binary(scope)
      assert String.valid?(scope)
    end
  end

  describe "AshVault.Scopes.Global" do
    test "always resolves to \"global\"" do
      assert Global.resolve!(context(nil)) == "global"
      assert Global.resolve!(context(%{tenant: "ignored"})) == "global"
    end
  end
end
