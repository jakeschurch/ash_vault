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

  describe "MissingScope messages (finding 10)" do
    # The message hardcoded "no Ash tenant was present" for every reason. An operator
    # who DID pass a tenant — in a shape with no `:id` — was sent hunting a missing
    # tenant that is not missing, and the `vars: [tenant: ...]` the scope assembled was
    # never read by anything.
    test "the unsupported-shape message says what was received, not that a tenant is missing" do
      error =
        assert_raise MissingScope, fn ->
          AshTenant.resolve!(context(%{tenant: {:weird, :shape}}))
        end

      message = Exception.message(error)

      refute message =~ "no Ash tenant was present"
      refute message =~ "Pass a tenant when executing the Ash action"

      assert message =~ "of a shape"
      assert message =~ "a 2-tuple"
      # The shape, never the contents: a tenant is routinely a loaded record full of
      # customer PII, and this error ends up in logs and APM.
      refute message =~ "weird"
      assert message =~ "this is not a missing-tenant error"
      assert message =~ "to_scope_key/2"
      assert message =~ "AshVault.Scopes.AshTenant"
    end

    test "the missing-tenant message keeps the operator-facing text CORE_SPEC §1 froze" do
      error = assert_raise MissingScope, fn -> AshTenant.resolve!(context(%{})) end

      message = Exception.message(error)

      assert message =~
               "Cannot encrypt AshVault.Test.Support.Resources.User.ssn because no Ash tenant was present."

      assert message =~ "This resource uses tenant-scoped encryption."

      assert message =~
               "Pass a tenant when executing the Ash action or configure another AshVault scope."
    end

    test "the verb follows the operation, and Exception.message/1 works for every reason" do
      for reason <- [nil, :no_tenant, :unsupported_tenant_shape, :something_new] do
        for operation <- [nil, :encrypt, :decrypt] do
          error =
            MissingScope.exception(
              resource: Resources.User,
              field: :ssn,
              scope_module: AshTenant,
              reason: reason,
              tenant: "\"weird\"",
              operation: operation
            )

          message = Exception.message(error)
          assert message != ""

          expected_verb = if operation == :decrypt, do: "decrypt", else: "encrypt"
          assert message =~ "Cannot #{expected_verb} "
        end
      end
    end
  end

  describe "AshVault.Scopes.Global" do
    test "always resolves to \"global\"" do
      assert Global.resolve!(context(nil)) == "global"
      assert Global.resolve!(context(%{tenant: "ignored"})) == "global"
    end
  end
end
