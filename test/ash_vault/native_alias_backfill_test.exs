defmodule AshVault.NativeAliasBackfillTest do
  use ExUnit.Case, async: false

  alias AshVault.Test.NativeAliasScopedDoc, as: Doc

  @tenant "alias-scope"

  setup do
    start_supervised!(AshVault.KeyProviders.Memory)
    :ok
  end

  test "planning CLI resolution writes and lookups share the retained binding scope" do
    record = create(%{source: "backfilled"})

    assert {:ok, plan} = AshVault.Backfill.plan(Doc, :token, options())
    assert plan.scope == @tenant <> "/vault_token"
    assert AshVault.Mix.Shared.resolve!(Doc, @tenant, :token).scope == plan.scope
    assert plan.encrypted_field == :encrypted_vault_token
    assert plan.lookup_field == :token_lookup
    refute Ash.Resource.Info.attribute(Doc, :vault_token_lookup)

    assert {:ok, %{done: 1}} = AshVault.Backfill.run(Doc, :token, options())
    assert lookup("backfilled").id == record.id
    assert lookup("backfilled").token == "backfilled"
    assert {:ok, %{done: 0}} = AshVault.Backfill.run(Doc, :token, options())

    assert {:ok, %{mismatches: []}} =
             AshVault.Backfill.run(Doc, :token, options(verify?: true, sample: 0))

    written = create(%{source: "written", token: "written"})
    assert lookup("written").id == written.id
  end

  test "lookup-only backfill decrypts the aliased ciphertext and retains logical HMAC naming" do
    record = create(%{source: "lookup", token: "lookup"})

    changeset =
      record
      |> Ash.Changeset.new()
      |> Ash.Changeset.set_tenant(@tenant)
      |> Ash.Changeset.force_change_attribute(:token_lookup, nil)

    assert {:ok, _} = Ash.DataLayer.update(Doc, changeset)
    assert {:ok, %{done: 1}} = AshVault.Backfill.run(Doc, :token, options(lookup?: true))
    assert lookup("lookup").id == record.id
  end

  defp create(input) do
    Doc
    |> Ash.Changeset.for_create(:create, Map.put(input, :org_id, @tenant), tenant: @tenant)
    |> Ash.create!()
  end

  defp lookup(value) do
    Doc
    |> AshVault.Query.filter_by(:token, value, tenant: @tenant)
    |> Ash.Query.load(:token)
    |> Ash.read_one!(tenant: @tenant)
  end

  defp options(extra \\ []), do: Keyword.merge([tenant: @tenant, action: :update], extra)
end
