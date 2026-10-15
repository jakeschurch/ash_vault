defmodule AshVault.NativeAliasTest do
  use ExUnit.Case, async: false

  alias AshVault.{Context, Serializer}
  alias AshVault.Test.{NativeAliasDoc, Vault}

  @tenant "native-alias"
  @actor %{tenant_id: @tenant}

  setup do
    start_supervised!(AshVault.KeyProviders.Memory)
    :ok
  end

  test "old ciphertext keeps its storage and binding while the public field stays logical" do
    record = create("temporary")

    old_blob =
      Vault.encrypt!(
        Serializer.serialize!("old-value", :binary, [], NativeAliasDoc, :vault_token),
        crypto_context()
      )

    store(record, :encrypted_vault_token, old_blob)

    assert read(record).token == "old-value"
    assert AshVault.encrypted_field_name(NativeAliasDoc, :token) == :encrypted_vault_token
    assert AshVault.Info.encrypted_field_names(NativeAliasDoc) == [:token, :other, :action_only]
    refute Ash.Resource.Info.attribute(NativeAliasDoc, :token)
    refute Ash.Resource.Info.attribute(NativeAliasDoc, :encrypted_token)
    refute Ash.Resource.Info.calculation(NativeAliasDoc, :vault_token)
    assert Ash.Resource.Info.calculation(NativeAliasDoc, :token).public?

    assert Ash.Resource.Info.action(NativeAliasDoc, :create).arguments
           |> Enum.any?(&(&1.name == :token))

    refute Ash.Resource.Info.action(NativeAliasDoc, :create).arguments
           |> Enum.any?(&(&1.name == :vault_token))

    assert Ash.Resource.Info.preparations(NativeAliasDoc) == []
  end

  test "normal writes use the retained binding and normalized policy keeps the logical name" do
    record = create("first")
    assert decrypt(record.encrypted_vault_token) == "first"

    updated =
      record
      |> Ash.Changeset.for_update(:update, %{token: "second"}, tenant: @tenant)
      |> Ash.update!()

    assert decrypt(updated.encrypted_vault_token) == "second"
    assert read(updated).token == "second"

    assert_receive {:decrypt_policy_context,
                    %{
                      field: :token,
                      tenant: @tenant,
                      actor: @actor,
                      resource: NativeAliasDoc,
                      phase: :read,
                      action: nil
                    }}

    context =
      AshVault.Context.Builder.from_calculation(NativeAliasDoc, :token, %{
        tenant: @tenant,
        actor: @actor,
        source_context: %{}
      })

    assert context.field == :vault_token
    assert context.ash_context.actor == @actor
    assert context.ash_context.tenant == @tenant
  end

  test "action-only decryption remains forbidden even when source context names the action" do
    record = create("first")

    query =
      NativeAliasDoc
      |> Ash.Query.set_context(%{action: :credentials, field: :action_only})
      |> Ash.Query.for_read(:credentials, %{},
        actor: %AshVault.Test.Admin{role: :system},
        tenant: @tenant
      )
      |> Ash.Query.load(:action_only)

    assert [%{action_only: %Ash.ForbiddenField{}}] = Ash.read!(query)
    assert decrypt(record.encrypted_vault_action_only, :vault_action_only) == "restricted"
  end

  test "ciphertext corruption and tenant resource or field substitution fail integrity" do
    record = create("first")
    blob = record.encrypted_vault_token
    {:ok, _} = AshVault.KeyProviders.Memory.current_key("other-tenant")

    for context <- [
          %{crypto_context() | field: :token},
          %{crypto_context() | field: :vault_other},
          %{crypto_context() | resource: AshVault.Test.EtsUser},
          %{crypto_context() | ash_context: %{tenant: "other-tenant"}}
        ] do
      assert_raise AshVault.Errors.CiphertextIntegrityFailed, fn ->
        Vault.decrypt!(blob, context)
      end
    end

    prefix = binary_part(blob, 0, byte_size(blob) - 1)
    last = :binary.last(blob)
    store(record, :encrypted_vault_token, <<prefix::binary, Bitwise.bxor(last, 1)>>)
    assert {:error, error} = read_result(record)

    assert Enum.any?(
             Ash.Error.to_error_class(error).errors,
             &is_struct(&1, AshVault.Errors.CiphertextIntegrityFailed)
           )
  end

  test "the existing AAD permits replay within the same tenant resource and field" do
    first = create("first")
    second = create("second")
    refute first.id == second.id
    store(second, :encrypted_vault_token, first.encrypted_vault_token)
    assert read(second).token == "first"
  end

  test "backfill planning resolves the ciphertext alias and refuses it as a source" do
    assert {:ok, plan} =
             AshVault.Backfill.plan(NativeAliasDoc, :token,
               from: :org_id,
               action: :update,
               tenant: @tenant
             )

    assert plan.encrypted_field == :encrypted_vault_token
    assert AshVault.Backfill.context(plan).field == :vault_token

    assert {:error, error} =
             AshVault.Backfill.plan(NativeAliasDoc, :token,
               from: :encrypted_vault_token,
               action: :update,
               tenant: @tenant
             )

    assert Exception.message(error) =~ "cannot be the ciphertext attribute"
  end

  defp create(token) do
    NativeAliasDoc
    |> Ash.Changeset.for_create(
      :create,
      %{org_id: @tenant, token: token, other: "other", action_only: "restricted"},
      tenant: @tenant
    )
    |> Ash.create!()
  end

  defp store(record, field, blob) do
    changeset =
      record
      |> Ash.Changeset.new()
      |> Ash.Changeset.set_tenant(@tenant)
      |> Ash.Changeset.force_change_attribute(field, blob)

    assert {:ok, _} = Ash.DataLayer.update(NativeAliasDoc, changeset)
  end

  defp crypto_context(field \\ :vault_token) do
    %Context{resource: NativeAliasDoc, field: field, ash_context: %{tenant: @tenant}}
  end

  defp decrypt(blob, field \\ :vault_token) do
    assert {:ok, value} =
             Serializer.deserialize(
               Vault.decrypt!(blob, crypto_context(field)),
               :binary,
               [],
               NativeAliasDoc,
               field
             )

    value
  end

  defp read_result(record) do
    require Ash.Query

    NativeAliasDoc
    |> Ash.Query.for_read(:read, %{}, actor: @actor, tenant: @tenant)
    |> Ash.Query.filter(id == ^record.id)
    |> Ash.Query.load(:token)
    |> Ash.read_one()
  end

  defp read(record) do
    assert {:ok, result} = read_result(record)
    result
  end
end
