defmodule AshVault.VaultMacAtTest do
  # Not async: vaults talk to the default-named `AshVault.KeyProviders.Memory`.
  use ExUnit.Case, async: false

  alias AshVault.Context
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Support.FlakyMacProvider
  alias AshVault.Test.Support.FlakyMacVault
  alias AshVault.Test.Support.Resources
  alias AshVault.Test.Support.TenantVault

  setup do
    start_supervised!({Memory, name: Memory})
    on_exit(&FlakyMacProvider.recover!/0)
    :ok
  end

  defp ctx(tenant \\ "acme") do
    %Context{
      resource: Resources.User,
      field: :token,
      ash_context: %{tenant: tenant, actor: nil, source_context: %{}}
    }
  end

  test "mac_at! at the current version equals mac!" do
    {version, tag} = TenantVault.mac!("data", ctx())
    assert TenantVault.mac_key_version!(ctx()) == version
    assert TenantVault.mac_at!("data", version, ctx()) == tag
  end

  test "mac_at! recomputes a tag at an older version after rotation" do
    {1, tag} = TenantVault.mac!("data", ctx())
    {:ok, 2} = TenantVault.rotate!("acme", purpose: :mac)

    assert TenantVault.mac_key_version!(ctx()) == 2
    assert TenantVault.mac_at!("data", 1, ctx()) == tag
    refute TenantVault.mac_at!("data", 2, ctx()) == tag
  end

  test "data-key rotation does not move the :mac version" do
    {1, _tag} = TenantVault.mac!("data", ctx())
    {:ok, _} = TenantVault.rotate!("acme")
    assert TenantVault.mac_key_version!(ctx()) == 1
  end

  test "an unknown, zero or non-integer version is KeyNotFound and mints nothing" do
    {1, _tag} = TenantVault.mac!("data", ctx())

    for version <- [2, 0, -1, "1", nil] do
      assert_raise KeyNotFound, fn -> TenantVault.mac_at!("data", version, ctx()) end
    end

    assert_raise KeyNotFound, fn -> TenantVault.mac_at!("data", 1, ctx("never-seen")) end
    assert Memory.get_key("never-seen", 1, :mac) == {:error, :not_found}
  end

  test "a destroyed scope is KeyDestroyed for both" do
    {1, _tag} = TenantVault.mac!("data", ctx())
    :ok = TenantVault.destroy!("acme")

    assert_raise KeyDestroyed, fn -> TenantVault.mac_at!("data", 1, ctx()) end
    assert_raise KeyDestroyed, fn -> TenantVault.mac_key_version!(ctx()) end
  end

  test "an outage is ProviderUnavailable, never KeyNotFound" do
    {1, _tag} = FlakyMacVault.mac!("data", ctx())
    FlakyMacProvider.outage!()

    assert_raise ProviderUnavailable, fn -> FlakyMacVault.mac_at!("data", 1, ctx()) end
    assert_raise ProviderUnavailable, fn -> FlakyMacVault.mac_key_version!(ctx()) end
  end

  test "mac_at! emits the :sign span with the stated version" do
    {1, _tag} = TenantVault.mac!("data", ctx())
    ref = make_ref()
    parent = self()

    :telemetry.attach(
      "mac-at-#{inspect(ref)}",
      [:ash_vault, :mac, :sign, :stop],
      fn _event, _measurements, metadata, _ -> send(parent, {ref, metadata}) end,
      nil
    )

    TenantVault.mac_at!("data", 1, ctx())
    :telemetry.detach("mac-at-#{inspect(ref)}")

    assert_received {^ref, %{key_version: 1}}
  end
end
