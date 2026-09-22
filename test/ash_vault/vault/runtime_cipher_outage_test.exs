defmodule AshVault.Vault.RuntimeCipherOutageTest do
  @moduledoc """
  A cipher may fail for reasons that have nothing to do with the stored bytes.

  `AshVault.Ciphers.OpenBaoTransit` does its AEAD inside OpenBao, so a `403`, a deleted
  transit key or a refused connection all surface as cipher errors. The runtime's
  catch-all used to report every one of them as
  `AshVault.Errors.CiphertextIntegrityFailed` — telling an operator their data was
  tampered with, over an outage. A `AshVault.Errors.ProviderUnavailable` from a cipher is
  now re-raised unchanged.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Support.Helpers
  alias AshVault.Test.Support.OutageCipher
  alias AshVault.Test.Support.OutageCipherVault
  alias AshVault.Test.Support.TenantVault

  setup do
    start_supervised!({Memory, name: Memory})

    previous = Application.get_env(:ash_vault, :ciphers, %{})
    Application.put_env(:ash_vault, :ciphers, Map.put(previous, "test_outage_v1", OutageCipher))
    on_exit(fn -> Application.put_env(:ash_vault, :ciphers, previous) end)

    %{ctx: Helpers.context_for("outage_tenant")}
  end

  test "a cipher's ProviderUnavailable is re-raised, not relabelled as tampering",
       %{ctx: ctx} do
    blob = OutageCipherVault.encrypt!("secret", ctx)

    error = assert_raise ProviderUnavailable, fn -> OutageCipherVault.decrypt!(blob, ctx) end

    assert error.reason == :simulated_outage
    assert error.provider == OutageCipher
    assert error.__struct__ == ProviderUnavailable
  end

  test "a genuine authentication failure is still CiphertextIntegrityFailed", %{ctx: ctx} do
    other = Helpers.context_for("outage_tenant", field: :other_field)
    blob = TenantVault.encrypt!("secret", ctx)

    assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(blob, other) end
  end
end
