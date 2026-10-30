defmodule AshVault.KeyProviders.OpenBaoNamespaceLiveTest do
  use ExUnit.Case, async: false
  alias AshVault.KeyProviders.{OpenBao, OpenBaoTransit}
  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.Test.Support.{Helpers, TransitVault}
  alias AshVault.Test.BaoVault
  @moduletag :openbao_plugin
  @address System.get_env("BAO_ADDR", "http://127.0.0.1:8200")
  @token System.get_env("BAO_TOKEN", "ashvault-root")

  setup do
    for provider <- [OpenBao, OpenBaoTransit] do
      old = Application.get_env(:ash_vault, provider)

      Application.put_env(:ash_vault, provider,
        address: @address,
        token: @token,
        transit_mount: "ashvault-transit",
        server_retirement: true,
        max_retries: 0
      )

      on_exit(fn ->
        if old,
          do: Application.put_env(:ash_vault, provider, old),
          else: Application.delete_env(:ash_vault, provider)
      end)
    end

    assert :ok = OpenBao.setup()
    native = "abd" <> :crypto.strong_rand_bytes(9) <> "ddd"

    binary =
      Base.url_decode64!("nx_" <> Base.url_encode64(native, padding: false), padding: false)

    %{native: native, binary: binary, legacy: OpenBaoTransit.key_name(native)}
  end

  defp create_legacy(name) do
    assert {:ok, %{status: 200}} =
             Transport.post(OpenBao, Transport.transit_path(OpenBao, "/keys/#{name}"), %{
               type: "aes256-gcm96",
               exportable: true
             })
  end

  test "migration preserves all key purposes, old ciphertext and independent native erasure",
       context do
    for suffix <- ["", ".mac", "_lookup"], do: create_legacy(context.legacy <> suffix)

    assert {:error, %AshVault.Errors.ProviderUnavailable{reason: :scope_namespace_conflict}} =
             OpenBaoTransit.destroy(context.native)

    assert {:ok, %{status: 200, body: body}} =
             Transport.get(
               OpenBao,
               Transport.transit_path(OpenBao, "/export/encryption-key/#{context.legacy}/1")
             )

    original = body["data"]["keys"]["1"] |> Base.decode64!()
    assert {:ok, payload} = AshVault.Ciphers.AES.GCM.encrypt("secret", original, "legacy-aad")
    assert {:error, %AshVault.Errors.ProviderUnavailable{}} = OpenBao.current_key(context.binary)
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary)
    assert {:ok, ^original} = OpenBao.get_key(context.binary, 1)
    assert {:ok, "secret"} = AshVault.Ciphers.AES.GCM.decrypt(payload, original, "legacy-aad")
    assert {:ok, _} = OpenBao.current_key(context.binary, :mac)
    assert {:ok, lookup} = OpenBao.lookup_key(context.binary)
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary, true)

    assert {:ok, %{status: 200}} =
             Transport.get(OpenBao, Transport.transit_path(OpenBao, "/keys/#{context.legacy}"))

    assert {:error, %AshVault.Errors.ProviderUnavailable{}} = OpenBao.current_key(context.binary)
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary)
    assert {:ok, ^lookup} = OpenBao.lookup_key(context.binary)

    native_ctx = Helpers.context_for(context.native)
    exported_ctx = Helpers.context_for(context.binary)
    native_blob = TransitVault.encrypt!("native secret", native_ctx)
    exported_blob = BaoVault.encrypt!("exported secret", exported_ctx)

    assert {:error, %AshVault.Errors.ProviderUnavailable{}} =
             Transport.migrate_binary_namespace(OpenBao, context.binary, true)

    assert :ok = OpenBaoTransit.destroy(context.native)
    # idempotent despite the other scope's later tombstone
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary)
    assert BaoVault.decrypt!(exported_blob, exported_ctx) == "exported secret"

    assert_raise AshVault.Errors.KeyDestroyed, fn ->
      TransitVault.decrypt!(native_blob, native_ctx)
    end

    assert :ok = OpenBao.destroy(context.binary)
  end

  test "erasing the escaped scope leaves native ciphertext usable", context do
    assert {:ok, _} = OpenBaoTransit.current_key(context.native)
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary)
    assert {:ok, _} = OpenBao.current_key(context.binary)
    ctx = Helpers.context_for(context.native)
    blob = TransitVault.encrypt!("native secret", ctx)
    assert :ok = OpenBao.destroy(context.binary)
    assert TransitVault.decrypt!(blob, ctx) == "native secret"
    assert :ok = OpenBaoTransit.destroy(context.native)
  end

  test "a historical KV tombstone is preserved in the escaped namespace", context do
    create_legacy(context.legacy)
    assert :ok = Transport.write_tombstone(OpenBao, context.legacy)
    assert :ok = Transport.migrate_binary_namespace(OpenBao, context.binary)
    assert {:error, :destroyed} = OpenBao.current_key(context.binary)

    assert {:ok, %{status: 404}} =
             Transport.get(OpenBao, Transport.transit_path(OpenBao, "/keys/#{context.legacy}"))

    assert {:error, %AshVault.Errors.ProviderUnavailable{}} =
             Transport.migrate_binary_namespace(OpenBao, context.binary, true)
  end
end
