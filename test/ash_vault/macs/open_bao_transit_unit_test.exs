defmodule AshVault.Macs.OpenBaoTransitUnitTest do
  @moduledoc """
  The parts of `AshVault.Macs.OpenBaoTransit` that are decided before any request is
  made, plus the handle separation between data and `:mac` keys. No server needed; the
  live suite is `test/ash_vault/macs/open_bao_transit_test.exs`.
  """

  use ExUnit.Case, async: false

  alias AshVault.Ciphers.OpenBaoTransit, as: Cipher
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider
  alias AshVault.Macs.OpenBaoTransit, as: Mac

  doctest AshVault.Macs.OpenBaoTransit

  @mac_handle Provider.mac_handle("ashvault_nx_YWJj.mac", 1)
  @data_handle Provider.handle("ashvault_nx_YWJj", 1)

  setup do
    # A port nothing listens on: any request that does go out fails fast and visibly.
    previous = Application.get_env(:ash_vault, Provider)

    Application.put_env(:ash_vault, Provider,
      address: "http://127.0.0.1:1",
      token: "unused",
      max_retries: 0,
      receive_timeout: 500
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_vault, Provider, previous),
        else: Application.delete_env(:ash_vault, Provider)
    end)
  end

  describe "handle separation" do
    test "the MAC refuses a data key handle" do
      assert {:error, :opaque_key_unsupported} = Mac.mac("d", @data_handle, "a")
      assert {:error, :opaque_key_unsupported} = Mac.verify("d", <<0::256>>, @data_handle, "a")
    end

    test "the cipher refuses a :mac key handle" do
      assert {:error, :opaque_key_unsupported} = Cipher.encrypt("d", @mac_handle, "a")

      assert {:error, :opaque_key_unsupported} =
               Cipher.decrypt(
                 %{ciphertext: "vault:v1:AAAA", nonce: "", tag: ""},
                 @mac_handle,
                 "a"
               )
    end

    test "raw key bytes are refused: there is no transit key name to invent" do
      assert {:error, :requires_open_bao_transit_key_provider} = Mac.mac("d", <<0::256>>, "a")
    end

    test "unwrap/1 and unwrap_mac/1 each accept only their own shape" do
      assert {:ok, {"ashvault_nx_YWJj.mac", 1}} = Provider.unwrap_mac(@mac_handle)
      assert :error = Provider.unwrap_mac(@data_handle)
      assert :error = Provider.unwrap(@mac_handle)
      assert {:ok, {"ashvault_nx_YWJj", 1}} = Provider.unwrap(@data_handle)
    end

    test "a :mac handle is inspected without its key name" do
      refute inspect(@mac_handle) =~ "YWJj"
    end
  end

  describe "decided locally" do
    test "a tag that is not 32 bytes is :invalid_tag, with no round trip" do
      for bad <- ["", <<0::128>>, <<0::264>>, nil, 7] do
        assert {:error, :invalid_tag} = Mac.verify("d", bad, @mac_handle, "a")
      end
    end

    test "an unreachable server is ProviderUnavailable, never :invalid_tag" do
      assert {:error, %ProviderUnavailable{}} = Mac.mac("d", @mac_handle, "a")
      assert {:error, %ProviderUnavailable{}} = Mac.verify("d", <<0::256>>, @mac_handle, "a")
    end
  end

  describe "decode_tag/2" do
    test "requires the version asked for, and 32 bytes" do
      tag = :crypto.strong_rand_bytes(32)

      assert {:ok, ^tag} = Mac.decode_tag("vault:v3:" <> Base.encode64(tag), 3)

      assert {:error, %ProviderUnavailable{}} =
               Mac.decode_tag("vault:v2:" <> Base.encode64(tag), 3)

      assert {:error, %ProviderUnavailable{}} =
               Mac.decode_tag("vault:v3:" <> Base.encode64(<<1>>), 3)

      assert {:error, %ProviderUnavailable{}} = Mac.decode_tag("vault:v3:%%%", 3)
      assert {:error, %ProviderUnavailable{}} = Mac.decode_tag("v3:" <> Base.encode64(tag), 3)
      assert {:error, %ProviderUnavailable{}} = Mac.decode_tag(nil, 3)
    end
  end
end
