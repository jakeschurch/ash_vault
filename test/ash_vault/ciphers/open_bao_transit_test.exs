defmodule AshVault.Ciphers.OpenBaoTransitVaultTest do
  @moduledoc """
  End-to-end suite for the non-exporting pairing: `AshVault.KeyProviders.OpenBaoTransit`
  serving handles, `AshVault.Ciphers.OpenBaoTransit` doing the AEAD inside OpenBao, and
  `AshVault.Vault.Runtime` joining them.

  Tagged `:openbao`, excluded by default, and skipped entirely when the server is
  unreachable.

      mix test --include openbao test/ash_vault/ciphers/open_bao_transit_test.exs
  """

  use ExUnit.Case, async: false

  alias AshVault.Ciphers.OpenBaoTransit, as: Cipher
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.OpaqueKeyUnsupported
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBaoTransit, as: Provider
  alias AshVault.Test.Support.Helpers
  alias AshVault.Test.Support.Resources
  alias AshVault.Test.Support.TransitVault

  ExUnit.configure(exclude: Enum.uniq([:openbao | ExUnit.configuration()[:exclude] || []]))

  @address System.get_env("BAO_ADDR") || "http://127.0.0.1:8200"
  @token System.get_env("BAO_TOKEN") || "ashvault-root"
  @kv_mount "ashvault"
  @transit_mount "transit"

  @scope_prefix "nxc"
  @name_prefix "ashvault_nx_" <> Base.url_encode64(@scope_prefix, padding: false)

  @server_up (case URI.parse(@address) do
                %URI{host: host, port: port} when is_binary(host) and is_integer(port) ->
                  case :gen_tcp.connect(String.to_charlist(host), port, [:binary], 1_000) do
                    {:ok, socket} ->
                      :gen_tcp.close(socket)
                      true

                    _ ->
                      false
                  end

                _ ->
                  false
              end)

  @moduletag :openbao

  if not @server_up do
    @moduletag skip: "OpenBao is not reachable at #{@address}"
  end

  setup_all do
    put_config()
    :ok = Provider.setup()
    on_exit(&clean_up/0)
    :ok
  end

  setup do
    put_config()
    %{tenant: @scope_prefix <> "_#{System.unique_integer([:positive])}"}
  end

  describe "round trip through a vault" do
    test "encrypt! then decrypt! returns the plaintext", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)

      blob = TransitVault.encrypt!("123-45-6789", ctx)
      assert TransitVault.decrypt!(blob, ctx) == "123-45-6789"
    end

    test "an empty string and a long value both round-trip", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      long = String.duplicate("a", 10_000)

      assert TransitVault.decrypt!(TransitVault.encrypt!("", ctx), ctx) == ""
      assert TransitVault.decrypt!(TransitVault.encrypt!(long, ctx), ctx) == long
    end

    test "the envelope carries the transit ciphertext verbatim, plus our own header",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)

      assert {:ok, env} = AshVault.Envelope.decode(blob)
      assert env.version == 1
      assert env.cipher == "openbao_transit_v1"
      assert env.key_version == 1

      # Transit's own AEAD nonce and tag live inside its base64 blob; our slots are empty.
      assert env.nonce == ""
      assert env.tag == ""

      # Stored verbatim, so a future transit ciphertext shape keeps working unchanged.
      assert String.starts_with?(env.ciphertext, "vault:v1:")
      assert {:ok, 1} = Cipher.parse_version(env.ciphertext)
    end

    test "the plaintext is nowhere in the stored bytes", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("wildly-distinctive-plaintext", ctx)

      refute blob =~ "wildly-distinctive-plaintext"
    end

    test "the cipher is resolved from the envelope, not from the vault default",
         %{tenant: tenant} do
      assert {:ok, Cipher} = AshVault.Cipher.fetch("openbao_transit_v1")
      assert {:ok, Cipher} = AshVault.Cipher.fetch(:openbao_transit_v1)

      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("x", ctx)
      assert {:ok, %{cipher: "openbao_transit_v1"}} = AshVault.Envelope.decode(blob)
    end
  end

  describe "AAD binding survives moving the AEAD into OpenBao" do
    test "cross-tenant substitution fails with CiphertextIntegrityFailed",
         %{tenant: tenant} do
      other = @scope_prefix <> "_#{System.unique_integer([:positive])}"

      victim = Helpers.context_for(tenant)
      attacker = Helpers.context_for(other)

      blob = TransitVault.encrypt!("mine", victim)
      # The other tenant must have a key, or this would fail as :not_found instead.
      _ = TransitVault.encrypt!("theirs", attacker)

      assert_raise CiphertextIntegrityFailed, fn ->
        TransitVault.decrypt!(blob, attacker)
      end
    end

    test "cross-field substitution fails, under the very same transit key",
         %{tenant: tenant} do
      ssn = Helpers.context_for(tenant, field: :ssn)
      email = Helpers.context_for(tenant, field: :email)

      # Same scope, so the same transit key and the same key version. Only the AAD
      # differs — which is precisely what `associated_data` has to be enforcing.
      assert Provider.key_name(tenant) == Provider.key_name(tenant)

      blob = TransitVault.encrypt!("123-45-6789", ssn)
      assert TransitVault.decrypt!(blob, ssn) == "123-45-6789"

      assert_raise CiphertextIntegrityFailed, fn ->
        TransitVault.decrypt!(blob, email)
      end
    end

    test "cross-resource substitution fails", %{tenant: tenant} do
      user = Helpers.context_for(tenant, resource: Resources.User)
      invoice = Helpers.context_for(tenant, resource: Resources.Invoice)

      blob = TransitVault.encrypt!("shared-looking", user)

      assert_raise CiphertextIntegrityFailed, fn ->
        TransitVault.decrypt!(blob, invoice)
      end
    end

    test "a tampered transit ciphertext body fails authentication", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)

      assert {:ok, env} = AshVault.Envelope.decode(blob)

      "vault:v1:" <> body = env.ciphertext
      flipped = flip_base64_char(body, 5)

      tampered =
        AshVault.Envelope.V1.encode(%{
          cipher: env.cipher,
          key_version: env.key_version,
          nonce: env.nonce,
          tag: env.tag,
          ciphertext: "vault:v1:" <> flipped
        })

      assert_raise CiphertextIntegrityFailed, fn -> TransitVault.decrypt!(tampered, ctx) end
    end

    test "a corrupted, undecodable ciphertext body is integrity failure, not an outage",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)
      assert {:ok, env} = AshVault.Envelope.decode(blob)

      for broken <- ["vault:v1:!!!!notbase64", "vault:v1:", "vault:v1:QQ"] do
        corrupted =
          AshVault.Envelope.V1.encode(%{
            cipher: env.cipher,
            key_version: env.key_version,
            nonce: env.nonce,
            tag: env.tag,
            ciphertext: broken
          })

        # "the value in your database is not the value we wrote" — retrying will never
        # help, so it must not be reported as a retryable provider outage.
        assert_raise CiphertextIntegrityFailed, fn -> TransitVault.decrypt!(corrupted, ctx) end
      end
    end

    test "a ciphertext whose embedded version disagrees with the envelope is refused",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)
      assert {:ok, env} = AshVault.Envelope.decode(blob)

      # The encrypt above already minted v1, so this is the rotation to v2.
      assert {:ok, 2} = Provider.rotate(tenant)

      # Envelope says v2, the transit string still says v1. They are written from one
      # handle, so disagreement means the stored bytes were spliced.
      spliced =
        AshVault.Envelope.V1.encode(%{
          cipher: env.cipher,
          key_version: 2,
          nonce: env.nonce,
          tag: env.tag,
          ciphertext: env.ciphertext
        })

      assert_raise CiphertextIntegrityFailed, fn -> TransitVault.decrypt!(spliced, ctx) end
    end
  end

  describe "rotation" do
    test "old ciphertext still decrypts after a rotation, new writes use the new version",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)

      old = TransitVault.encrypt!("before", ctx)
      assert {:ok, %{key_version: 1}} = AshVault.Envelope.decode(old)

      assert {:ok, 2} = TransitVault.rotate!(tenant)

      new = TransitVault.encrypt!("after", ctx)
      assert {:ok, %{key_version: 2}} = AshVault.Envelope.decode(new)

      assert TransitVault.decrypt!(old, ctx) == "before"
      assert TransitVault.decrypt!(new, ctx) == "after"
    end
  end

  describe "crypto-erasure" do
    test "after destroy, reads are KeyDestroyed and writes refuse", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("erase me", ctx)

      assert :ok = TransitVault.destroy!(tenant)

      assert_raise KeyDestroyed, fn -> TransitVault.decrypt!(blob, ctx) end
      assert_raise KeyDestroyed, fn -> TransitVault.encrypt!("again", ctx) end

      # Never reported as tampering: erasure is deliberate, and the operator must be able
      # to tell the two apart.
      assert %KeyDestroyed{} =
               assert_raise(KeyDestroyed, fn -> TransitVault.decrypt!(blob, ctx) end)
    end

    test "destroying one tenant leaves another working", %{tenant: tenant} do
      other = @scope_prefix <> "_#{System.unique_integer([:positive])}"
      doomed = Helpers.context_for(tenant)
      kept = Helpers.context_for(other)

      doomed_blob = TransitVault.encrypt!("doomed", doomed)
      kept_blob = TransitVault.encrypt!("kept", kept)

      assert :ok = TransitVault.destroy!(tenant)

      assert_raise KeyDestroyed, fn -> TransitVault.decrypt!(doomed_blob, doomed) end
      assert TransitVault.decrypt!(kept_blob, kept) == "kept"
    end
  end

  describe "pairing mistakes are named, never silently worked around" do
    test "a local cipher given this provider's handle raises OpaqueKeyUnsupported",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)

      error =
        assert_raise OpaqueKeyUnsupported, fn ->
          AshVault.Test.Support.TransitWithLocalCipherVault.encrypt!("x", ctx)
        end

      message = Exception.message(error)
      assert message =~ "AshVault.Ciphers.AES.GCM"
      assert message =~ "AshVault.KeyProviders.OpenBaoTransit"
    end

    test "this cipher given raw key bytes refuses rather than inventing a key name" do
      assert {:error, :requires_open_bao_transit_key_provider} =
               Cipher.encrypt("x", <<0::256>>, "aad")

      assert {:error, :requires_open_bao_transit_key_provider} =
               Cipher.decrypt(%{ciphertext: "vault:v1:x", nonce: "", tag: ""}, <<0::256>>, "aad")
    end

    test "this cipher given a foreign opaque handle reports opaque_key_unsupported" do
      foreign = %AshVault.Key{ref: make_ref(), owner: SomeOtherProvider}

      assert {:error, :opaque_key_unsupported} = Cipher.encrypt("x", foreign, "aad")
    end
  end

  describe "an outage is never reported as tampering" do
    test "a deleted transit key is ProviderUnavailable out of the cipher",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)
      assert {:ok, env} = AshVault.Envelope.decode(blob)

      name = Provider.key_name(tenant)
      {:ok, handle} = Provider.get_key(tenant, 1)

      # Delete the transit key WITHOUT a tombstone: the provider would say `:destroyed`,
      # so the cipher is exercised directly to isolate its own error mapping.
      raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{deletion_allowed: true})
      assert %{status: 204} = raw(:delete, "/v1/#{@transit_mount}/keys/#{name}")

      aad = AshVault.Vault.Runtime.build_aad(tenant, ctx)

      assert {:error, %ProviderUnavailable{provider: Provider}} =
               Cipher.decrypt(
                 %{ciphertext: env.ciphertext, nonce: "", tag: ""},
                 handle,
                 aad
               )
    end

    test "an unreachable server is ProviderUnavailable out of the cipher",
         %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)
      blob = TransitVault.encrypt!("secret", ctx)
      assert {:ok, env} = AshVault.Envelope.decode(blob)
      {:ok, handle} = Provider.get_key(tenant, 1)
      aad = AshVault.Vault.Runtime.build_aad(tenant, ctx)

      put_config(address: "http://127.0.0.1:1", max_retries: 0)

      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} =
               Cipher.decrypt(%{ciphertext: env.ciphertext, nonce: "", tag: ""}, handle, aad)

      assert {:error, %ProviderUnavailable{reason: {:transport, _}}} =
               Cipher.encrypt("x", handle, aad)
    end
  end

  describe "the round-trip cost, measured rather than asserted" do
    # The number in the moduledocs and in documentation/topics/threat-model.md. It is the
    # single most important thing to be honest about for this provider, and "one round
    # trip per value" was wrong: the provider checks the tombstone and reads the key
    # metadata before the cipher ever issues its transit call.
    test "encrypt and decrypt each cost three HTTP calls per value", %{tenant: tenant} do
      ctx = Helpers.context_for(tenant)

      # Warm: the very first encrypt also CREATES the transit key, which is one more call.
      _ = TransitVault.encrypt!("warm", ctx)

      assert {encrypt_calls, blob} = count_http(fn -> TransitVault.encrypt!("secret", ctx) end)
      assert {decrypt_calls, "secret"} = count_http(fn -> TransitVault.decrypt!(blob, ctx) end)

      # tombstone GET + transit/keys GET + transit/encrypt POST
      assert encrypt_calls == 3
      # tombstone GET + transit/keys GET + transit/decrypt POST
      assert decrypt_calls == 3
    end
  end

  describe "parse_version/1" do
    test "reads the version transit embeds in its own ciphertext" do
      assert {:ok, 1} = Cipher.parse_version("vault:v1:abc")
      assert {:ok, 42} = Cipher.parse_version("vault:v42:abc")
      assert :error = Cipher.parse_version("vault:v0:abc")
      assert :error = Cipher.parse_version("vault:vx:abc")
      assert :error = Cipher.parse_version("vault:v1")
      assert :error = Cipher.parse_version("")
      assert :error = Cipher.parse_version("AV\x01nonsense")
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────

  defp put_config(overrides \\ []) do
    config =
      Keyword.merge([address: @address, token: @token, kv_mount: @kv_mount], overrides)

    previous = Application.get_env(:ash_vault, Provider)
    Application.put_env(:ash_vault, Provider, config)

    on_exit(fn ->
      if previous do
        Application.put_env(:ash_vault, Provider, previous)
      else
        Application.delete_env(:ash_vault, Provider)
      end
    end)

    :ok
  end

  # Counts Finch requests issued while `fun` runs. Req is built on Finch, so every call
  # this library makes to OpenBao emits exactly one `[:finch, :request, :stop]`.
  defp count_http(fun) do
    handler = "ashvault-count-#{System.unique_integer([:positive])}"
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    :telemetry.attach(
      handler,
      [:finch, :request, :stop],
      fn _event, _measurements, _metadata, _config -> Agent.update(counter, &(&1 + 1)) end,
      nil
    )

    try do
      result = fun.()
      {Agent.get(counter, & &1), result}
    after
      :telemetry.detach(handler)
      Agent.stop(counter)
    end
  end

  # Deliberately NOT the last character: transit's base64 is padded, and replacing a
  # `=` produces "invalid ciphertext: could not decode base64" rather than a MAC failure.
  # Both are CiphertextIntegrityFailed, but this test is about the AEAD specifically.
  defp flip_base64_char(body, at) do
    <<head::binary-size(^at), char::binary-size(1), tail::binary>> = body
    head <> if(char == "A", do: "B", else: "A") <> tail
  end

  defp raw(method, path, body \\ nil) do
    options = [
      method: method,
      base_url: @address,
      url: path,
      headers: [{"x-vault-token", @token}],
      receive_timeout: 5_000
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options

    case options |> Req.new() |> Req.request() do
      {:ok, response} -> response
      {:error, exception} -> exception
    end
  end

  defp clean_up do
    for name <- list("/v1/#{@transit_mount}/keys"), String.starts_with?(name, @name_prefix) do
      raw(:post, "/v1/#{@transit_mount}/keys/#{name}/config", %{deletion_allowed: true})
      raw(:delete, "/v1/#{@transit_mount}/keys/#{name}")
    end

    for name <- list("/v1/#{@kv_mount}/metadata/tombstones"),
        String.starts_with?(name, @name_prefix) do
      raw(:delete, "/v1/#{@kv_mount}/metadata/tombstones/#{name}")
    end

    :ok
  end

  defp list(path) do
    case raw(:get, path <> "?list=true") do
      %Req.Response{status: 200, body: %{"data" => %{"keys" => keys}}} when is_list(keys) ->
        keys

      _ ->
        []
    end
  end
end
