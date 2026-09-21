defmodule AshVault.VaultTest do
  # Not async: the `AshVault.KeyProvider` callbacks take no server name, so a vault
  # always talks to the default-named provider process. Each test starts a fresh one.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Context
  alias AshVault.Envelope
  alias AshVault.Errors.AuthenticationFailed
  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.MissingScope
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Errors.UnsupportedEnvelope
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Support.FailingRotateVault
  alias AshVault.Test.Support.GlobalVault
  alias AshVault.Test.Support.Resources
  alias AshVault.Test.Support.RotatingVault
  alias AshVault.Test.Support.TenantVault
  alias AshVault.Test.Support.UnavailableVault
  alias AshVault.Vault.Runtime

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp ctx(opts \\ []) do
    %Context{
      resource: Keyword.get(opts, :resource, Resources.User),
      field: Keyword.get(opts, :field, :ssn),
      ash_context: %{
        tenant: Keyword.get(opts, :tenant, "acme"),
        actor: nil,
        source_context: %{}
      }
    }
  end

  describe "introspection" do
    test "__ash_vault__/1 reports the configured modules" do
      assert TenantVault.__ash_vault__(:key_provider) == Memory
      assert TenantVault.__ash_vault__(:cipher) == AshVault.Ciphers.AES.GCM
      assert TenantVault.__ash_vault__(:envelope) == AshVault.Envelope.V1
      assert TenantVault.__ash_vault__(:scope) == AshVault.Scopes.AshTenant
      assert TenantVault.__ash_vault__(:rotation_policy) == AshVault.RotationPolicies.Manual
      assert GlobalVault.__ash_vault__(:scope) == AshVault.Scopes.Global
    end

    test "a vault without a key provider does not compile" do
      assert_raise ArgumentError, ~r/requires a `:key_provider`/, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.NoProviderVault#{System.unique_integer([:positive])} do
          use AshVault.Vault
        end
        """)
      end
    end
  end

  describe "roundtrip" do
    test "encrypt! then decrypt! returns the plaintext" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      assert is_binary(blob)
      refute blob =~ "hunter2"
      assert TenantVault.decrypt!(blob, ctx()) == "hunter2"
    end

    test "empty and large plaintexts roundtrip" do
      assert TenantVault.decrypt!(TenantVault.encrypt!("", ctx()), ctx()) == ""

      big = :crypto.strong_rand_bytes(100_000)
      assert TenantVault.decrypt!(TenantVault.encrypt!(big, ctx()), ctx()) == big
    end

    test "the envelope carries the cipher and key version" do
      blob = TenantVault.encrypt!("hunter2", ctx())

      assert {:ok, env} = Envelope.decode(blob)
      assert env.version == 1
      assert env.cipher == "aes_256_gcm_v1"
      assert env.key_version == 1
    end

    test "each encryption of the same plaintext differs" do
      assert TenantVault.encrypt!("same", ctx()) != TenantVault.encrypt!("same", ctx())
    end

    test "the global scope vault roundtrips without a tenant" do
      ctx = %Context{resource: Resources.User, field: :ssn, ash_context: nil}
      assert GlobalVault.decrypt!(GlobalVault.encrypt!("x", ctx), ctx) == "x"
    end
  end

  describe "associated data binding" do
    test "build_aad/2 has the frozen format" do
      assert Runtime.build_aad("acme", ctx()) ==
               "ashvault:v1|acme|AshVault.Test.Support.Resources.User|ssn"
    end

    test "cross-scope decrypt raises AuthenticationFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(tenant: "acme"))

      # Give the other tenant a key of its own, so the failure is the AAD/key mismatch
      # rather than a missing key.
      _ = TenantVault.encrypt!("other", ctx(tenant: "globex"))

      assert_raise AuthenticationFailed, fn ->
        TenantVault.decrypt!(blob, ctx(tenant: "globex"))
      end
    end

    test "cross-field decrypt raises AuthenticationFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(field: :ssn))

      assert_raise AuthenticationFailed, fn ->
        TenantVault.decrypt!(blob, ctx(field: :dob))
      end
    end

    test "cross-resource decrypt raises AuthenticationFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(resource: Resources.User))

      assert_raise AuthenticationFailed, fn ->
        TenantVault.decrypt!(blob, ctx(resource: Resources.Invoice))
      end
    end

    test "the error carries resource, field and key version" do
      blob = TenantVault.encrypt!("hunter2", ctx())

      error =
        assert_raise AuthenticationFailed, fn ->
          TenantVault.decrypt!(blob, ctx(field: :dob))
        end

      assert error.resource == Resources.User
      assert error.field == :dob
      assert error.key_version == 1
    end

    test "tampered ciphertext raises AuthenticationFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      size = byte_size(blob)
      <<prefix::binary-size(^size - 1), byte>> = blob
      tampered = <<prefix::binary, Bitwise.bxor(byte, 0xFF)>>

      assert_raise AuthenticationFailed, fn -> TenantVault.decrypt!(tampered, ctx()) end
    end
  end

  describe "malformed input" do
    test "garbage raises InvalidCiphertext" do
      for blob <- ["", "AV", "not an envelope"] do
        assert_raise InvalidCiphertext, fn -> TenantVault.decrypt!(blob, ctx()) end
      end
    end

    test "an unknown envelope version raises UnsupportedEnvelope" do
      assert_raise UnsupportedEnvelope, fn ->
        TenantVault.decrypt!(<<"AV", 9::8, "rest">>, ctx())
      end
    end

    test "an unknown key version raises KeyNotFound" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      {:ok, env} = Envelope.decode(blob)
      forged = AshVault.Envelope.V1.encode(%{env | key_version: 42})

      assert_raise KeyNotFound, fn -> TenantVault.decrypt!(forged, ctx()) end
    end
  end

  describe "missing tenant" do
    test "encrypt! raises MissingScope with the operator-facing message" do
      ctx = %Context{resource: Resources.User, field: :ssn, ash_context: %{}}

      error = assert_raise MissingScope, fn -> TenantVault.encrypt!("x", ctx) end

      assert Exception.message(error) =~
               "Cannot encrypt AshVault.Test.Support.Resources.User.ssn because no Ash tenant was present."

      assert Exception.message(error) =~ "This resource uses tenant-scoped encryption."

      assert Exception.message(error) =~
               "Pass a tenant when executing the Ash action or configure another AshVault scope."
    end

    test "decrypt! raises MissingScope too" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      ctx = %Context{resource: Resources.User, field: :ssn, ash_context: nil}

      assert_raise MissingScope, fn -> TenantVault.decrypt!(blob, ctx) end
    end
  end

  describe "rotation" do
    test "old blobs still decrypt and new blobs carry the new key version" do
      old = TenantVault.encrypt!("old secret", ctx())
      assert {:ok, %{key_version: 1}} = Envelope.decode(old)

      assert {:ok, 2} = TenantVault.rotate!("acme")

      new = TenantVault.encrypt!("new secret", ctx())
      assert {:ok, %{key_version: 2}} = Envelope.decode(new)

      assert TenantVault.decrypt!(old, ctx()) == "old secret"
      assert TenantVault.decrypt!(new, ctx()) == "new secret"
    end

    test "AshVault.rotate_key!/2 delegates to the vault" do
      assert {:ok, %{version: 1}} = Memory.current_key("acme")
      assert {:ok, 2} = AshVault.rotate_key!(TenantVault, "acme")
    end

    test "rotate_on_write? rotates opportunistically" do
      assert {:ok, %{version: 1}} = Memory.current_key("acme")
      Process.sleep(2)

      blob = RotatingVault.encrypt!("secret", ctx())
      assert {:ok, %{key_version: 2}} = Envelope.decode(blob)
      assert RotatingVault.decrypt!(blob, ctx()) == "secret"
    end

    test "a failing rotation never fails the write" do
      log =
        capture_log(fn ->
          blob = FailingRotateVault.encrypt!("secret", ctx())
          assert {:ok, %{key_version: 1}} = Envelope.decode(blob)
          assert FailingRotateVault.decrypt!(blob, ctx()) == "secret"
        end)

      assert log =~ "key rotation for scope"
    end

    test "rotating a destroyed scope raises KeyDestroyed" do
      assert {:ok, _} = Memory.current_key("acme")
      assert :ok = TenantVault.destroy!("acme")

      assert_raise KeyDestroyed, fn -> TenantVault.rotate!("acme") end
    end
  end

  describe "destruction" do
    test "decrypt after destroy raises KeyDestroyed, never AuthenticationFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx())

      assert :ok = TenantVault.destroy!("acme")

      error = assert_raise KeyDestroyed, fn -> TenantVault.decrypt!(blob, ctx()) end
      assert error.scope == "acme"
      assert error.key_version == 1
      assert Exception.message(error) =~ "cryptographically erased"
    end

    test "encrypt after destroy raises KeyDestroyed, never minting a fresh key" do
      assert :ok = TenantVault.destroy!("acme")
      assert_raise KeyDestroyed, fn -> TenantVault.encrypt!("hunter2", ctx()) end
    end

    test "destroying one tenant leaves the others readable" do
      acme = TenantVault.encrypt!("acme secret", ctx(tenant: "acme"))
      globex = TenantVault.encrypt!("globex secret", ctx(tenant: "globex"))

      assert :ok = AshVault.destroy_keys!(TenantVault, "acme")

      assert_raise KeyDestroyed, fn -> TenantVault.decrypt!(acme, ctx(tenant: "acme")) end
      assert TenantVault.decrypt!(globex, ctx(tenant: "globex")) == "globex secret"
    end

    test "destroy is idempotent" do
      assert :ok = TenantVault.destroy!("acme")
      assert :ok = TenantVault.destroy!("acme")
    end
  end

  describe "provider failures" do
    test "an unavailable provider surfaces as ProviderUnavailable" do
      error = assert_raise ProviderUnavailable, fn -> UnavailableVault.encrypt!("x", ctx()) end
      assert error.provider == AshVault.Test.Support.UnavailableProvider
      assert error.reason == :timeout

      blob = TenantVault.encrypt!("x", ctx())
      assert_raise ProviderUnavailable, fn -> UnavailableVault.decrypt!(blob, ctx()) end
      assert_raise ProviderUnavailable, fn -> UnavailableVault.rotate!("acme") end
      assert_raise ProviderUnavailable, fn -> UnavailableVault.destroy!("acme") end
    end
  end
end
