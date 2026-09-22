defmodule AshVault.VaultTest do
  # Not async: the `AshVault.KeyProvider` callbacks take no server name, so a vault
  # always talks to the default-named provider process. Each test starts a fresh one.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Context
  alias AshVault.Envelope
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.InvalidScope
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.KeySizeMismatch
  alias AshVault.Errors.MissingScope
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Errors.UnsupportedEnvelope
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.Support.FailingRotateVault
  alias AshVault.Test.Support.DestroyedRotateVault
  alias AshVault.Test.Support.FixedKeyVault
  alias AshVault.Test.Support.GlobalVault
  alias AshVault.Test.Support.NonBinaryScopeVault
  alias AshVault.Test.Support.ShortKeyProvider
  alias AshVault.Test.Support.StructScopeVault
  alias AshVault.Test.Support.ShortKeyVault
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

    test "cross-scope decrypt raises CiphertextIntegrityFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(tenant: "acme"))

      # Give the other tenant a key of its own, so the failure is the AAD/key mismatch
      # rather than a missing key.
      _ = TenantVault.encrypt!("other", ctx(tenant: "globex"))

      assert_raise CiphertextIntegrityFailed, fn ->
        TenantVault.decrypt!(blob, ctx(tenant: "globex"))
      end
    end

    # P2 #16. The test above cannot distinguish "the AAD bound the scope" from "the two
    # tenants simply have different keys" — with per-scope keys, decryption would fail
    # either way. FixedKeyVault hands out the SAME key for every scope, so the ONLY
    # thing that differs between these two calls is the scope inside the AAD.
    test "cross-scope decrypt fails on the AAD alone, with an identical key" do
      acme = ctx(tenant: "acme")
      globex = ctx(tenant: "globex")

      # Same key, both scopes — proving the point of the fixture.
      assert {:ok, key} = AshVault.Test.Support.FailingRotateProvider.get_key("acme", 1)
      assert {:ok, ^key} = AshVault.Test.Support.FailingRotateProvider.get_key("globex", 1)

      blob = FixedKeyVault.encrypt!("hunter2", acme)
      assert FixedKeyVault.decrypt!(blob, acme) == "hunter2"

      assert_raise CiphertextIntegrityFailed, fn -> FixedKeyVault.decrypt!(blob, globex) end
    end

    test "cross-field and cross-resource also fail on the AAD alone" do
      blob = FixedKeyVault.encrypt!("hunter2", ctx())

      assert_raise CiphertextIntegrityFailed, fn ->
        FixedKeyVault.decrypt!(blob, ctx(field: :dob))
      end

      assert_raise CiphertextIntegrityFailed, fn ->
        FixedKeyVault.decrypt!(blob, ctx(resource: Resources.Invoice))
      end
    end

    test "cross-field decrypt raises CiphertextIntegrityFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(field: :ssn))

      assert_raise CiphertextIntegrityFailed, fn ->
        TenantVault.decrypt!(blob, ctx(field: :dob))
      end
    end

    test "cross-resource decrypt raises CiphertextIntegrityFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx(resource: Resources.User))

      assert_raise CiphertextIntegrityFailed, fn ->
        TenantVault.decrypt!(blob, ctx(resource: Resources.Invoice))
      end
    end

    test "the error carries resource, field and key version" do
      blob = TenantVault.encrypt!("hunter2", ctx())

      error =
        assert_raise CiphertextIntegrityFailed, fn ->
          TenantVault.decrypt!(blob, ctx(field: :dob))
        end

      assert error.resource == Resources.User
      assert error.field == :dob
      assert error.key_version == 1
    end

    test "tampered ciphertext raises CiphertextIntegrityFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      size = byte_size(blob)
      <<prefix::binary-size(^size - 1), byte>> = blob
      tampered = <<prefix::binary, Bitwise.bxor(byte, 0xFF)>>

      assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(tampered, ctx()) end
    end

    # An earlier name for this error borrowed the word "authentication" and was misread,
    # by this project's own author, as an authorization failure — the mis-triage that
    # turns "someone is writing to your ciphertext columns" into "someone lacks a
    # permission". The name is fixed; the message says it out loud too, because the
    # message is what an operator actually reads.
    test "the message says what happened and that it is NOT an authorization error" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      size = byte_size(blob)
      <<prefix::binary-size(^size - 1), byte>> = blob
      tampered = <<prefix::binary, Bitwise.bxor(byte, 0xFF)>>

      error =
        assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(tampered, ctx()) end

      message = Exception.message(error)

      assert message =~ "failed its integrity check"
      assert message =~ "key version 1"
      assert message =~ "This is not an authorization error."
      assert message =~ "AshVault performs no authorization"
      refute message =~ "Failed to authenticate"
    end
  end

  describe "truncated authentication tags" do
    # Finding 6. `:crypto.crypto_one_time_aead/7` on OTP 29 accepts a truncated GCM tag
    # and compares only its leading bytes (verified: 1, 2, 4, 8, 12 all return
    # plaintext; only a 0-byte tag is rejected). The envelope carries `tag_len` as a
    # byte straight out of the database, and GCM is CTR mode — so anyone who can write
    # a row could XOR the ciphertext to a chosen plaintext, set `tag_len: 1`, and
    # enumerate 0x00..0xFF for a guaranteed forgery within 256 reads.
    test "a 1-byte-tag forgery of a chosen plaintext is rejected in all 256 attempts" do
      plaintext = "hunter2"
      desired = "pwned!!"

      blob = TenantVault.encrypt!(plaintext, ctx())
      assert {:ok, env} = Envelope.decode(blob)

      # CTR mode: flip the keystream output to whatever we like.
      forged_ciphertext = :crypto.exor(env.ciphertext, :crypto.exor(plaintext, desired))

      results =
        for byte <- 0..255 do
          forged =
            AshVault.Envelope.V1.encode(%{
              env
              | ciphertext: forged_ciphertext,
                tag: <<byte>>
            })

          try do
            {:decrypted, TenantVault.decrypt!(forged, ctx())}
          rescue
            error in [CiphertextIntegrityFailed] -> {:rejected, error}
          end
        end

      assert Enum.all?(results, &match?({:rejected, _}, &1)),
             "a truncated tag was accepted: #{inspect(Enum.find(results, &match?({:decrypted, _}, &1)))}"
    end

    test "every truncated tag length is rejected, including the correct prefix" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      assert {:ok, env} = Envelope.decode(blob)

      for len <- [0, 1, 2, 4, 8, 12, 15] do
        forged = AshVault.Envelope.V1.encode(%{env | tag: binary_part(env.tag, 0, len)})

        assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(forged, ctx()) end
      end

      # An over-long tag is no better.
      forged = AshVault.Envelope.V1.encode(%{env | tag: env.tag <> <<0>>})
      assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(forged, ctx()) end
    end

    test "a truncated nonce is rejected" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      assert {:ok, env} = Envelope.decode(blob)

      for len <- [0, 1, 8, 11] do
        forged = AshVault.Envelope.V1.encode(%{env | nonce: binary_part(env.nonce, 0, len)})

        assert_raise CiphertextIntegrityFailed, fn -> TenantVault.decrypt!(forged, ctx()) end
      end
    end

    test "the untampered envelope still decrypts" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      assert TenantVault.decrypt!(blob, ctx()) == "hunter2"
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

    # P2 #18: runtime.ex's UnsupportedCipher branch had no end-to-end coverage.
    test "an envelope naming an unregistered cipher raises UnsupportedCipher" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      {:ok, env} = Envelope.decode(blob)
      forged = AshVault.Envelope.V1.encode(%{env | cipher: "chacha_from_the_future_v9"})

      error =
        assert_raise AshVault.Errors.UnsupportedCipher, fn ->
          TenantVault.decrypt!(forged, ctx())
        end

      assert error.cipher_id == "chacha_from_the_future_v9"
      # Resolved before the key is fetched, so it is never mistaken for tampering.
      refute Exception.message(error) =~ "tampered"
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
    test "decrypt after destroy raises KeyDestroyed, never CiphertextIntegrityFailed" do
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

  describe "key size mismatch (finding 8)" do
    # `AshVault.KeyProvider.key_bytes/1` had zero callers. A provider serving keys of
    # the wrong size was reported as two different lies: CiphertextIntegrityFailed on
    # decrypt ("your data was tampered with", for a config typo) and a *retryable*
    # ProviderUnavailable naming the CIPHER as the provider on encrypt — so operators
    # retry a permanent misconfiguration forever.
    test "encrypt raises KeySizeMismatch, not ProviderUnavailable" do
      error = assert_raise KeySizeMismatch, fn -> ShortKeyVault.encrypt!("x", ctx()) end

      assert error.provider == ShortKeyProvider
      assert error.cipher == AshVault.Ciphers.AES.GCM
      assert error.expected == 32
      assert error.actual == 16

      message = Exception.message(error)
      assert message =~ "requires 32-byte keys"
      assert message =~ "supplied 16 bytes"
      assert message =~ "configuration fault"
      refute message =~ "was tampered with"
    end

    test "decrypt raises KeySizeMismatch, never CiphertextIntegrityFailed" do
      blob = TenantVault.encrypt!("hunter2", ctx())

      error = assert_raise KeySizeMismatch, fn -> ShortKeyVault.decrypt!(blob, ctx()) end
      assert error.actual == 16
    end

    test "a provider/cipher size disagreement is caught at compile time" do
      unique = System.unique_integer([:positive])

      Code.eval_string("""
      defmodule AshVault.Test.SmallKeyProvider#{unique} do
        @behaviour AshVault.KeyProvider
        def key_bytes, do: 16
        def current_key(_), do: {:error, :nope}
        def get_key(_, _), do: {:error, :nope}
        def rotate(_), do: {:error, :nope}
        def destroy(_), do: :ok
      end
      """)

      assert_raise ArgumentError, ~r/disagree on key size/, fn ->
        Code.eval_string("""
        defmodule AshVault.Test.SmallKeyVault#{unique} do
          use AshVault.Vault, key_provider: AshVault.Test.SmallKeyProvider#{unique}
        end
        """)
      end
    end
  end

  describe "non-binary scopes (finding 9)" do
    test "a Scope returning a non-binary raises InvalidScope, not a provider error" do
      error = assert_raise InvalidScope, fn -> NonBinaryScopeVault.encrypt!("x", ctx()) end

      assert error.scope_module == AshVault.Test.Support.NonBinaryScope
      assert Exception.message(error) =~ "which is not a binary"
      assert Exception.message(error) =~ "stable across"
    end

    test "the same check applies on decrypt" do
      blob = TenantVault.encrypt!("hunter2", ctx())
      assert_raise InvalidScope, fn -> NonBinaryScopeVault.decrypt!(blob, ctx()) end
    end

    # `inspect(scope, structs: false)` rendered a loaded tenant record as a bare map with
    # every field in it. The redaction is at construction, not at render, so the struct
    # itself never carries the PII either — `inspect(error)` and Ash's error aggregation
    # read the struct directly.
    test "a struct scope is named, never printed" do
      error = assert_raise InvalidScope, fn -> StructScopeVault.encrypt!("x", ctx()) end

      assert error.scope == "a %AshVault.Test.Support.PiiTenant{}"

      for rendered <- [Exception.message(error), inspect(error), inspect(error.scope)] do
        refute rendered =~ "Acme Holdings"
        refute rendered =~ "cfo@acme.example"
        refute rendered =~ "org_1a2b3c"
      end

      assert Exception.message(error) =~ "which is not a binary"
    end
  end

  describe "rotation racing a destroy (finding 12)" do
    # rotate_best_effort used to swallow {:error, :destroyed}, log a warning and encrypt
    # under the pre-destroy key. The write "succeeded" and stored ciphertext nobody can
    # ever read — the exact opposite of what crypto-erasure promises.
    test "an opportunistic rotation that reports :destroyed raises KeyDestroyed" do
      log =
        capture_log(fn ->
          error =
            assert_raise KeyDestroyed, fn ->
              DestroyedRotateVault.encrypt!("secret", ctx())
            end

          assert error.resource == Resources.User
          assert error.field == :ssn
        end)

      refute log =~ "continuing with the existing key"
    end

    test "an ordinary rotation failure still never fails the write" do
      log =
        capture_log(fn ->
          blob = FailingRotateVault.encrypt!("secret", ctx())
          assert {:ok, %{key_version: 1}} = Envelope.decode(blob)
        end)

      assert log =~ "key rotation for scope"
    end

    # A scope key is a tenant id, and a tenant id is routinely an email address or an
    # organisation name. `inspect(scope)` put it straight into the application log, which
    # outlives and out-audiences the database. A fingerprint still lets an operator tell
    # two tenants' failures apart and correlate repeats.
    test "a failed rotation logs a scope fingerprint, never the scope key" do
      tenant = "cfo@acme.example"

      log =
        capture_log(fn ->
          assert is_binary(FailingRotateVault.encrypt!("secret", ctx(tenant: tenant)))
        end)

      refute log =~ tenant
      refute log =~ "acme.example"
      assert log =~ AshVault.Scope.fingerprint(tenant)
      assert log =~ "continuing with the existing key"
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
