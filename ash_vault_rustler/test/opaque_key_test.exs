defmodule AshVaultRustler.OpaqueKeyTest do
  @moduledoc """
  Level 2: key material that never becomes an Elixir term.

  The `AshVault.Key` union is purely additive — a binary is still a valid key and always
  will be — so these tests also pin the *backward* direction: the built-in cipher and the
  built-in providers are untouched by any of this.
  """

  use ExUnit.Case, async: false

  alias AshVault.Ciphers.AES.GCM
  alias AshVaultRustler.KeyProviders.Opaque
  alias AshVaultRustler.Test.ObservableProvider

  defmodule OpaqueKeys do
    @moduledoc false
    use AshVaultRustler.KeyProviders.Opaque, provider: AshVaultRustler.Test.ObservableProvider
  end

  defmodule OpaqueVault do
    @moduledoc false
    use AshVault.Vault,
      key_provider: AshVaultRustler.OpaqueKeyTest.OpaqueKeys,
      cipher: AshVaultRustler.Cipher
  end

  defmodule MismatchedVault do
    @moduledoc false
    # Deliberately wrong: opaque keys into a cipher that can only use bytes.
    use AshVault.Vault, key_provider: AshVaultRustler.OpaqueKeyTest.OpaqueKeys
  end

  setup do
    start_supervised!(ObservableProvider)
    %{scope: "acme_#{System.unique_integer([:positive])}"}
  end

  defp ctx(scope) do
    %AshVault.Context{resource: MyApp.User, field: :ssn, ash_context: %{tenant: scope}}
  end

  describe "AshVault.Key" do
    test "a binary is still a valid key" do
      assert AshVault.Key.key?(<<0::256>>)
      refute AshVault.Key.opaque?(<<0::256>>)
      assert AshVault.Key.owner(<<0::256>>) == nil
    end

    test "a handle is opaque and names its owner" do
      key = %AshVault.Key{ref: make_ref(), owner: Opaque}

      assert AshVault.Key.key?(key)
      assert AshVault.Key.opaque?(key)
      assert AshVault.Key.owner(key) == Opaque
    end

    test "nonsense is not a key" do
      refute AshVault.Key.key?(:nope)
      refute AshVault.Key.key?(%AshVault.Key{ref: nil, owner: nil})
    end
  end

  describe "the opaque provider" do
    test "current_key returns a handle, not bytes", %{scope: scope} do
      assert {:ok, %{key: %AshVault.Key{} = key, version: 1}} = OpaqueKeys.current_key(scope)
      assert AshVault.Key.opaque?(key)
      assert key.owner == Opaque
    end

    test "get_key returns a handle", %{scope: scope} do
      assert {:ok, %{version: version}} = OpaqueKeys.current_key(scope)
      assert {:ok, %AshVault.Key{} = key} = OpaqueKeys.get_key(scope, version)
      assert AshVault.Key.opaque?(key)
    end

    test "the handle holds the same key the wrapped provider minted", %{scope: scope} do
      assert {:ok, %{version: version}} = OpaqueKeys.current_key(scope)
      assert {:ok, raw} = ObservableProvider.get_key(scope, version)
      assert {:ok, handle} = OpaqueKeys.get_key(scope, version)

      assert Opaque.matches?(handle, raw)
      refute Opaque.matches?(handle, :crypto.strong_rand_bytes(32))
    end

    test "errors pass straight through", %{scope: scope} do
      assert {:error, :not_found} = OpaqueKeys.get_key(scope, 99)
      assert :ok = OpaqueKeys.destroy(scope)
      assert {:error, :destroyed} = OpaqueKeys.current_key(scope)
      assert {:error, :destroyed} = OpaqueKeys.get_key(scope, 1)
    end

    test "rotation works through the wrapper", %{scope: scope} do
      assert {:ok, %{version: 1}} = OpaqueKeys.current_key(scope)
      assert {:ok, 2} = OpaqueKeys.rotate(scope)
      assert {:ok, %{version: 2}} = OpaqueKeys.current_key(scope)
    end
  end

  describe "end to end through a vault" do
    test "encrypt and decrypt never put the key on this process's heap", %{scope: scope} do
      context = ctx(scope)

      blob = OpaqueVault.encrypt!("123-45-6789", context)
      assert OpaqueVault.decrypt!(blob, context) == "123-45-6789"

      # The key the provider minted, as bytes.
      assert {:ok, raw} = ObservableProvider.get_key(scope, 1)
      assert byte_size(raw) == 32

      # Best effort, and narrower than it looks. This inspects the two things
      # `Process.info/2` will actually hand over — the process dictionary and the message
      # queue — and nothing else. **The process heap itself is not observable from
      # Elixir**, and a 32-byte key is a heap binary rather than a refcounted one, so
      # `Process.info(pid, :binary)` would not see it either. The spec asks for a
      # best-effort `process_info` check and this is one; it is not proof of absence, and
      # the opaque provider does receive the bytes once from the wrapped provider on the
      # way into the handle. The real guarantee is structural: `AshVaultRustler.Cipher`
      # passes a resource reference to the NIF, so there is no term for the key to be.
      :erlang.garbage_collect(self())

      refute reachable_binaries(self()) |> Enum.any?(&(&1 == raw))
    end

    test "a value written through the opaque path reads back through the ordinary one",
         %{scope: scope} do
      context = ctx(scope)
      blob = OpaqueVault.encrypt!("wire compatible", context)

      assert {:ok, env} = AshVault.Envelope.decode(blob)
      assert {:ok, raw} = ObservableProvider.get_key(scope, env.key_version)

      aad = AshVault.Vault.Runtime.build_aad(scope, context)

      assert {:ok, "wire compatible"} =
               GCM.decrypt(
                 %{ciphertext: env.ciphertext, nonce: env.nonce, tag: env.tag},
                 raw,
                 aad
               )
    end

    test "a cipher that cannot take a handle raises, naming both modules", %{scope: scope} do
      context = ctx(scope)

      error =
        assert_raise AshVault.Errors.OpaqueKeyUnsupported, fn ->
          MismatchedVault.encrypt!("secret", context)
        end

      message = Exception.message(error)
      assert message =~ "AshVault.Ciphers.AES.GCM"
      assert message =~ inspect(OpaqueKeys)
      assert message =~ "will not unwrap the handle"

      # The verb follows the operation. REVIEW_FINDINGS #10 is the same defect in
      # `MissingScope`: saying "encrypting" on a read sends the operator to the wrong
      # half of the system.
      assert message =~ "encrypting MyApp.User.ssn"
      refute message =~ "decrypting"
    end

    test "the decrypt direction raises the same error, never AuthenticationFailed",
         %{scope: scope} do
      context = ctx(scope)
      blob = OpaqueVault.encrypt!("secret", context)

      # `decrypt!/3` resolves the cipher from the ENVELOPE, through the registry — not
      # from the vault's `:cipher`. Emptying the registry here is what makes this vault
      # actually mismatched on the read path, and is itself the reason the README insists
      # on configuring `:ciphers` alongside `:cipher`.
      original = Application.get_env(:ash_vault, :ciphers)
      Application.put_env(:ash_vault, :ciphers, %{})
      on_exit(fn -> Application.put_env(:ash_vault, :ciphers, original) end)

      error =
        assert_raise AshVault.Errors.OpaqueKeyUnsupported, fn ->
          MismatchedVault.decrypt!(blob, context)
        end

      message = Exception.message(error)
      assert message =~ "decrypting MyApp.User.ssn"
      refute message =~ "encrypting"
    end
  end

  describe "mlock" do
    test "a handle reports whether its pages are locked", %{scope: scope} do
      assert {:ok, %{key: key}} = OpaqueKeys.current_key(scope)
      assert is_boolean(Opaque.mlocked?(key))
    end
  end

  # Collect every binary reachable from this process's dictionary and message queue —
  # the two structures `Process.info/2` exposes. Not the heap: there is no BIF for that.
  defp reachable_binaries(pid) do
    {:dictionary, dict} = Process.info(pid, :dictionary)
    {:messages, messages} = Process.info(pid, :messages)

    [dict, messages]
    |> collect_binaries()
  end

  defp collect_binaries(term, acc \\ [])
  defp collect_binaries(term, acc) when is_binary(term), do: [term | acc]

  # Hand-rolled rather than `Enum.reduce/3`: a process dictionary and a message queue can
  # both legitimately hold improper lists, and `Enum` raises on those.
  defp collect_binaries(term, acc) when is_list(term), do: collect_list(term, acc)

  defp collect_binaries(term, acc) when is_tuple(term),
    do: term |> Tuple.to_list() |> collect_list(acc)

  defp collect_binaries(term, acc) when is_map(term),
    do: term |> Map.to_list() |> collect_list(acc)

  defp collect_binaries(_term, acc), do: acc

  defp collect_list([], acc), do: acc
  defp collect_list([head | tail], acc), do: collect_list(tail, collect_binaries(head, acc))
  defp collect_list(improper_tail, acc), do: collect_binaries(improper_tail, acc)
end
