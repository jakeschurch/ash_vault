defmodule AshVault.VaultLocalTest do
  @moduledoc """
  P2 #19 — an end-to-end vault run over `AshVault.KeyProviders.Local`.

  Every other vault test uses `AshVault.KeyProviders.Memory`, which cannot exercise the
  one property `Local` exists for: key material that outlives the process. This suite
  needs no Docker and no database — just a temp directory.
  """

  # Not async: the `AshVault.KeyProvider` callbacks take no server name, so the vault
  # always talks to the default-named provider process.
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias AshVault.Context
  alias AshVault.Envelope
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.KeyProviders.Local
  alias AshVault.Test.Support.LocalVaultForTests, as: Vault
  alias AshVault.Test.Support.Resources

  setup %{tmp_dir: tmp_dir} do
    root = Path.join(tmp_dir, "keys")
    Local.init_root!(root)
    start_supervised!({Local, name: Local, root: root})

    %{root: root}
  end

  defp restart(root) do
    stop_supervised!(Local)
    start_supervised!({Local, name: Local, root: root})
    :ok
  end

  defp ctx(opts \\ []) do
    %Context{
      resource: Keyword.get(opts, :resource, Resources.User),
      field: Keyword.get(opts, :field, :ssn),
      ash_context: %{tenant: Keyword.get(opts, :tenant, "acme"), source_context: %{}}
    }
  end

  test "encrypt, restart the provider, decrypt, destroy, KeyDestroyed", %{root: root} do
    blob = Vault.encrypt!("hunter2", ctx())
    assert {:ok, %{key_version: 1}} = Envelope.decode(blob)

    # The whole reason Local exists: the key material is on disk, not in the process.
    :ok = restart(root)
    assert Vault.decrypt!(blob, ctx()) == "hunter2"

    assert :ok = Vault.destroy!("acme")

    error = assert_raise KeyDestroyed, fn -> Vault.decrypt!(blob, ctx()) end
    assert error.scope == "acme"
    assert Exception.message(error) =~ "cryptographically erased"

    # And it stays destroyed across a restart — the tombstone is on disk too.
    :ok = restart(root)
    assert_raise KeyDestroyed, fn -> Vault.decrypt!(blob, ctx()) end
    assert_raise KeyDestroyed, fn -> Vault.encrypt!("again", ctx()) end
  end

  test "rotation across a restart: old blobs still decrypt", %{root: root} do
    old = Vault.encrypt!("old secret", ctx())
    assert {:ok, 2} = Vault.rotate!("acme")
    new = Vault.encrypt!("new secret", ctx())

    assert {:ok, %{key_version: 1}} = Envelope.decode(old)
    assert {:ok, %{key_version: 2}} = Envelope.decode(new)

    :ok = restart(root)

    assert Vault.decrypt!(old, ctx()) == "old secret"
    assert Vault.decrypt!(new, ctx()) == "new secret"
  end

  test "destroying one tenant leaves the others readable, across a restart", %{root: root} do
    acme = Vault.encrypt!("acme secret", ctx(tenant: "acme"))
    globex = Vault.encrypt!("globex secret", ctx(tenant: "globex"))

    assert :ok = Vault.destroy!("acme")
    :ok = restart(root)

    assert_raise KeyDestroyed, fn -> Vault.decrypt!(acme, ctx(tenant: "acme")) end
    assert Vault.decrypt!(globex, ctx(tenant: "globex")) == "globex secret"
  end

  test "the AAD still binds resource and field over a filesystem provider" do
    blob = Vault.encrypt!("hunter2", ctx())

    assert_raise CiphertextIntegrityFailed, fn -> Vault.decrypt!(blob, ctx(field: :dob)) end

    assert_raise CiphertextIntegrityFailed, fn ->
      Vault.decrypt!(blob, ctx(resource: Resources.Invoice))
    end
  end

  test "a truncated tag forged into a stored envelope is rejected" do
    blob = Vault.encrypt!("hunter2", ctx())
    {:ok, env} = Envelope.decode(blob)

    forged = AshVault.Envelope.V1.encode(%{env | tag: binary_part(env.tag, 0, 1)})
    assert_raise CiphertextIntegrityFailed, fn -> Vault.decrypt!(forged, ctx()) end
  end
end
