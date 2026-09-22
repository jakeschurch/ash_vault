defmodule AshVault.KeyProviders.LocalTest do
  use ExUnit.Case, async: true

  @moduletag :tmp_dir

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_local/1

  import ExUnit.CaptureLog

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.Local

  @doc false
  def start_local(%{tmp_dir: tmp_dir}) do
    root = Path.join(tmp_dir, "keys")
    # The provider refuses to start on a root it did not see an operator initialise.
    # `init_root!/1` also chmods 0700, which keeps the (correct) loose-permissions
    # warning from firing in every test.
    Local.init_root!(root)

    name = :"ash_vault_local_#{System.unique_integer([:positive])}"
    start_supervised!({Local, name: name, root: root})

    %{
      provider: {Local, name},
      name: name,
      root: root,
      scope: fn -> "scope_#{System.unique_integer([:positive])}" end
    }
  end

  defp restart(name, root) do
    stop_supervised!(Local)
    start_supervised!({Local, name: name, root: root})
    :ok
  end

  # `init/1` raising crashes the linked provider process, so the caller sees an exit
  # rather than the exception. Trap it and hand back the ArgumentError.
  defp start_error(root) do
    Process.flag(:trap_exit, true)

    result =
      case Local.start_link(
             name: :"ash_vault_local_x_#{System.unique_integer([:positive])}",
             root: root
           ) do
        {:error, {%ArgumentError{} = error, _stacktrace}} -> error
        {:error, %ArgumentError{} = error} -> error
        other -> flunk("expected start_link to fail, got: #{inspect(other)}")
      end

    receive do
      {:EXIT, _pid, _reason} -> :ok
    after
      0 -> :ok
    end

    Process.flag(:trap_exit, false)
    result
  end

  defp scope_path(root, scope), do: Path.join(root, Local.scope_dir(scope))
  defp meta_path(root, scope), do: Path.join(scope_path(root, scope), "meta.json")
  defp tombstone_path(root, scope), do: scope_path(root, scope) <> ".tombstone"

  describe "start_link/1" do
    test "requires a root" do
      assert_raise ArgumentError, ~r/requires a `:root`/, fn -> Local.start_link([]) end
    end

    test "falls back to application config", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "configured")
      prior = Application.get_env(:ash_vault, Local)
      Application.put_env(:ash_vault, Local, root: root)

      on_exit(fn ->
        case prior do
          nil -> Application.delete_env(:ash_vault, Local)
          prior -> Application.put_env(:ash_vault, Local, prior)
        end
      end)

      Local.init_root!(root)

      name = :"ash_vault_local_cfg_#{System.unique_integer([:positive])}"
      start_supervised!(%{id: name, start: {Local, :start_link, [[name: name]]}})

      assert File.dir?(root)
      assert {:ok, %{version: 1}} = Local.current_key(name, "cfg")
    end

    # Finding 1. `init/1` used to run `File.mkdir_p!/1` unconditionally. If `:root` is a
    # mount point — exactly what the moduledoc tells operators to use — and the volume
    # fails to mount, that created the root on the *underlying* filesystem: no
    # tombstones, a pristine-looking key store, and a fresh v1 minted for every tenant
    # that was ever crypto-erased. No attacker needed, just a boot-order bug.
    test "refuses to start on a root that does not exist", %{tmp_dir: tmp_dir} do
      root = Path.join([tmp_dir, "deep", "nested", "root"])

      assert Exception.message(start_error(root)) =~ "does not exist"
      refute File.exists?(root), "start_link must not create the key root"
    end

    test "refuses to start on an existing root with no sentinel", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "unmounted")
      File.mkdir_p!(root)

      assert Exception.message(start_error(root)) =~ "holds no .ash_vault_root sentinel"
    end

    # The whole point of the sentinel: an unmounted volume must not present itself as a
    # brand-new, empty key store.
    test "an unmounted key volume cannot resurrect a destroyed scope", %{tmp_dir: tmp_dir} do
      mount_point = Path.join(tmp_dir, "mnt")
      Local.init_root!(mount_point)

      name = :"ash_vault_local_mnt_#{System.unique_integer([:positive])}"

      start_supervised!(%{
        id: name,
        start: {Local, :start_link, [[name: name, root: mount_point]]}
      })

      assert {:ok, %{version: 1}} = Local.current_key(name, "erased")
      assert :ok = Local.destroy(name, "erased")
      stop_supervised!(name)

      # The volume fails to mount: the mount point is back to a bare, empty directory
      # on the underlying filesystem.
      File.rm_rf!(mount_point)
      File.mkdir_p!(mount_point)

      assert Exception.message(start_error(mount_point)) =~ "sentinel"
    end

    test "init_root!/1 creates the root at 0700 with a sentinel, idempotently",
         %{tmp_dir: tmp_dir} do
      root = Path.join([tmp_dir, "deep", "nested", "root"])

      assert :ok = Local.init_root!(root)
      assert File.dir?(root)
      assert Bitwise.band(File.stat!(root).mode, 0o777) == 0o700

      sentinel = Path.join(root, Local.sentinel_file())
      assert File.regular?(sentinel)
      before = File.read!(sentinel)

      assert :ok = Local.init_root!(root)
      assert File.read!(sentinel) == before

      name = :"ash_vault_local_init_#{System.unique_integer([:positive])}"
      start_supervised!(%{id: name, start: {Local, :start_link, [[name: name, root: root]]}})
      assert {:ok, %{version: 1}} = Local.current_key(name, "after-init")
    end

    test "warns loudly when the root is group/world readable", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "loose")
      Local.init_root!(root)
      File.chmod!(root, 0o755)

      name = :"ash_vault_local_loose_#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          start_supervised!(%{id: name, start: {Local, :start_link, [[name: name, root: root]]}})
        end)

      assert log =~ root
      assert log =~ "group- or world-accessible"

      # It warns, but it still starts.
      assert {:ok, %{version: 1}} = Local.current_key(name, "loose")
    end
  end

  describe "lookup keys" do
    test "are minted once and never move, across a rotation or a restart", %{
      provider: {Local, name},
      root: root
    } do
      scope = "lookup_scope"

      assert {:ok, key} = Local.lookup_key(name, scope)
      assert byte_size(key) == 32
      assert {:ok, ^key} = Local.lookup_key(name, scope)

      assert {:ok, %{version: 1}} = Local.current_key(name, scope)
      assert {:ok, 2} = Local.rotate(name, scope)
      assert {:ok, ^key} = Local.lookup_key(name, scope)

      # Same bytes after a process restart: the secret is on disk, not in state.
      restart(name, root)
      assert {:ok, ^key} = Local.lookup_key(name, scope)
    end

    test "live in lookup.key, beside \u2014 and never inside \u2014 the versioned metadata", %{
      provider: {Local, name},
      root: root
    } do
      scope = "lookup_layout"
      assert {:ok, _key} = Local.lookup_key(name, scope)
      assert {:ok, _info} = Local.current_key(name, scope)

      dir = Path.join(root, Local.scope_dir(scope))
      assert File.regular?(Path.join(dir, "lookup.key"))

      meta = dir |> Path.join("meta.json") |> File.read!() |> Jason.decode!()
      refute meta["versions"] |> Map.keys() |> Enum.any?(&(&1 =~ "lookup"))
    end

    test "a scope holding ONLY a lookup key still mints version 1 normally", %{
      provider: {Local, name}
    } do
      scope = "lookup_only"

      assert {:ok, _key} = Local.lookup_key(name, scope)

      # The scope directory now exists with no meta.json. `read_meta/2` must still read
      # that as an absent scope rather than corruption.
      assert {:ok, %{version: 1}} = Local.current_key(name, scope)
    end

    test "are separate from every data key version", %{provider: {Local, name}} do
      scope = "lookup_separate"

      assert {:ok, lookup} = Local.lookup_key(name, scope)
      assert {:ok, %{key: v1}} = Local.current_key(name, scope)
      assert {:ok, 2} = Local.rotate(name, scope)
      assert {:ok, %{key: v2}} = Local.current_key(name, scope)

      refute lookup == v1
      refute lookup == v2
    end

    test "are per scope", %{provider: {Local, name}} do
      assert {:ok, a} = Local.lookup_key(name, "lookup_a")
      assert {:ok, b} = Local.lookup_key(name, "lookup_b")
      refute a == b
    end

    test "are destroyed by destroy/1, shredded and tombstoned like any other key", %{
      provider: {Local, name},
      root: root
    } do
      scope = "lookup_destroyed"
      assert {:ok, _key} = Local.lookup_key(name, scope)
      assert :ok = Local.destroy(name, scope)

      refute File.exists?(Path.join([root, Local.scope_dir(scope), "lookup.key"]))
      # A fresh secret here would let anyone holding it keep confirming guesses about a
      # subject whose data was "destroyed".
      assert {:error, :destroyed} = Local.lookup_key(name, scope)
    end
  end

  describe "scope_dir/1" do
    test "is reversible and filesystem safe" do
      for scope <- ["acme", "a/b", "tenant with spaces", "ünïcode", <<0, 255, 128>>] do
        dir = Local.scope_dir(scope)
        refute String.contains?(dir, ["/", ".", " "])
        assert {:ok, ^scope} = Base.url_decode64(dir, padding: false)
      end
    end
  end

  describe "on-disk layout" do
    test "writes meta.json and v<n>.key under the encoded scope dir",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{version: 1}} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)

      dir = scope_path(root, scope)
      assert File.exists?(Path.join(dir, "v1.key"))
      assert File.exists?(Path.join(dir, "v2.key"))

      assert {:ok, meta} = File.read(meta_path(root, scope))
      assert %{"current" => 2, "versions" => %{"1" => _, "2" => _}} = Jason.decode!(meta)
    end

    test "key files are mode 0600", %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)

      for file <- ["v1.key", "v2.key", "meta.json"] do
        %File.Stat{mode: mode} = File.stat!(Path.join(scope_path(root, scope), file))

        assert Bitwise.band(mode, 0o777) == 0o600,
               "#{file} had mode #{inspect(mode, base: :octal)}"
      end
    end

    test "leaves no temp files behind", %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)

      assert Enum.sort(File.ls!(scope_path(root, scope))) == ["meta.json", "v1.key", "v2.key"]
    end

    test "the tombstone sits beside the scope dir, not inside it",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      assert File.exists?(tombstone_path(root, scope))
      refute File.exists?(scope_path(root, scope))

      assert %{"destroyed_at" => _} =
               tombstone_path(root, scope) |> File.read!() |> Jason.decode!()
    end

    test "deleting the scope dir cannot delete the tombstone",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      # Even a well-meaning operator wiping the directory leaves the tombstone intact.
      File.rm_rf!(scope_path(root, scope))
      assert {:error, :destroyed} = current_key(provider, scope)
    end
  end

  describe "persistence across restarts" do
    test "keys survive a provider restart on the same root",
         %{provider: provider, name: name, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{version: 1, key: v1}} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)
      assert {:ok, %{key: v2}} = current_key(provider, scope)

      :ok = restart(name, root)

      assert {:ok, %{version: 2, key: ^v2}} = current_key(provider, scope)
      assert {:ok, ^v1} = get_key(provider, scope, 1)
      assert {:ok, ^v2} = get_key(provider, scope, 2)
    end

    test "created_at is preserved across a restart",
         %{provider: provider, name: name, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{created_at: created_at}} = current_key(provider, scope)

      :ok = restart(name, root)

      assert {:ok, %{created_at: reloaded}} = current_key(provider, scope)
      assert DateTime.compare(created_at, reloaded) == :eq
    end

    test "tombstone survives a restart",
         %{provider: provider, name: name, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      :ok = restart(name, root)

      assert {:error, :destroyed} = current_key(provider, scope)
      assert {:error, :destroyed} = get_key(provider, scope, 1)
      assert {:error, :destroyed} = rotate(provider, scope)
    end
  end

  describe "backup/restore simulation" do
    test "restoring anything but the key root leaves the scope destroyed",
         %{provider: provider, name: name, root: root, tmp_dir: tmp_dir, scope: scope} do
      scope = scope.()
      assert {:ok, %{key: _key}} = current_key(provider, scope)

      # The "backup" taken before the erasure — as a database dump would be.
      backup = Path.join(tmp_dir, "backup")
      File.cp_r!(root, backup)

      assert :ok = destroy(provider, scope)
      assert {:error, :destroyed} = current_key(provider, scope)

      # Restore the database side: by construction that touches nothing under the key
      # root. Restart the provider on the untouched root — still destroyed. This is the
      # whole point of the provider.
      :ok = restart(name, root)
      assert {:error, :destroyed} = current_key(provider, scope)
      assert {:error, :destroyed} = get_key(provider, scope, 1)
    end

    test "restoring the key root DOES resurrect the scope — which is why it must not be in the DB backup",
         %{provider: provider, name: name, root: root, tmp_dir: tmp_dir, scope: scope} do
      scope = scope.()
      assert {:ok, %{key: key}} = current_key(provider, scope)

      backup = Path.join(tmp_dir, "backup")
      File.cp_r!(root, backup)

      assert :ok = destroy(provider, scope)
      assert {:error, :destroyed} = current_key(provider, scope)

      # Replace the key root wholesale with the backup. The rm_rf is load-bearing: the
      # tombstone lives in the root, so a merge-copy would leave it in place and the
      # scope would stay destroyed. A restore that overwrites the root removes it.
      File.rm_rf!(root)
      File.cp_r!(backup, root)
      File.chmod!(root, 0o700)

      :ok = restart(name, root)

      assert {:ok, %{version: 1, key: ^key}} = current_key(provider, scope)
    end
  end

  describe "error discrimination" do
    test "corrupt meta.json is ProviderUnavailable, never :destroyed",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)

      File.write!(meta_path(root, scope), "{\"current\": 1, \"versi")

      assert {:error, %ProviderUnavailable{}} = current_key(provider, scope)
      assert {:error, %ProviderUnavailable{}} = rotate(provider, scope)
    end

    test "structurally invalid meta.json is ProviderUnavailable",
         %{provider: provider, root: root, scope: scope} do
      for body <- [
            "{}",
            ~s({"current": "two", "versions": {}}),
            ~s({"current": 1, "versions": []}),
            ~s({"current": 1, "versions": {"one": "2024-01-01T00:00:00Z"}}),
            ~s({"current": 1, "versions": {"1": "not-a-timestamp"}}),
            ~s({"current": 2, "versions": {"1": "2024-01-01T00:00:00Z"}}),
            "not json at all"
          ] do
        scope = scope.()
        assert {:ok, _} = current_key(provider, scope)
        File.write!(meta_path(root, scope), body)

        assert {:error, %ProviderUnavailable{}} = current_key(provider, scope),
               "expected ProviderUnavailable for meta #{body}"
      end
    end

    test "a missing key file referenced by meta is :not_found, never :destroyed",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{version: 1}} = current_key(provider, scope)

      File.rm!(Path.join(scope_path(root, scope), "v1.key"))

      assert {:error, :not_found} = current_key(provider, scope)
      assert {:error, :not_found} = get_key(provider, scope, 1)
    end

    test "an absent scope is :not_found, not ProviderUnavailable",
         %{provider: provider, scope: scope} do
      assert {:error, :not_found} = get_key(provider, scope.(), 1)
    end

    test "calls against a dead instance surface as a provider error" do
      assert {:error, {:provider_unavailable, _}} =
               Local.current_key(:ash_vault_local_never_started, "x")
    end

    test "non-binary scopes raise", %{name: name} do
      assert_raise ArgumentError, ~r/must be binaries/, fn -> Local.current_key(name, :atom) end
    end
  end

  describe "crash safety" do
    test "an orphan key file with no meta entry is harmless",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{key: v1}} = current_key(provider, scope)

      # Simulates a crash between writing v2.key and updating meta.json: the key file
      # exists, meta still says v1. current_key must keep serving v1.
      File.write!(Path.join(scope_path(root, scope), "v2.key"), :crypto.strong_rand_bytes(32))

      assert {:ok, %{version: 1, key: ^v1}} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)
    end
  end

  describe "tombstone reads fail closed" do
    # Finding 3. `File.exists?/1` answers `false` for ANY stat failure, not just
    # absence. With the tombstone unreadable the provider used to conclude "not
    # destroyed" and mint a fresh key for an erased tenant.
    @tag :unix
    test "an unreadable tombstone is ProviderUnavailable, never a fresh key",
         %{provider: provider, name: name, root: root, tmp_dir: tmp_dir, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      # Move the tombstone into a subdirectory the process cannot traverse, and point a
      # fresh provider at it: stat now fails with :eacces, not :enoent.
      blocked_root = Path.join(tmp_dir, "blocked")
      Local.init_root!(blocked_root)
      File.cp!(tombstone_path(root, scope), tombstone_path(blocked_root, scope))

      blocked_name = :"ash_vault_local_blk_#{System.unique_integer([:positive])}"

      start_supervised!(%{
        id: blocked_name,
        start: {Local, :start_link, [[name: blocked_name, root: blocked_root]]}
      })

      File.chmod!(blocked_root, 0o600)
      on_exit(fn -> File.chmod(blocked_root, 0o700) end)

      assert {:error, %ProviderUnavailable{reason: {:tombstone_unreadable, _, :eacces}}} =
               Local.current_key(blocked_name, scope)

      assert {:error, %ProviderUnavailable{}} = Local.get_key(blocked_name, scope, 1)
      assert {:error, %ProviderUnavailable{}} = Local.rotate(blocked_name, scope)

      File.chmod!(blocked_root, 0o700)
      assert {:error, :destroyed} = Local.current_key(blocked_name, scope)

      _ = name
    end

    test "a tombstone whose contents are unparseable still means destroyed",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      File.write!(tombstone_path(root, scope), "")
      assert {:error, :destroyed} = current_key(provider, scope)

      File.write!(tombstone_path(root, scope), "{ truncated")
      assert {:error, :destroyed} = current_key(provider, scope)
    end
  end

  describe "destroy ordering" do
    # Finding 7. Shred-then-tombstone leaves a window with no keys AND no tombstone: the
    # next current_key mints a fresh v1, existing rows say key_version: 1, and the
    # caller gets CiphertextIntegrityFailed — erasure disguised as tampering.
    @tag :unix
    test "a destroy that cannot write its tombstone never shreds the keys",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{version: 1, key: original}} = current_key(provider, scope)

      File.chmod!(root, 0o500)
      on_exit(fn -> File.chmod(root, 0o700) end)

      assert {:error, _} = destroy(provider, scope)

      # The load-bearing assertion: whatever happens, the next current_key must not
      # hand out a freshly minted key under an old version number.
      case current_key(provider, scope) do
        {:error, _} -> :ok
        {:ok, %{version: 1, key: ^original}} -> :ok
        other -> flunk("destroy left the scope re-mintable: #{inspect(other)}")
      end

      File.chmod!(root, 0o700)
    end

    @tag :unix
    test "a destroy interrupted after the tombstone leaves the scope destroyed",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)

      # Let the tombstone land, then make the scope directory unshreddable.
      dir = scope_path(root, scope)
      File.chmod!(dir, 0o500)
      on_exit(fn -> File.chmod(dir, 0o700) end)

      assert {:error, %ProviderUnavailable{}} = destroy(provider, scope)

      assert File.exists?(tombstone_path(root, scope))
      assert {:error, :destroyed} = current_key(provider, scope)
      assert {:error, :destroyed} = get_key(provider, scope, 1)

      File.chmod!(dir, 0o700)
    end

    test "a completed destroy records shredded_at alongside destroyed_at",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert :ok = destroy(provider, scope)

      assert %{"destroyed_at" => _, "shredded_at" => _} =
               tombstone_path(root, scope) |> File.read!() |> Jason.decode!()
    end
  end

  describe "key file validation" do
    # Finding 8(c). A truncated key file used to be handed straight to the cipher,
    # which reports {:error, {:invalid_key_size, n}} — surfaced by the vault as
    # CiphertextIntegrityFailed, i.e. "your data was tampered with" for a broken key store.
    test "a key file of the wrong size is ProviderUnavailable",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, %{version: 1}} = current_key(provider, scope)

      File.write!(Path.join(scope_path(root, scope), "v1.key"), :crypto.strong_rand_bytes(16))

      assert {:error, %ProviderUnavailable{reason: {:invalid_key_size, _}}} =
               current_key(provider, scope)

      assert {:error, %ProviderUnavailable{reason: {:invalid_key_size, _}}} =
               get_key(provider, scope, 1)
    end
  end

  describe "get_key/2 version validation" do
    # Finding 15. get_key/2 is public API, and "v#{version}.key" interpolated an
    # unvalidated term into a path.
    test "a traversing or non-positive version is :not_found, never a file read",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)

      # A file the traversal would otherwise reach.
      secret = Path.join(root, "server.key")
      File.write!(secret, :crypto.strong_rand_bytes(32))

      for version <- ["../../server", "../server", 0, -1, :one, 1.0] do
        assert {:error, :not_found} = get_key(provider, scope, version),
               "expected :not_found for version #{inspect(version)}"
      end
    end
  end

  describe "destroy" do
    test "shreds every version's key file", %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert {:ok, _} = current_key(provider, scope)
      assert {:ok, 2} = rotate(provider, scope)
      assert {:ok, 3} = rotate(provider, scope)

      assert :ok = destroy(provider, scope)

      refute File.exists?(scope_path(root, scope))
      assert File.exists?(tombstone_path(root, scope))
    end

    test "destroying a never-used scope still writes a tombstone",
         %{provider: provider, root: root, scope: scope} do
      scope = scope.()
      assert :ok = destroy(provider, scope)
      assert File.exists?(tombstone_path(root, scope))
    end

    test "destroying one scope leaves another's files alone",
         %{provider: provider, root: root, scope: scope} do
      gone = scope.()
      kept = scope.()

      assert {:ok, _} = current_key(provider, gone)
      assert {:ok, _} = current_key(provider, kept)
      assert :ok = destroy(provider, gone)

      refute File.exists?(scope_path(root, gone))
      assert File.exists?(Path.join(scope_path(root, kept), "v1.key"))
      refute File.exists?(tombstone_path(root, kept))
    end
  end
end
