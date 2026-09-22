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
    File.mkdir_p!(root)
    # ExUnit's tmp_dir is created under the umask, so it lands 0755. Tighten it so the
    # provider's (correct) loose-permissions warning does not fire in every test.
    File.chmod!(root, 0o700)

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

      name = :"ash_vault_local_cfg_#{System.unique_integer([:positive])}"
      start_supervised!(%{id: name, start: {Local, :start_link, [[name: name]]}})

      assert File.dir?(root)
      assert {:ok, %{version: 1}} = Local.current_key(name, "cfg")
    end

    test "creates the root, mode 0700, if it is missing", %{tmp_dir: tmp_dir} do
      root = Path.join([tmp_dir, "deep", "nested", "root"])
      name = :"ash_vault_local_mk_#{System.unique_integer([:positive])}"
      start_supervised!(%{id: name, start: {Local, :start_link, [[name: name, root: root]]}})

      assert File.dir?(root)
      assert Bitwise.band(File.stat!(root).mode, 0o777) == 0o700
    end

    test "warns loudly when the root is group/world readable", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "loose")
      File.mkdir_p!(root)
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
