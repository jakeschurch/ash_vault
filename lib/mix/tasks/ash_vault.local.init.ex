defmodule Mix.Tasks.AshVault.Local.Init do
  @shortdoc "Initialise an AshVault.KeyProviders.Local key root"

  @moduledoc """
  Create and initialise a key root for `AshVault.KeyProviders.Local`.

      mix ash_vault.local.init /var/lib/my_app/ash_vault_keys

  With no argument the root is read from configuration:

      config :ash_vault, AshVault.KeyProviders.Local, root: "/var/lib/my_app/ash_vault_keys"

  The task creates the directory at mode `0700` and writes the sentinel file
  `.ash_vault_root` into it. `AshVault.KeyProviders.Local` refuses to start against a
  root without that sentinel, and never creates one itself.

  ## Why this step exists

  The key root is supposed to live on its own volume, separate from the database. If
  that volume fails to mount — a reordered systemd unit, a degraded array, an NFS
  server that is not up yet — a provider that created its own root would quietly build
  an empty key store on the *underlying* filesystem: no tombstones, no key material,
  and a freshly minted version 1 for every tenant that was ever crypto-erased.

  The sentinel lives on the mounted volume, so its absence distinguishes "the key
  store is not here" from "the key store is empty". Running this task is therefore an
  explicit operator decision, taken once, with the volume mounted.

  > #### Do not run this to make a start-up error go away {: .error}
  >
  > If `AshVault.KeyProviders.Local` refuses to start on a root that you know was
  > already initialised, the sentinel is missing because the *volume* is missing.
  > Running this task then creates a second, empty key store over the top of the mount
  > point and resurrects every destroyed tenant. Check the mount first.

  ## Options

    * `--force` — write the sentinel even if the directory already exists and is
      non-empty. Without it, a non-empty directory with no sentinel is treated as a
      probable unmounted volume and the task refuses.
  """

  use Mix.Task

  alias AshVault.KeyProviders.Local

  @impl Mix.Task
  @spec run([String.t()]) :: :ok
  def run(argv) do
    {opts, args} = OptionParser.parse!(argv, strict: [force: :boolean])

    root = resolve_root!(args)

    if not Keyword.get(opts, :force, false) do
      refuse_if_suspicious!(root)
    end

    Local.init_root!(root)

    Mix.shell().info("""
    Initialised AshVault key root: #{Path.expand(root)}
      mode:     0700
      sentinel: #{Local.sentinel_file()}

    Back this directory up separately from the database, and exclude it from the
    database backup job. See the AshVault.KeyProviders.Local moduledoc.
    """)

    :ok
  end

  defp resolve_root!([root]) when is_binary(root) and root != "", do: root

  defp resolve_root!([]) do
    :ash_vault
    |> Application.get_env(Local, [])
    |> Keyword.get(:root)
    |> case do
      root when is_binary(root) and root != "" ->
        root

      _ ->
        Mix.raise("""
        No key root given.

            mix ash_vault.local.init /var/lib/my_app/ash_vault_keys

        or configure one:

            config :ash_vault, #{inspect(Local)}, root: "/var/lib/my_app/ash_vault_keys"
        """)
    end
  end

  defp resolve_root!(args) do
    Mix.raise("Expected at most one key root, got: #{inspect(args)}")
  end

  defp refuse_if_suspicious!(root) do
    expanded = Path.expand(root)

    with true <- File.dir?(expanded),
         false <- File.regular?(Path.join(expanded, Local.sentinel_file())),
         {:ok, [_ | _] = entries} <- File.ls(expanded) do
      Mix.raise("""
      #{expanded} already exists, contains #{length(entries)} entries, and has no
      #{Local.sentinel_file()} sentinel.

      That is exactly what an unmounted key volume looks like from above, and also what
      a key root initialised by an older AshVault looks like. Check `mount` before you
      do anything else.

      If you are certain this directory is the real key root, re-run with --force.
      """)
    end

    :ok
  end
end
