defmodule AshVault.KeyProviders.Local do
  @moduledoc """
  A filesystem-backed `AshVault.KeyProvider` for single-node deployments.

  `Local` exists because AshVault's central property — *restoring a PostgreSQL backup must
  not resurrect destroyed keys* — only requires the key store to be **a different system
  from the database**. A directory on another volume, excluded from the database backup
  job, is a legitimate answer for a single-node app. `AshVault.KeyProviders.Memory`
  cannot serve that role (it forgets everything on restart) and OpenBao is overkill for
  one node.

  ## Layout

      <root>/
        <scope_dir>/
          meta.json          # {"current": 2, "versions": {"1": "<iso8601>", ...}}
          v1.key             # raw key bytes, mode 0600
          v2.key
          lookup.key         # the non-rotating searchable-field secret, mode 0600
          mac-meta.json      # the :mac keyring's own meta, same shape as meta.json
          mac-v1.key         # :mac key bytes (always 32), mode 0600
        <scope_dir>.tombstone   # presence == scope destroyed

  `scope_dir` is `Base.url_encode64(scope, padding: false)` — total, reversible and
  filesystem-safe. `scope_dir/1` is public so operators can find a tenant's directory.

  The tombstone deliberately sits **beside** the scope directory rather than inside it, so
  that deleting (or losing) the directory cannot delete the tombstone.

  ## Starting it

      # config/runtime.exs
      config :ash_vault, AshVault.KeyProviders.Local,
        root: "/var/lib/my_app/ash_vault_keys",
        key_bytes: 32

      # lib/my_app/application.ex
      children = [MyApp.Repo, AshVault.KeyProviders.Local]

  `:root` is required, either as a `start_link/1` option or under that config key.
  `start_link/1` also takes `:name` (default `__MODULE__`) and `:key_bytes` (default 32).

  ## The key root must be initialised explicitly {: .error}

  > #### `Local` never creates its own key root {: .error}
  >
  > Before the provider will start, the root directory must already exist **and**
  > contain the sentinel file `.ash_vault_root`. Create both, once, with:
  >
  >     mix ash_vault.local.init /var/lib/my_app/ash_vault_keys
  >
  > or, from code, `AshVault.KeyProviders.Local.init_root!/1`.

  This is a deliberate, breaking operational requirement, and it exists because the
  moduledoc tells you to put the key root on its own volume. If that volume fails to
  mount — a reordered systemd unit, a degraded array, an NFS server that is not up
  yet — a provider that ran `File.mkdir_p!/1` would create the root on the *underlying*
  filesystem, find no tombstones at all, report itself healthy, and mint a fresh
  version 1 for every tenant you have ever crypto-erased. No attacker is needed; a
  boot-order bug is enough.

  The sentinel lives on the mounted volume, so its absence is exactly the signal that
  distinguishes "the key store is not there" from "the key store is empty". It is never
  created automatically — a fresh install has an empty root too, and auto-creating the
  sentinel would make the two indistinguishable again.

  All operations are serialised through a `GenServer`, reads included. Simplicity beats
  throughput here; `AshVault.KeyProviders.OpenBao` is the answer for load.

  ## Operating this provider

  > #### The key directory must be excluded from the database backup {: .error}
  >
  > If the key root and the database land in the same tarball, snapshot or volume clone,
  > crypto-erasure is defeated: restoring that backup resurrects both the ciphertext and
  > the keys that open it. Keep the key root off the volume you snapshot with the
  > database, and exclude it from the database backup job explicitly.

  Back the key directory up **separately and deliberately**, with its own retention
  policy. This is a real, sharp tradeoff with no free answer:

    * Keeping key backups makes erasure harder — every retained copy of the key root is a
      copy that can resurrect a destroyed tenant, and your retention window is the real
      lifetime of a "destroyed" key.
    * Keeping no key backups makes data loss easy — losing the key root destroys every
      encrypted value in the database, permanently, with no recovery path.

  Decide which risk you are underwriting, write it down, and test the restore.

  `Local` is **single-node**. Two nodes sharing one NFS or SMB mount will race on
  `meta.json` and can mint conflicting versions; use `AshVault.KeyProviders.OpenBao`
  for multi-node deployments.

  ## Durability

  Every write is: write to a temp file in the same directory, `fsync` the file, `chmod`
  it, then `rename` into place (atomic within a filesystem). A key file always lands
  **before** the `meta.json` entry that references it, so an ill-timed crash leaves a
  harmless orphan key file rather than a `meta.json` pointing at a missing key — the
  latter would be an accidental crypto-erasure, the worst failure this module could have.

  > #### Directory fsync is best-effort {: .warning}
  >
  > OTP offers no way to open a directory for `:file.sync/1` (`:file.open/2` on a
  > directory returns `{:error, :eisdir}`), so this provider cannot fsync the containing
  > directory after a rename. Durability of the *directory entry* is therefore left to
  > the filesystem's own ordering guarantees. The load-bearing property — key file
  > durably written before the metadata naming it — does not depend on it.

  ## Destruction

  `destroy/1` writes the **tombstone first**, fsyncs it, and only then overwrites each
  `*.key` — `:data`, `:mac` and lookup alike — with random bytes of the same length, fsyncs, unlinks, and removes
  `meta.json` and the scope directory. Once the shred completes the tombstone is
  rewritten with a `shredded_at`, so an interrupted destroy is visible to an operator.

  The ordering is load-bearing. Shredding first and tombstoning second leaves a window
  — ENOSPC, EACCES, a read-only remount, a crash — in which the scope has no key
  material *and* no tombstone. The next `current_key/1` would see an absent scope and
  mint a fresh version 1; existing rows carry `key_version: 1`, so `get_key/2` would
  hand back the **new** v1 key and the caller would get
  `AshVault.Errors.CiphertextIntegrityFailed` — erasure wearing the costume of tampering.
  Tombstone-first fails safe: the worst case is a scope marked destroyed whose key
  files linger, and the provider refuses to serve them anyway.

  A tombstone is honoured on **presence alone**: its contents are never parsed to
  decide whether a scope is destroyed, so a truncated or unreadable tombstone still
  means destroyed.

  > #### Overwrite-before-unlink guarantees nothing about the media {: .warning}
  >
  > Overwriting a file's bytes in place is best-effort only. On copy-on-write and
  > log-structured filesystems (btrfs, ZFS, APFS, any SSD behind an FTL, and any
  > snapshotted or thinly-provisioned volume) the overwrite is written *elsewhere* and
  > the original blocks survive until they are reclaimed — if ever. Treat the tombstone
  > and the AEAD, not the overwrite, as the mechanism that makes data unreadable. If you
  > need media-level erasure, use full-disk encryption and destroy the volume key.

  ## Error discrimination

  An outage must never look like erasure:

    * tombstone present → `{:error, :destroyed}`, for `current_key/1`, `get_key/2` and
      `rotate/1` alike, forever
    * tombstone **unreadable** (`:eacces`, `:eio`, `:estale`, `:eloop`, …) →
      `{:error, %AshVault.Errors.ProviderUnavailable{}}`. A tombstone read that cannot
      complete is never answered with "not destroyed": only a positive `:enoent`
      counts as absence
    * no scope directory, or no `meta.json` → an ordinary absent scope: `current_key/1`
      mints version 1, `get_key/2` returns `{:error, :not_found}`
    * `meta.json` present but corrupt or truncated → `{:error, %AshVault.Errors.ProviderUnavailable{}}`
    * `meta.json` references a version whose key file is missing → `{:error, :not_found}`

  Neither corruption nor a missing key file is ever reported as `:destroyed`.
  """

  @behaviour AshVault.KeyProvider

  use GenServer

  require Logger

  alias AshVault.Errors.ProviderUnavailable

  @default_key_bytes 32
  @key_file_mode 0o600
  @meta_file "meta.json"
  @mac_meta_file "mac-meta.json"
  @sentinel_file ".ash_vault_root"

  @doc """
  Start the provider.

  Options: `:name` (default `__MODULE__`), `:root` (required, falling back to
  `config :ash_vault, AshVault.KeyProviders.Local, root: ...`) and `:key_bytes`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)

    opts =
      opts
      |> Keyword.put(:root, resolve_root!(opts))
      |> Keyword.put_new_lazy(:key_bytes, &key_bytes/0)

    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  The key size in bytes this provider mints, from config, defaulting to 32.
  """
  @impl AshVault.KeyProvider
  @spec key_bytes() :: pos_integer()
  def key_bytes do
    __MODULE__
    |> AshVault.KeyProvider.config()
    |> Keyword.get(:key_bytes, @default_key_bytes)
  end

  @doc """
  Initialise the configured key root, if it is not initialised already.

  The **operator** setup step: exactly `init_root!/1` on the `:root` from configuration,
  so a host application that has already written that configuration does not have to dig
  it back out to call `init_root!/1` by hand.

      MyApp.Vault.setup()

  Idempotent — `init_root!/1` is — but deliberately still explicit: it is the step that
  creates the `.ash_vault_root` sentinel, and the sentinel's whole job is to be absent
  when the key volume failed to mount. Running it automatically on boot would create it
  on the underlying filesystem and hand back a pristine, empty key store. It belongs in
  a deploy step, not in a supervision tree.
  """
  @impl AshVault.KeyProvider
  @spec setup() :: :ok
  def setup, do: init_root!(resolve_root!([]))

  @doc """
  Create and initialise a key root: the directory itself (mode `0700`) and the
  `.ash_vault_root` sentinel the provider refuses to start without.

  This is the **operator** step. It is deliberately not something the provider does for
  itself — see the moduledoc. It is idempotent, and it never touches existing key
  material.

  Raises `File.Error` if the directory or the sentinel cannot be created.
  """
  @spec init_root!(binary()) :: :ok
  def init_root!(root) when is_binary(root) and root != "" do
    root = Path.expand(root)

    File.mkdir_p!(root)
    File.chmod!(root, 0o700)

    sentinel = sentinel_path(root)

    unless File.regular?(sentinel) do
      File.write!(
        sentinel,
        Jason.encode!(%{
          "initialised_at" => DateTime.to_iso8601(DateTime.utc_now()),
          "note" =>
            "AshVault key root marker. Do not delete: #{inspect(__MODULE__)} refuses to " <>
              "start without it, which is what stops an unmounted volume from looking " <>
              "like an empty, never-used key store."
        })
      )

      File.chmod!(sentinel, @key_file_mode)
    end

    :ok
  end

  @doc """
  The name of the sentinel file that marks a directory as an initialised key root.
  """
  @spec sentinel_file() :: String.t()
  def sentinel_file, do: @sentinel_file

  @doc """
  The directory name, relative to the root, holding a scope's key material.

      iex> AshVault.KeyProviders.Local.scope_dir("acme")
      "YWNtZQ"

  The encoding is `Base.url_encode64/2` without padding: total, reversible and safe on
  every filesystem, so operators can map a tenant id to a directory and back.
  """
  @spec scope_dir(binary()) :: String.t()
  def scope_dir(scope) when is_binary(scope), do: Base.url_encode64(scope, padding: false)

  @doc """
  The purposes this provider serves: `[:data, :mac]`.
  """
  @impl AshVault.KeyProvider
  @spec purposes() :: [AshVault.KeyProvider.purpose()]
  def purposes, do: [:data, :mac]

  @doc """
  Fetch the current `:data` key for a scope, minting version 1 on first use.
  """
  @impl AshVault.KeyProvider
  @spec current_key(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope), do: current_key(__MODULE__, scope, :data)

  @doc """
  Two forms, told apart by the first argument — a scope is always a binary, a server
  never is:

    * `current_key(scope, purpose)` — the `c:AshVault.KeyProvider.current_key/2`
      callback, against the default-named instance;
    * `current_key(server, scope)` — `current_key/1` against an explicitly named
      instance.
  """
  @impl AshVault.KeyProvider
  @spec current_key(term(), term()) :: {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope, purpose) when is_binary(scope),
    do: current_key(__MODULE__, scope, purpose)

  def current_key(server, scope),
    do: call(server, {:current_key, validate_server_scope!(server, scope), :data})

  @doc """
  `current_key/2` for a purpose, against an explicitly named instance.
  """
  @spec current_key(
          GenServer.server(),
          AshVault.KeyProvider.scope(),
          AshVault.KeyProvider.purpose()
        ) :: {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(server, scope, purpose),
    do: call(server, {:current_key, validate_scope!(scope), validate_purpose!(purpose)})

  @doc """
  Fetch a specific `:data` key version for a scope.
  """
  @impl AshVault.KeyProvider
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version), do: get_key(__MODULE__, scope, version, :data)

  @doc """
  Two forms, told apart by the first argument:

    * `get_key(scope, version, purpose)` — the `c:AshVault.KeyProvider.get_key/3`
      callback, against the default-named instance;
    * `get_key(server, scope, version)` — `get_key/2` against a named instance.
  """
  @impl AshVault.KeyProvider
  @spec get_key(term(), term(), term()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version, purpose) when is_binary(scope),
    do: get_key(__MODULE__, scope, version, purpose)

  def get_key(server, scope, version),
    do: call(server, {:get_key, validate_scope!(scope), version, :data})

  @doc """
  `get_key/3` for a purpose, against an explicitly named instance.
  """
  @spec get_key(
          GenServer.server(),
          AshVault.KeyProvider.scope(),
          AshVault.KeyProvider.version(),
          AshVault.KeyProvider.purpose()
        ) :: {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(server, scope, version, purpose),
    do: call(server, {:get_key, validate_scope!(scope), version, validate_purpose!(purpose)})

  @doc """
  Mint the next `:data` key version for a scope, keeping previous versions fetchable.
  """
  @impl AshVault.KeyProvider
  @spec rotate(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope), do: rotate(__MODULE__, scope, :data)

  @doc """
  Two forms, told apart by the first argument:

    * `rotate(scope, purpose)` — the `c:AshVault.KeyProvider.rotate/2` callback;
    * `rotate(server, scope)` — `rotate/1` against a named instance.
  """
  @impl AshVault.KeyProvider
  @spec rotate(term(), term()) :: {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope, purpose) when is_binary(scope), do: rotate(__MODULE__, scope, purpose)

  def rotate(server, scope),
    do: call(server, {:rotate, validate_server_scope!(server, scope), :data})

  @doc """
  `rotate/2` for a purpose, against an explicitly named instance.
  """
  @spec rotate(GenServer.server(), AshVault.KeyProvider.scope(), AshVault.KeyProvider.purpose()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(server, scope, purpose),
    do: call(server, {:rotate, validate_scope!(scope), validate_purpose!(purpose)})

  @doc """
  Irreversibly destroy every key for a scope — every purpose, and the lookup key — and
  write its tombstone.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope), do: destroy(__MODULE__, scope)

  @doc """
  Fetch the scope's stable lookup key, minting `lookup.key` on first use.

  Written with the same crash-safe ordering as a versioned key, gated by the same
  tombstone, and shredded by the same `destroy/1` — it ends in `.key`, so
  `shred_directory/1` overwrites it before unlinking like any other key file.

  It is deliberately absent from `meta.json`: it has no version, and `rotate/1` must
  never touch it. See `c:AshVault.KeyProvider.lookup_key/1`.
  """
  @impl AshVault.KeyProvider
  @spec lookup_key(AshVault.KeyProvider.scope()) :: {:ok, binary()} | {:error, term()}
  def lookup_key(scope), do: lookup_key(__MODULE__, scope)

  @doc """
  Same as `destroy/1`, against an explicitly named instance.
  """
  @spec destroy(GenServer.server(), AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(server, scope), do: call(server, {:destroy, validate_scope!(scope)})

  @doc """
  Same as `lookup_key/1`, against an explicitly named instance.
  """
  @spec lookup_key(GenServer.server(), AshVault.KeyProvider.scope()) ::
          {:ok, binary()} | {:error, term()}
  def lookup_key(server, scope), do: call(server, {:lookup_key, validate_scope!(scope)})

  defp call(server, message) do
    GenServer.call(server, message)
  catch
    :exit, reason -> {:error, {:provider_unavailable, reason}}
  end

  defp validate_scope!(scope) when is_binary(scope), do: scope

  defp validate_scope!(scope) do
    raise ArgumentError, """
    #{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}.

    Scopes reach a key provider already normalised to a binary by the vault's
    `AshVault.Scope` implementation.
    """
  end

  # `current_key(:not_a_scope, :mac)` lands in the named-server clause, because its first
  # argument is not a binary. Report the term the caller meant as a scope, not the purpose.
  defp validate_server_scope!(server, scope) when scope in [:data, :mac],
    do: validate_scope!(server)

  defp validate_server_scope!(_server, scope), do: validate_scope!(scope)

  defp validate_purpose!(purpose) when purpose in [:data, :mac], do: purpose

  defp validate_purpose!(purpose) do
    raise ArgumentError,
          "#{inspect(__MODULE__)} purposes are :data and :mac, got: #{inspect(purpose)}"
  end

  defp resolve_root!(opts) do
    config = AshVault.KeyProvider.config(__MODULE__)

    case Keyword.get(opts, :root) || Keyword.get(config, :root) do
      root when is_binary(root) and root != "" ->
        Path.expand(root)

      nil ->
        raise ArgumentError, """
        #{inspect(__MODULE__)} requires a `:root` directory to store key material in.

        Either pass it when starting the provider:

            {#{inspect(__MODULE__)}, root: "/var/lib/my_app/ash_vault_keys"}

        or configure it, under your own application or under `:ash_vault`:

            config :my_app, #{inspect(__MODULE__)},
              root: "/var/lib/my_app/ash_vault_keys"

        That directory must live outside the database backup — see the moduledoc.
        """

      other ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} `:root` must be a non-empty string, got: #{inspect(other)}"
    end
  end

  @impl GenServer
  def init(opts) do
    root = Keyword.fetch!(opts, :root)

    # Deliberately NOT `File.mkdir_p!/1`. See the moduledoc: creating the root is how an
    # unmounted key volume turns into a pristine-looking key store that resurrects every
    # tenant you have ever crypto-erased.
    verify_initialised!(root)
    verify_writable!(root)
    warn_on_loose_permissions(root)

    {:ok, %{root: root, key_bytes: Keyword.fetch!(opts, :key_bytes)}}
  end

  defp verify_initialised!(root) do
    cond do
      not File.dir?(root) ->
        raise ArgumentError, uninitialised_message(root, "does not exist, or is not a directory")

      not File.regular?(sentinel_path(root)) ->
        raise ArgumentError,
              uninitialised_message(
                root,
                "exists but holds no #{@sentinel_file} sentinel, so it is either " <>
                  "uninitialised or not the volume you think it is"
              )

      true ->
        :ok
    end
  end

  defp uninitialised_message(root, what) do
    """
    #{inspect(__MODULE__)} key root #{root} #{what}.

    #{inspect(__MODULE__)} never creates its own key root. If it did, a key volume that
    failed to mount would be silently replaced by an empty directory on the underlying
    filesystem: no tombstones, no key material, and a fresh version 1 minted for every
    tenant that was ever crypto-erased.

    Initialise the root once, explicitly, as the operator:

        mix ash_vault.local.init #{root}

    or from code:

        #{inspect(__MODULE__)}.init_root!(#{inspect(root)})

    If the directory already existed and you are seeing this, do NOT run the task
    blindly — check that the volume holding the key material is actually mounted first.
    """
  end

  defp verify_writable!(root) do
    case File.stat(root) do
      {:ok, %File.Stat{type: :directory, access: access}} when access in [:write, :read_write] ->
        :ok

      {:ok, %File.Stat{type: :directory}} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} root #{root} is not writable by this process."

      {:ok, %File.Stat{type: type}} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} root #{root} exists but is a #{type}, not a directory."

      {:error, reason} ->
        raise ArgumentError,
              "#{inspect(__MODULE__)} could not stat root #{root}: #{inspect(reason)}"
    end
  end

  defp warn_on_loose_permissions(root) do
    with {:ok, %File.Stat{mode: mode}} <- File.stat(root),
         true <- Bitwise.band(mode, 0o077) != 0 do
      Logger.warning("""
      #{inspect(__MODULE__)} key root #{root} has mode \
      #{mode |> Bitwise.band(0o777) |> Integer.to_string(8) |> String.pad_leading(4, "0")}, \
      which is group- or world-accessible.

      Key material is readable by other users on this machine. Run:

          chmod 0700 #{root}

      Starting anyway.
      """)
    end

    :ok
  end

  @impl GenServer
  def handle_call({:current_key, scope, purpose}, _from, state) do
    {:reply, do_current_key(state, scope, purpose), state}
  end

  def handle_call({:get_key, scope, version, purpose}, _from, state) do
    {:reply, do_get_key(state, scope, version, purpose), state}
  end

  def handle_call({:rotate, scope, purpose}, _from, state) do
    {:reply, do_rotate(state, scope, purpose), state}
  end

  def handle_call({:destroy, scope}, _from, state) do
    {:reply, do_destroy(state, scope), state}
  end

  def handle_call({:lookup_key, scope}, _from, state) do
    {:reply, do_lookup_key(state, scope), state}
  end

  # -- operations ------------------------------------------------------------

  defp do_current_key(state, scope, purpose) do
    with :absent <- tombstone_state(state, scope) do
      case read_meta(state, scope, purpose) do
        :missing -> mint(state, scope, 1, purpose)
        {:ok, meta} -> load_current(state, scope, meta, purpose)
        {:error, _} = error -> error
      end
    end
  end

  defp load_current(state, scope, meta, purpose) do
    version = meta.current

    case File.read(key_path(state, scope, version, purpose)) do
      {:ok, key} ->
        with :ok <- validate_key_size(state, key, scope, version, purpose) do
          {:ok, %{version: version, key: key, created_at: Map.fetch!(meta.versions, version)}}
        end

      # The meta names a version whose key file is gone. That is data loss, not
      # erasure — it must never be reported as `:destroyed`.
      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error,
         unavailable({:key_read_failed, key_path(state, scope, version, purpose), reason})}
    end
  end

  # A key file of the wrong length is a corrupt or truncated key store, not a key. Handed
  # to the cipher it becomes `{:error, {:invalid_key_size, n}}`, which the vault would
  # report as `AshVault.Errors.CiphertextIntegrityFailed` — "your data was tampered with" for
  # what is in fact a broken key file.
  defp validate_key_size(state, key, scope, version, purpose) do
    expected = key_size(state, purpose)

    if byte_size(key) == expected do
      :ok
    else
      key_size_error(expected, key, scope, version)
    end
  end

  defp key_size(state, :data), do: state.key_bytes
  defp key_size(_state, :mac), do: AshVault.KeyProvider.mac_key_bytes()

  defp key_size_error(expected, key, scope, version) do
    {:error,
     unavailable(
       {:invalid_key_size,
        %{
          scope_dir: scope_dir(scope),
          version: version,
          expected: expected,
          actual: byte_size(key)
        }}
     )}
  end

  defp do_get_key(state, scope, version, purpose) do
    with :absent <- tombstone_state(state, scope) do
      # `version` is public API. Without this guard a caller passing
      # "../../../etc/ssl/private/server" reads any `.key` file this process can reach.
      if is_integer(version) and version > 0 do
        read_key_file(state, scope, version, purpose)
      else
        {:error, :not_found}
      end
    end
  end

  defp read_key_file(state, scope, version, purpose) do
    case File.read(key_path(state, scope, version, purpose)) do
      {:ok, key} ->
        with :ok <- validate_key_size(state, key, scope, version, purpose), do: {:ok, key}

      {:error, reason} when reason in [:enoent, :enotdir, :enametoolong] ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, unavailable({:key_read_failed, reason})}
    end
  end

  defp do_rotate(state, scope, purpose) do
    with :absent <- tombstone_state(state, scope) do
      case read_meta(state, scope, purpose) do
        :missing ->
          with {:ok, %{version: version}} <- mint(state, scope, 1, purpose), do: {:ok, version}

        {:ok, meta} ->
          with {:ok, %{version: version}} <-
                 mint(state, scope, meta.current + 1, purpose, meta),
               do: {:ok, version}

        {:error, _} = error ->
          error
      end
    end
  end

  # Minted once, then read back verbatim forever. There is deliberately no path that
  # rewrites an existing lookup.key: every token already in the database is an HMAC
  # under these exact bytes.
  defp do_lookup_key(state, scope) do
    with :absent <- tombstone_state(state, scope) do
      path = lookup_key_path(state, scope)

      case File.read(path) do
        {:ok, key} when byte_size(key) == 0 ->
          {:error, unavailable({:corrupt_lookup_key, path})}

        {:ok, key} ->
          {:ok, key}

        {:error, reason} when reason in [:enoent, :enotdir] ->
          mint_lookup_key(state, scope, path)

        {:error, reason} ->
          {:error, unavailable({:key_read_failed, path, reason})}
      end
    end
  end

  defp mint_lookup_key(state, scope, path) do
    key = :crypto.strong_rand_bytes(state.key_bytes)

    with :ok <- ensure_dir(scope_path(state, scope)),
         :ok <- atomic_write(path, key) do
      {:ok, key}
    end
  end

  # Tombstone FIRST. See the moduledoc: shredding first leaves a window in which a
  # scope has no key material and no tombstone, and the next `current_key/1` mints a
  # fresh v1 that makes every existing row look tampered with.
  defp do_destroy(state, scope) do
    dir = scope_path(state, scope)

    with :ok <- write_tombstone(state, scope),
         :ok <- shred_directory(dir) do
      mark_shredded(state, scope)
      :ok
    end
  end

  # -- minting ---------------------------------------------------------------

  # A `:mac` key is its own random draw at the fixed MAC key size, in its own files: never
  # the data key, never derived from it, and never the same length by accident.
  defp mint(state, scope, version, purpose, meta \\ %{current: 0, versions: %{}}) do
    dir = scope_path(state, scope)
    created_at = DateTime.utc_now()
    key = :crypto.strong_rand_bytes(key_size(state, purpose))

    meta = %{
      current: version,
      versions: Map.put(meta.versions, version, created_at)
    }

    with :ok <- ensure_dir(dir),
         # Key material lands first. A crash between these two writes leaves an orphan
         # key file (harmless); the reverse order would leave meta.json pointing at a
         # key that does not exist, which is an accidental crypto-erasure.
         :ok <- atomic_write(key_path(state, scope, version, purpose), key),
         :ok <- atomic_write(meta_path(state, scope, purpose), encode_meta(meta)) do
      {:ok, %{version: version, key: key, created_at: created_at}}
    end
  end

  defp ensure_dir(dir) do
    case File.mkdir_p(dir) do
      :ok -> File.chmod(dir, 0o700)
      {:error, reason} -> {:error, unavailable({:mkdir_failed, dir, reason})}
    end
  end

  # -- meta.json -------------------------------------------------------------

  defp encode_meta(meta) do
    Jason.encode!(%{
      "current" => meta.current,
      "versions" =>
        Map.new(meta.versions, fn {version, at} ->
          {Integer.to_string(version), DateTime.to_iso8601(at)}
        end)
    })
  end

  defp read_meta(state, scope, purpose) do
    path = meta_path(state, scope, purpose)

    case File.read(path) do
      {:ok, body} -> decode_meta(body, path)
      {:error, reason} when reason in [:enoent, :enotdir] -> :missing
      {:error, reason} -> {:error, unavailable({:meta_read_failed, path, reason})}
    end
  end

  defp decode_meta(body, path) do
    with {:ok, %{"current" => current, "versions" => versions}} when is_map(versions) <-
           Jason.decode(body),
         true <- is_integer(current) and current > 0,
         {:ok, versions} <- decode_versions(versions),
         # A meta naming a `current` it has no timestamp for is corrupt, not usable with
         # a made-up `created_at`: an epoch timestamp would make every age-based
         # `AshVault.RotationPolicy` fire forever with no error anywhere.
         true <- Map.has_key?(versions, current) do
      {:ok, %{current: current, versions: versions}}
    else
      _ -> {:error, unavailable({:corrupt_meta, path})}
    end
  end

  defp decode_versions(versions) do
    Enum.reduce_while(versions, {:ok, %{}}, fn {version, at}, {:ok, acc} ->
      with {parsed, ""} <- Integer.parse(to_string(version)),
           {:ok, at, _offset} <- DateTime.from_iso8601(to_string(at)) do
        {:cont, {:ok, Map.put(acc, parsed, at)}}
      else
        _ -> {:halt, :error}
      end
    end)
  end

  # -- tombstones ------------------------------------------------------------

  # Fails CLOSED. `File.exists?/1` answers `false` for *any* stat failure, not just
  # absence — a parent directory at mode 000 (`:eacces`), a failing disk (`:eio`), a
  # stale NFS handle (`:estale`), a symlink loop (`:eloop`). During any such window
  # `File.exists?/1` would report a destroyed scope as intact and the provider would
  # mint it a fresh key. Only a positive `:enoent` is absence.
  @spec tombstone_state(map(), binary()) ::
          :absent | {:error, :destroyed} | {:error, Exception.t()}
  defp tombstone_state(state, scope) do
    path = tombstone_path(state, scope)

    case File.stat(path) do
      # Presence alone decides. The contents are never parsed: a truncated or
      # unreadable tombstone must still mean destroyed.
      {:ok, _stat} -> {:error, :destroyed}
      {:error, :enoent} -> :absent
      # A path component longer than the filesystem allows can never have been written,
      # so a tombstone at it cannot exist: this is a positive answer, not a failed read.
      # Reporting it as an outage would let a caller-supplied scope (a forged macaroon)
      # manufacture a `ProviderUnavailable` at will.
      {:error, :enametoolong} -> :absent
      {:error, reason} -> {:error, unavailable({:tombstone_unreadable, path, reason})}
    end
  end

  defp write_tombstone(state, scope) do
    path = tombstone_path(state, scope)

    case File.stat(path) do
      # Already destroyed. Keep the original `destroyed_at`; destroy/1 is idempotent.
      {:ok, _stat} ->
        :ok

      {:error, :enoent} ->
        atomic_write(
          path,
          Jason.encode!(%{"destroyed_at" => DateTime.to_iso8601(DateTime.utc_now())})
        )

      {:error, reason} ->
        {:error, unavailable({:tombstone_unreadable, path, reason})}
    end
  end

  # Best effort, and deliberately so: the tombstone already exists and already means
  # destroyed. This only records that the shred finished, so an operator can tell an
  # interrupted destroy from a completed one.
  defp mark_shredded(state, scope) do
    path = tombstone_path(state, scope)

    with {:ok, body} <- File.read(path),
         {:ok, %{} = decoded} <- Jason.decode(body) do
      _ =
        atomic_write(
          path,
          Jason.encode!(Map.put(decoded, "shredded_at", DateTime.to_iso8601(DateTime.utc_now())))
        )
    end

    :ok
  end

  # -- shredding -------------------------------------------------------------

  defp shred_directory(dir) do
    case File.ls(dir) do
      {:ok, entries} ->
        Enum.reduce_while(entries, :ok, fn entry, :ok ->
          case shred_entry(Path.join(dir, entry), entry) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
        end)
        |> case do
          :ok -> remove_dir(dir)
          error -> error
        end

      {:error, reason} when reason in [:enoent, :enotdir] ->
        :ok

      {:error, reason} ->
        {:error, unavailable({:scope_dir_unreadable, dir, reason})}
    end
  end

  defp shred_entry(path, entry) do
    # Key material is overwritten before unlinking. Best-effort only — see the moduledoc
    # on copy-on-write and log-structured filesystems.
    if String.ends_with?(entry, ".key"), do: overwrite(path)

    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, unavailable({:shred_failed, path, reason})}
    end
  end

  defp overwrite(path) do
    with {:ok, %File.Stat{size: size}} <- File.stat(path),
         # `:read` is load-bearing: without it Erlang truncates the file on open, and a
         # truncate-then-append allocates fresh blocks instead of overwriting in place.
         {:ok, fd} <- :file.open(path, [:read, :write, :raw, :binary]) do
      _ = :file.write(fd, :crypto.strong_rand_bytes(size))
      _ = :file.sync(fd)
      _ = :file.close(fd)
    end

    :ok
  end

  defp remove_dir(dir) do
    case File.rmdir(dir) do
      :ok ->
        :ok

      {:error, :enoent} ->
        :ok

      {:error, _reason} ->
        case File.rm_rf(dir) do
          {:ok, _} -> :ok
          {:error, reason, _} -> {:error, unavailable({:rmdir_failed, dir, reason})}
        end
    end
  end

  # -- durable writes --------------------------------------------------------

  defp atomic_write(path, contents) do
    tmp = path <> ".tmp-" <> Integer.to_string(System.unique_integer([:positive]))

    with {:ok, fd} <- :file.open(tmp, [:write, :raw, :binary]),
         :ok <- write_and_sync(fd, contents),
         :ok <- File.chmod(tmp, @key_file_mode),
         :ok <- File.rename(tmp, path) do
      # Best-effort: OTP cannot open a directory to fsync it, so the durability of the
      # rename itself is the filesystem's business. Ordering — key file before the meta
      # that names it — is what this module actually depends on.
      sync_dir(Path.dirname(path))
      :ok
    else
      {:error, reason} ->
        _ = File.rm(tmp)
        {:error, unavailable({:write_failed, path, reason})}
    end
  end

  defp write_and_sync(fd, contents) do
    with :ok <- :file.write(fd, contents),
         :ok <- :file.sync(fd) do
      :file.close(fd)
    else
      {:error, reason} ->
        _ = :file.close(fd)
        {:error, reason}
    end
  end

  defp sync_dir(dir) do
    case :file.open(dir, [:read, :raw]) do
      {:ok, fd} ->
        _ = :file.sync(fd)
        _ = :file.close(fd)
        :ok

      # `:eisdir` on every platform OTP supports: there is no directory fsync here.
      {:error, _reason} ->
        :ok
    end
  end

  # -- paths -----------------------------------------------------------------

  defp scope_path(state, scope), do: Path.join(state.root, scope_dir(scope))

  defp tombstone_path(state, scope),
    do: Path.join(state.root, scope_dir(scope) <> ".tombstone")

  defp sentinel_path(root), do: Path.join(root, @sentinel_file)

  # Each purpose has its own name space inside the scope directory: `v<n>.key` and
  # `meta.json` for `:data`, `mac-v<n>.key` and `mac-meta.json` for `:mac`. No name in one
  # can be produced by the other, so `get_key/2` can never hand a MAC key to the cipher.
  defp key_path(state, scope, version, :data),
    do: Path.join(scope_path(state, scope), "v#{version}.key")

  defp key_path(state, scope, version, :mac),
    do: Path.join(scope_path(state, scope), "mac-v#{version}.key")

  defp meta_path(state, scope, :data), do: Path.join(scope_path(state, scope), @meta_file)
  defp meta_path(state, scope, :mac), do: Path.join(scope_path(state, scope), @mac_meta_file)

  # `v<n>.key` for data keys, `lookup.key` for this one: the name spaces cannot collide,
  # so `get_key/2` can never hand the lookup key to the cipher.
  defp lookup_key_path(state, scope), do: Path.join(scope_path(state, scope), "lookup.key")

  defp unavailable(reason),
    do: ProviderUnavailable.exception(provider: __MODULE__, reason: reason)
end
