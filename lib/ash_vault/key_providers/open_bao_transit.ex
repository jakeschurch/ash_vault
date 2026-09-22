defmodule AshVault.KeyProviders.OpenBaoTransit do
  @moduledoc """
  An `AshVault.KeyProvider` backed by OpenBao `transit` that **never exports key
  material**.

  This is the sibling of `AshVault.KeyProviders.OpenBao`, and the difference is the
  whole point: that provider exports a scope's raw DEK so an in-process cipher can use
  it, and this one does not export anything ever. Encryption and decryption happen
  *inside* OpenBao, through `transit/encrypt` and `transit/decrypt`. The key bytes never
  become an Elixir term, never land on a process heap, and never appear in a crash dump,
  a core file or a `:erlang.system_info(:procs)` dump — because they never leave the
  server.

  > #### The cost is three network round trips per value {: .warning}
  >
  > Per *value*, not per query — and three, not one. Measured with a
  > `[:finch, :request, :stop]` counter in
  > `test/ash_vault/ciphers/open_bao_transit_test.exs`:
  >
  >   * **encrypt: 3 calls** — tombstone read, `transit/keys` metadata read, then
  >     `transit/encrypt`. A scope's very first encrypt adds the key-create call.
  >   * **decrypt: 3 calls** — tombstone read, `transit/keys` metadata read, then
  >     `transit/decrypt`.
  >
  > For comparison, measured the same way, `AshVault.KeyProviders.OpenBao` costs 3 on
  > encrypt and **2** on decrypt, and `AshVault.KeyProviders.Cached` collapses both to
  > **0** on a cache hit. This provider gets nothing from that wrapper: `Cached` caches
  > a key only when it `is_binary/1`, so a handle passes through uncached on every call.
  > Transit also has batch endpoints, but the `AshVault.Cipher` contract is one value at
  > a time, so they go unused.
  >
  > A page of 50 rows with two encrypted columns is therefore ~300 calls, ~300 ms of
  > serialised latency at a 1 ms round trip. Choose this provider when key material in
  > BEAM memory is the threat you are actually defending against, and measure before you
  > roll it out broadly.

  ## How it works

  A `AshVault.KeyProvider` callback has to return *something* as the key. This one
  returns an opaque `AshVault.Key` handle naming the transit key and the version to use:

      %AshVault.Key{ref: {"ashvault_nx_dGVuYW50XzQy", 3}, owner: AshVault.KeyProviders.OpenBaoTransit}

  The handle carries no secret — only a name and an integer — and it is a pure,
  deterministic function of the scope and the version, so two calls for the same scope
  and version are equal terms. `AshVault.Ciphers.OpenBaoTransit` is the only cipher that
  understands it; every other cipher returns `{:error, :opaque_key_unsupported}` and
  `AshVault.Vault.Runtime` raises `AshVault.Errors.OpaqueKeyUnsupported` naming both
  modules. There is deliberately no unwrap path.

      defmodule MyApp.Vault do
        use AshVault.Vault,
          key_provider: AshVault.KeyProviders.OpenBaoTransit,
          cipher: AshVault.Ciphers.OpenBaoTransit
      end

  ## Configuration

      config :ash_vault, AshVault.KeyProviders.OpenBaoTransit,
        address: "http://127.0.0.1:8200",
        token: {:system, "BAO_TOKEN"},
        transit_mount: "transit",
        kv_mount: "ashvault",
        key_type: "aes256-gcm96",
        receive_timeout: 5_000,
        max_retries: 2

  `AshVault.Ciphers.OpenBaoTransit` reads this same configuration block — address and
  token are looked up under *this* module's key, never carried in the handle.

  ## The key is verified non-exportable on every metadata read

  Creating a transit key that already exists is a **silent no-op** on OpenBao 2.6.2: the
  server returns the existing metadata and ignores the `exportable` flag you sent
  (verified live). So posting `exportable: false` is not a guarantee — if the key was
  already created exportable, by `AshVault.KeyProviders.OpenBao` or by an operator, this
  provider would quietly be using exportable key material while its moduledoc promised
  otherwise.

  `current_key/1` and `get_key/2` therefore *read* `data.exportable` back and refuse
  with `AshVault.Errors.ProviderUnavailable` (`reason: {:exportable_key, name}`) if it
  is true. The claim in the headline is a checked invariant, not a hope.

  This is checked when a key handle is obtained, not on every transit call — flipping a
  key to exportable mid-request is not defended against, and cannot be from here.

  ## Transit key names are deliberately distinct from the exporting provider's

  `AshVault.KeyProviders.OpenBao` uses `ashvault_<base64url(scope)>`; this provider uses
  `ashvault_nx_<base64url(scope)>` (`nx` for non-exportable). Sharing a name would mean
  the first provider to touch a scope decides whether its key is exportable, and the
  other one silently inherits that decision.

  The consequence is that the two providers hold **separate key material and separate
  tombstones** for the same scope, exactly as `AshVault.KeyProviders.Local` and
  `AshVault.KeyProviders.OpenBao` do. Migrating between them means re-encrypting, and
  erasing a subject who has data under both means destroying under both vaults. See
  [Two vaults in one application](two-vaults.md).

  ## The OpenBao policy this provider needs

  Verified against openbao 2.6.2. `POST /v1/transit/encrypt/<name>` **creates the key**
  if it does not exist, and pinning `key_version` does not stop it. That matters here
  because the cipher issues the encrypt from a handle, and the tombstone check lives in
  the provider: a handle obtained microseconds before a `destroy/1` would recreate the
  deleted transit key on its next encrypt. The recreated key is orphaned — the tombstone
  still fails every read closed — but it is key material that should not exist.

  Withhold the `create` capability on the encrypt path and OpenBao refuses the
  auto-creation with `403` while still allowing encryption of existing keys (verified):

      path "transit/keys/*"            { capabilities = ["read"] }
      path "transit/keys/+/rotate"     { capabilities = ["update"] }
      path "transit/keys/+/config"     { capabilities = ["update"] }
      path "transit/encrypt/*"         { capabilities = ["update"] }
      path "transit/decrypt/*"         { capabilities = ["update"] }
      path "ashvault/data/tombstones/*" { capabilities = ["create", "read", "update"] }

  Note there is **no** `transit/export/*` grant, and there must not be one. A separate,
  privileged token does key creation (`create` on `transit/keys/*`) and destruction.
  Running the application token with `create` on `transit/encrypt/*` still works; it just
  gives up this guarantee, and `current_key/1` will create keys on demand as the
  exporting provider does.

  ## Searchable fields are not supported

  This provider deliberately does not implement `c:AshVault.KeyProvider.lookup_key/1`. A
  lookup key must be raw bytes in the application process — `AshVault.Lookup` runs HKDF
  and HMAC locally — and transit cannot hand out raw bytes by definition. Implementing it
  through a second, *exportable* transit key would make the provider's one promise false
  for the sake of a feature the exporting provider already does well.

  The consequence is loud, not silent: `AshVault.Verifiers.VerifyVault` turns
  `searchable?: true` under this provider into a compile-time DSL error naming the
  provider, and `AshVault.Errors.LookupUnsupported` is the runtime backstop. Use
  `AshVault.KeyProviders.OpenBao` for vaults with searchable fields, or split the
  resource across two vaults.

  A future provider could compute tokens with `transit/hmac/<key>` and skip local HKDF
  entirely, at one more round trip per searchable field per query. That is not built.

  ## Tombstones and fail-closed behaviour

  Identical to `AshVault.KeyProviders.OpenBao`, through the shared
  `AshVault.KeyProviders.OpenBao.Transport`: `destroy/1` writes the tombstone *before*
  deleting the transit key; a missing KV mount on a read path is
  `AshVault.Errors.ProviderUnavailable` and never "not destroyed"; `destroy/1` returns
  `:ok` only once the transit key is confirmed absent by a fresh read. An outage is never
  reported as erasure, and erasure is never reported as an outage.
  """

  @behaviour AshVault.KeyProvider

  alias AshVault.KeyProviders.OpenBao.Transport

  @prefix "ashvault_nx_"
  @default_key_type "aes256-gcm96"

  @doc """
  The transit key name a scope maps to.

  Note the `_nx_` infix: this provider's keys are a different namespace from
  `AshVault.KeyProviders.OpenBao`'s, on purpose.

      iex> AshVault.KeyProviders.OpenBaoTransit.key_name("tenant_42")
      "ashvault_nx_dGVuYW50XzQy"
  """
  @spec key_name(AshVault.KeyProvider.scope()) :: String.t()
  def key_name(scope), do: Transport.key_name(__MODULE__, @prefix, scope)

  @doc """
  Mount the KV-v2 engine that holds tombstones, if it is not already mounted.

  The operator setup step, and the only place the mount is created: the tombstone read
  path treats a missing mount as an outage and never provisions it, because a freshly
  created, empty tombstone store reports every erased scope as intact.
  """
  @impl AshVault.KeyProvider
  @spec setup() :: :ok | {:error, Exception.t()}
  def setup, do: Transport.ensure_kv_mount(__MODULE__)

  @doc """
  The current key handle for a scope, creating the transit key (version 1) on first use.

  The `:key` is an `AshVault.Key` handle, never bytes. `created_at` comes from the
  server's own key metadata — never fabricated, because a key that is always "created
  now" is never older than a `max_age` and silently disables every age-based
  `AshVault.RotationPolicy`.
  """
  @impl AshVault.KeyProvider
  @spec current_key(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope) do
    name = key_name(scope)

    with :absent <- check_tombstone(name),
         {:ok, meta} <- meta_or_create(name),
         :ok <- refuse_exportable(name, meta),
         version = meta["latest_version"],
         {:ok, created_at} <- Transport.created_at(__MODULE__, meta, version) do
      {:ok, %{version: version, key: handle(name, version), created_at: created_at}}
    end
  end

  @doc """
  A handle to one specific key version of a scope.

  The version is validated against the server's `latest_version` and
  `min_decryption_version` **before** a handle is returned. Handing back a handle for a
  version that does not exist would push the failure into
  `AshVault.Ciphers.OpenBaoTransit`, where a transit `400` becomes
  `AshVault.Errors.CiphertextIntegrityFailed` — telling an operator their data was
  tampered with, over a key version that was simply never minted.
  """
  @impl AshVault.KeyProvider
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, AshVault.Key.opaque()}
          | {:error, :not_found}
          | {:error, :destroyed}
          | {:error, term()}
  def get_key(scope, version) do
    name = key_name(scope)

    with :absent <- check_tombstone(name) do
      if is_integer(version) and version > 0 do
        fetch_version(name, version)
      else
        {:error, :not_found}
      end
    end
  end

  defp fetch_version(name, version) do
    case Transport.read_meta(__MODULE__, name) do
      {:ok, :missing} ->
        {:error, :not_found}

      {:ok, meta} ->
        with :ok <- refuse_exportable(name, meta) do
          if usable_version?(meta, version) do
            {:ok, handle(name, version)}
          else
            {:error, :not_found}
          end
        end

      {:error, error} ->
        {:error, error}
    end
  end

  # `min_decryption_version` is an operator-set floor: versions below it are refused by
  # transit itself, so reporting them as `:not_found` here matches what the exporting
  # provider reports for the same key and keeps the two interchangeable.
  defp usable_version?(meta, version) do
    latest = meta["latest_version"]
    minimum = meta["min_decryption_version"] || 1

    is_integer(latest) and version <= latest and version >= minimum and
      Map.has_key?(Map.get(meta, "keys") || %{}, to_string(version))
  end

  @doc """
  Mint the next key version for a scope. Previous versions stay decryptable.
  """
  @impl AshVault.KeyProvider
  @spec rotate(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope) do
    name = key_name(scope)

    with :absent <- check_tombstone(name),
         {:ok, meta} <- Transport.read_meta(__MODULE__, name) do
      case meta do
        :missing ->
          # No key yet: creating it mints version 1, which is the rotation. Matches
          # `AshVault.KeyProviders.Memory` and `AshVault.KeyProviders.OpenBao`.
          with {:ok, created} <- create_key(name), do: {:ok, created["latest_version"]}

        _ ->
          with :ok <- refuse_exportable(name, meta),
               {:ok, response} <-
                 Transport.post(__MODULE__, path("/keys/#{name}/rotate"), %{}),
               {:ok, data} <- transit_ok(response) do
            {:ok, data["latest_version"]}
          end
      end
    end
  end

  @doc """
  Tombstone a scope, then irreversibly destroy every key version for it.

  The tombstone is committed first, so an interrupted destroy fails closed: a later
  `current_key/1` cannot mint a fresh v1 for ciphertext whose key is already gone.
  Returns `:ok` only once the transit key is confirmed absent by a fresh read, and a
  repeated call resumes cleanup behind an existing tombstone.

  There is no lookup key to delete — this provider has none.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope) do
    name = key_name(scope)

    with :ok <- ensure_tombstone(name) do
      Transport.delete_transit_key(__MODULE__, name)
    end
  end

  defp ensure_tombstone(name) do
    case check_tombstone(name) do
      :absent -> Transport.write_tombstone(__MODULE__, name)
      {:error, :destroyed} -> :ok
      other -> other
    end
  end

  # ── handles ────────────────────────────────────────────────────────────────────

  @doc """
  The opaque handle this provider serves for a transit key name and version.

  Deterministic and secret-free: `{name, version}`. `AshVault.Key` derives a redacted
  `Inspect` that shows only `:owner`, which matters because the name is
  `Base.url_encode64/2` of the tenant id and therefore reversible.
  """
  @spec handle(String.t(), AshVault.KeyProvider.version()) :: AshVault.Key.opaque()
  def handle(name, version) when is_binary(name) and is_integer(version) do
    %AshVault.Key{ref: {name, version}, owner: __MODULE__}
  end

  @doc """
  The transit key name and version a handle refers to, for
  `AshVault.Ciphers.OpenBaoTransit`.
  """
  @spec unwrap(AshVault.Key.t()) :: {:ok, {String.t(), pos_integer()}} | :error
  def unwrap(%AshVault.Key{ref: {name, version}, owner: __MODULE__})
      when is_binary(name) and is_integer(version) and version > 0 do
    {:ok, {name, version}}
  end

  def unwrap(_key), do: :error

  # ── transit ────────────────────────────────────────────────────────────────────

  defp check_tombstone(name), do: Transport.check_tombstone(__MODULE__, name)

  defp meta_or_create(name) do
    case Transport.read_meta(__MODULE__, name) do
      {:ok, :missing} -> create_key(name)
      {:ok, meta} -> {:ok, meta}
      {:error, error} -> {:error, error}
    end
  end

  defp create_key(name) do
    body = %{
      type: key_type(),
      exportable: false,
      allow_plaintext_backup: false
    }

    with {:ok, response} <- Transport.post(__MODULE__, path("/keys/#{name}"), body),
         {:ok, meta} <- transit_ok(response),
         :ok <- refuse_exportable(name, meta) do
      {:ok, meta}
    end
  end

  # The invariant that makes this provider's name true. Creating an existing key is a
  # silent no-op on OpenBao 2.6.2 — the `exportable: false` we send is ignored and the
  # existing metadata comes back — so the flag has to be READ, not assumed.
  defp refuse_exportable(name, meta) do
    case Map.get(meta, "exportable") do
      false -> :ok
      nil -> {:error, Transport.unavailable(__MODULE__, {:malformed_key_metadata, name})}
      _true -> {:error, Transport.unavailable(__MODULE__, {:exportable_key, name})}
    end
  end

  defp transit_ok(%{status: 200, body: body}), do: {:ok, Transport.data(body)}
  defp transit_ok(response), do: Transport.unavailable!(__MODULE__, response)

  defp path(suffix), do: Transport.transit_path(__MODULE__, suffix)

  defp key_type do
    Keyword.get(AshVault.KeyProvider.config(__MODULE__), :key_type) || @default_key_type
  end
end
