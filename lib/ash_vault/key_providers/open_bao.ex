defmodule AshVault.KeyProviders.OpenBao do
  @moduledoc """
  An `AshVault.KeyProvider` backed by [OpenBao](https://openbao.org) (or Vault) `transit`.

  ## How it works

  Each scope gets one **exportable transit key**, and that key *is* the scope's key
  material. Transit key versions map 1:1 onto AshVault key versions:

    * `current_key/1` reads the transit key's metadata, creating the key (version 1) on
      first use, and exports the latest version's raw bytes.
    * `get_key/2` exports one specific version.
    * `rotate/1` bumps `latest_version`; every previous version stays exportable.
    * `destroy/1` deletes the transit key — which destroys every version at once — and
      writes a tombstone to a KV-v2 mount.

  No key material is ever written to the application database, so a PostgreSQL backup
  contains no keys and restoring one cannot undo a crypto-erasure.

  > #### `exportable: true` {: .warning}
  >
  > Anything holding a `transit/export` capability on these keys can read raw key
  > material. The AshVault application needs exactly that capability; nothing else
  > should have it. The exported key is also a refcounted binary on a process heap for
  > the life of the call and beyond, which the BEAM will not zero.
  >
  > `AshVault.KeyProviders.OpenBaoTransit` is the sibling provider that never exports:
  > it runs the AEAD inside OpenBao instead, at the cost of one network round trip per
  > value and no support for searchable fields. See
  > [Threat model](threat-model.md) for which to choose.

  ## Configuration

      config :ash_vault, AshVault.KeyProviders.OpenBao,
        address: "http://127.0.0.1:8200",
        token: {:system, "BAO_TOKEN"},
        transit_mount: "transit",
        kv_mount: "ashvault",
        key_type: "aes256-gcm96",
        receive_timeout: 5_000,
        max_retries: 2

  `:token` accepts a literal binary, `{:system, "VAR"}`, or a zero-arity function.

  > #### What the token guarantee actually is {: .warning}
  >
  > AshVault never logs the token, never puts it in an error struct, and never puts it
  > in an exception message — the transport failures it reports carry only the
  > exception *kind* and reason, never the request.
  >
  > It cannot promise more than that. The token is sent as the `x-vault-token` header,
  > so the raw value necessarily sits in the `Req.Request` and `Finch.Request` structs
  > for the life of the call. `Req`'s own `Inspect` implementation redacts only
  > `authorization`, and Finch's `[:finch, :request, :start | :stop | :exception]`
  > telemetry metadata carries the request headers verbatim — which APM handlers
  > routinely record. If you attach handlers to those events, filter `x-vault-token`
  > out of the metadata yourself. Nothing inside this module can do it for you.

  ## Tombstones

  Deleting a transit key makes its name simply *absent*: a naive `current_key/1` would
  happily create it again and mint a fresh version 1, silently resurrecting an erased
  scope. So `destroy/1` also writes a tombstone to a KV-v2 mount, and `current_key/1`,
  `get_key/2` and `rotate/1` all check the tombstone **first**, before touching transit.

  The tombstone read fails *closed*, and every branch demands a **positive**
  identification of the body, not just a status code:

    * `200` counts as destroyed only when the body is a map with a map at `"data"`.
      A proxy or ingress answering `200` with an HTML page at the tombstone path does
      not make every scope report `KeyDestroyed`.
    * `404` counts as absent only when the body is a map with an `"errors"` key whose
      list is empty — the shape a genuinely absent KV-v2 secret returns. An HTML 404
      from an ingress mid-reload, or a gateway error page, is
      `AshVault.Errors.ProviderUnavailable`, not "not destroyed".
    * A `404` carrying `"data"` is a *soft-deleted* tombstone: it existed, so it counts
      as destroyed.

  > #### The KV mount is never created on a read {: .error}
  >
  > A missing KV mount answers `404 "no handler for route ..."` — status-identical to
  > "no tombstone here". This provider reports that as `ProviderUnavailable` and stops.
  > It does **not** mount the engine and retry: auto-provisioning the store that holds
  > your tombstones is fail-open by construction, because the freshly created mount is
  > empty and every destroyed scope then reads as intact. Mount the KV engine once, as
  > an operator, with `setup/0` or:
  >
  >     bao secrets enable -path=ashvault -version=2 kv
  >
  > (`destroy/1`'s tombstone *write* still mounts on demand and retries once: creating
  > the store in order to record an erasure cannot lose an erasure.)

  An outage is never reported as `{:error, :destroyed}`, and erasure is never reported
  as an outage.

  ## Transit key names

  Transit key names are restricted to `[a-zA-Z0-9_.-]`, so a scope is encoded:

      "ashvault_" <> Base.url_encode64(scope, padding: false)

  The mapping is total, and injective over the binary scopes `AshVault.Scope`
  produces. Use `key_name/1` to map a tenant to the transit key name an operator must
  look for.

  Tombstone paths use the same encoding, so a scope containing `/` cannot reshape the
  KV hierarchy.

  ## Semantics worth knowing

    * `rotate/1` on a scope that has no key yet mints version 1 and returns `{:ok, 1}`,
      matching `AshVault.KeyProviders.Memory`.
    * `destroy/1` writes the tombstone **before** deleting either transit key. A crash or
      outage during deletion therefore fails closed: later writes cannot mint a fresh v1
      for ciphertext whose original key is already gone.
    * `destroy/1` on a scope that never had a key still writes the tombstone and returns
      `:ok`.
    * `destroy/1` returns `:ok` only when both transit keys are **confirmed absent** by
      fresh reads. A repeated call retries cleanup when a previous destroy wrote the
      tombstone but was interrupted before every key was gone.
    * Scopes must be binaries. A non-binary scope raises `ArgumentError` rather than
      being encoded with `:erlang.term_to_binary/1`, whose output is not stable across
      OTP releases — an encoding change would relocate both the transit key name and
      the tombstone path, resurrecting the scope with a fresh key and making every
      existing ciphertext unreadable.
  """

  @behaviour AshVault.KeyProvider

  alias AshVault.KeyProviders.OpenBao.Transport

  @default_key_type "aes256-gcm96"

  @key_bytes %{
    "aes128-gcm96" => 16,
    "aes256-gcm96" => 32,
    "chacha20-poly1305" => 32
  }
  @default_key_bytes 32

  @doc """
  The transit key name a scope maps to.

  Provided so operators can find a tenant's key material in OpenBao:

      iex> AshVault.KeyProviders.OpenBao.key_name("tenant_42")
      "ashvault_dGVuYW50XzQy"
  """
  @spec key_name(AshVault.KeyProvider.scope()) :: String.t()
  def key_name(scope), do: Transport.key_name(__MODULE__, "ashvault_", scope)

  @doc """
  Mount the KV-v2 engine that holds tombstones, if it is not already mounted.

  This is the **operator** setup step. It is deliberately the only place the mount is
  created: the tombstone read path treats a missing mount as
  `AshVault.Errors.ProviderUnavailable` and never provisions it, because an empty,
  freshly created tombstone store reports every erased scope as intact.
  """
  @impl AshVault.KeyProvider
  @spec setup() :: :ok | {:error, Exception.t()}
  def setup, do: Transport.ensure_kv_mount(__MODULE__)

  @doc """
  The key size in bytes this provider mints, derived from the configured `:key_type`.
  """
  @impl AshVault.KeyProvider
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: Map.get(@key_bytes, key_type(), @default_key_bytes)

  @doc """
  Fetch the current key for a scope, creating the transit key (version 1) on first use.
  """
  @impl AshVault.KeyProvider
  @spec current_key(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.key_info()} | {:error, term()}
  def current_key(scope) do
    name = key_name(scope)

    with :absent <- check_tombstone(scope),
         {:ok, meta} <- meta_or_create(name),
         version = meta["latest_version"],
         {:ok, created_at} <- created_at(meta, version),
         {:ok, key} <- export(name, version) do
      {:ok, %{version: version, key: key, created_at: created_at}}
    end
  end

  @doc """
  Fetch one historical key version for a scope.
  """
  @impl AshVault.KeyProvider
  @spec get_key(AshVault.KeyProvider.scope(), AshVault.KeyProvider.version()) ::
          {:ok, binary()} | {:error, :not_found} | {:error, :destroyed} | {:error, term()}
  def get_key(scope, version) do
    with :absent <- check_tombstone(scope) do
      if is_integer(version) and version > 0 do
        export(key_name(scope), version)
      else
        {:error, :not_found}
      end
    end
  end

  @doc """
  Mint the next key version for a scope, keeping every previous version exportable.
  """
  @impl AshVault.KeyProvider
  @spec rotate(AshVault.KeyProvider.scope()) ::
          {:ok, AshVault.KeyProvider.version()} | {:error, term()}
  def rotate(scope) do
    name = key_name(scope)

    with :absent <- check_tombstone(scope),
         {:ok, meta} <- Transport.read_meta(__MODULE__, name) do
      case meta do
        :missing ->
          # No key yet: creating it mints version 1, which is the rotation.
          with {:ok, created} <- create_key(name), do: {:ok, created["latest_version"]}

        _ ->
          with {:ok, rotated} <- Transport.post(__MODULE__, path("/keys/#{name}/rotate")),
               {:ok, data} <- transit_ok(rotated) do
            {:ok, data["latest_version"]}
          end
      end
    end
  end

  @doc """
  Fetch the scope's stable lookup key from its own, separate transit key.

  The lookup key lives at `<key_name>_lookup` — a second exportable transit key that is
  **never rotated**, so version 1 is always the version exported. `destroy/1` deletes it
  alongside the data key, and the same tombstone gates it.

  `rotate/1` deliberately does not touch it. See `c:AshVault.KeyProvider.lookup_key/1`
  for what rotating it would silently break.
  """
  @impl AshVault.KeyProvider
  @spec lookup_key(AshVault.KeyProvider.scope()) :: {:ok, binary()} | {:error, term()}
  def lookup_key(scope) do
    name = lookup_key_name(scope)

    with :absent <- check_tombstone(scope),
         {:ok, _meta} <- meta_or_create(name) do
      export(name, 1)
    end
  end

  @doc """
  The transit key name holding a scope's lookup key.

      iex> AshVault.KeyProviders.OpenBao.lookup_key_name("tenant_42")
      "ashvault_dGVuYW50XzQy_lookup"

  ## Why the `_lookup` suffix cannot collide with a data key

  This namespace is safety-critical, not cosmetic. If some scope `s1` existed with
  `key_name(s1) == lookup_key_name(s2)`, then one tenant's **lookup key would be another
  tenant's data key** — and the lookup key is deliberately never rotated, so `s1` would
  silently be pinned to a key `rotate/1` cannot move, while anyone holding `s2`'s lookup
  key could decrypt `s1`'s data.

  Both names share the `"ashvault_"` prefix, so a collision requires
  `enc(s1) == enc(s2) <> "_lookup"` where `enc/1` is `Base.url_encode64/2` with
  `padding: false`. That is impossible, and the reason is worth stating rather than
  trusting:

  Every character of `"_lookup"` is in the base64url alphabet, so the suffix does not
  disqualify itself. The proof rests entirely on its **last** character, `?p`, whose
  base64url index is 41 (`0b101001`), and on the two canonicity rules unpadded base64
  imposes on a final character. Writing `n` for `byte_size(enc(s2))`, every `enc/1`
  output has length `≡ 0, 2 or 3 (mod 4)` — never 1 — and `enc(s1)` would have length
  `n + 7`:

    * `n ≡ 2` → `n + 7 ≡ 1 (mod 4)`, which is not a legal unpadded base64 length at all.
    * `n ≡ 0` → `n + 7 ≡ 3 (mod 4)`. A 3-character final group encodes 2 bytes, so its
      third character carries only 4 data bits: its low **2** bits must be zero.
      `41 &&& 3 == 1`.
    * `n ≡ 3` → `n + 7 ≡ 2 (mod 4)`. A 2-character final group encodes 1 byte, so its
      second character carries only 2 data bits: its low **4** bits must be zero.
      `41 &&& 15 == 9`.

  In both surviving cases `?p` is not a character a canonical encoder can emit in that
  position, so no scope produces a `key_name/1` ending in `"_lookup"`.

  The remaining residue, `n + 7 ≡ 0 (mod 4)`, needs `n ≡ 1`, and 1 is the one length an
  unpadded base64 string can never have. That case is worth naming, because it is the
  only place the property is *not* about `?p` at all: canonical encodings ending in
  `"_lookup"` genuinely exist at length 8 — `"A_lookup"` is one, the encoding of
  `<<3, 249, 104, 162, 75, 169>>` — and all 64 of them are excluded solely because they
  would require an `enc(s2)` of length 1. Both halves of the argument are load-bearing.

  The property is therefore real but **fragile**: it depends on the alphabet, on
  `padding: false`, and on the exact suffix. Changing any of the three — hex instead of
  base64url, padding back on, a suffix ending in a character whose low bits are zero
  (`"_lookupA"`, say) — can reintroduce the collision. `AshVault.KeyProviders.OpenBaoKeyNameTest`
  asserts it directly so a change to any of them fails loudly.
  """
  @spec lookup_key_name(AshVault.KeyProvider.scope()) :: String.t()
  def lookup_key_name(scope), do: key_name(scope) <> "_lookup"

  @doc """
  Tombstone a scope, then irreversibly destroy every key version for it.

  The tombstone is committed first: losing the data key before persisting its tombstone
  would let a later `current_key/1` mint a fresh v1 and silently strand every existing
  ciphertext. Presence always gates reads and writes, even if a later transit deletion
  fails. Repeating `destroy/1` resumes that cleanup and returns `:ok` only after both
  transit keys are confirmed absent.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope) do
    name = key_name(scope)

    with :ok <- ensure_tombstone(scope),
         :ok <- Transport.delete_transit_key(__MODULE__, name),
         # Erasure must be total. A surviving lookup key would let anyone holding it
         # keep confirming guesses about a subject whose data was "destroyed".
         :ok <- Transport.delete_transit_key(__MODULE__, lookup_key_name(scope)) do
      :ok
    end
  end

  # Presence is the access-control decision, but not proof that cleanup completed: a
  # prior destroy may have written the tombstone and then lost connectivity while deleting
  # a transit key. Retrying deletion here makes `destroy/1` both safe to interrupt and
  # honestly idempotent.
  defp ensure_tombstone(scope) do
    case check_tombstone(scope) do
      :absent -> Transport.write_tombstone(__MODULE__, key_name(scope))
      {:error, :destroyed} -> :ok
      other -> other
    end
  end

  @doc """
  Classify a raw transit key metadata read into `:present`, `:absent` or
  `{:unavailable, reason}`.

  Public for the same reason as `classify_tombstone/2`: this is the state check that
  `destroy/1` requires before it will write a tombstone and report success.
  """
  @doc since: "0.1.0"
  @spec classify_transit_key(integer(), term()) :: :present | :absent | {:unavailable, term()}
  defdelegate classify_transit_key(status, body), to: Transport

  @doc """
  Classify a raw tombstone-read response into `:destroyed`, `:absent` or
  `{:unavailable, reason}`.

  Public so the fail-closed rules can be tested directly against the exact bodies an
  OpenBao server, and an ingress in front of one, actually return. Every branch demands
  a **positive** identification of the body; a status code alone decides nothing.
  """
  @doc since: "0.1.0"
  @spec classify_tombstone(integer(), term()) :: :destroyed | :absent | {:unavailable, term()}
  defdelegate classify_tombstone(status, body), to: Transport

  @doc """
  Whether the HTTP transport this provider needs is actually running.

  See `AshVault.KeyProviders.OpenBao.Transport.transport_status/0` — a missing `:req`
  or `:finch` application is a dependency mistake, not an OpenBao outage, and the two
  must never be reported identically.
  """
  @doc since: "0.1.0"
  @spec transport_status() :: :ready | {:not_started, :req | :finch}
  defdelegate transport_status(), to: Transport

  @doc """
  Extract a key version's creation time from transit key metadata.

  Returns `{:error, %AshVault.Errors.ProviderUnavailable{}}` rather than fabricating a
  timestamp. A key whose `created_at` is always `DateTime.utc_now()` is never older
  than a `max_age`, so every age-based `AshVault.RotationPolicy` silently never fires
  and nothing anywhere logs a reason.

  Public so the refusal can be tested against metadata shapes a live server will not
  produce on demand.
  """
  @doc since: "0.1.0"
  @spec created_at(map(), term()) :: {:ok, DateTime.t()} | {:error, Exception.t()}
  def created_at(meta, version), do: Transport.created_at(__MODULE__, meta, version)

  # ── transit ────────────────────────────────────────────────────────────────────

  defp check_tombstone(scope), do: Transport.check_tombstone(__MODULE__, key_name(scope))

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
      exportable: true,
      allow_plaintext_backup: false
    }

    with {:ok, response} <- Transport.post(__MODULE__, path("/keys/#{name}"), body) do
      transit_ok(response)
    end
  end

  defp export(name, version) do
    case Transport.get(__MODULE__, path("/export/encryption-key/#{name}/#{version}")) do
      {:ok, %{status: 200, body: body}} ->
        body
        |> Transport.data()
        |> Map.get("keys", %{})
        |> Map.get(to_string(version))
        |> decode_key()

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      # A version above `latest_version`, or below `min_decryption_version`, is a 400
      # on this server, not a 404.
      {:ok, %{status: 400} = response} ->
        if unknown_version?(response),
          do: {:error, :not_found},
          else: Transport.unavailable!(__MODULE__, response)

      {:ok, response} ->
        Transport.unavailable!(__MODULE__, response)

      {:error, error} ->
        {:error, error}
    end
  end

  defp decode_key(encoded) when is_binary(encoded) do
    case Base.decode64(encoded) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, Transport.unavailable(__MODULE__, :malformed_key_material)}
    end
  end

  defp decode_key(_), do: {:error, :not_found}

  defp transit_ok(%{status: 200, body: body}), do: {:ok, Transport.data(body)}
  defp transit_ok(response), do: Transport.unavailable!(__MODULE__, response)

  defp unknown_version?(response) do
    Transport.error_message(response) =~ ~r/version|no existing key|not found/i
  end

  defp path(suffix), do: Transport.transit_path(__MODULE__, suffix)

  defp key_type,
    do: Keyword.get(AshVault.KeyProvider.config(__MODULE__), :key_type) || @default_key_type
end
