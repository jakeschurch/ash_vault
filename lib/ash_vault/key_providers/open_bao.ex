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
  > should have it.

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
    * `destroy/1` on a scope that never had a key still writes the tombstone and
      returns `:ok`.
    * `destroy/1` returns `:ok` only when the transit key is **confirmed absent** by a
      fresh read and the tombstone write succeeded. It never infers "there was nothing
      to delete" from an error message.
    * Scopes must be binaries. A non-binary scope raises `ArgumentError` rather than
      being encoded with `:erlang.term_to_binary/1`, whose output is not stable across
      OTP releases — an encoding change would relocate both the transit key name and
      the tombstone path, resurrecting the scope with a fresh key and making every
      existing ciphertext unreadable.
  """

  @behaviour AshVault.KeyProvider

  alias AshVault.Errors.ProviderUnavailable

  @default_address "http://127.0.0.1:8200"
  @default_transit_mount "transit"
  @default_kv_mount "ashvault"
  @default_key_type "aes256-gcm96"
  @default_receive_timeout 5_000
  @default_max_retries 2

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
  def key_name(scope) do
    "ashvault_" <> Base.url_encode64(validate_scope!(scope), padding: false)
  end

  @doc """
  Mount the KV-v2 engine that holds tombstones, if it is not already mounted.

  This is the **operator** setup step. It is deliberately the only place the mount is
  created: the tombstone read path treats a missing mount as
  `AshVault.Errors.ProviderUnavailable` and never provisions it, because an empty,
  freshly created tombstone store reports every erased scope as intact.
  """
  @spec setup() :: :ok | {:error, Exception.t()}
  def setup, do: ensure_kv_mount()

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
         {:ok, meta} <- read_meta(name) do
      case meta do
        :missing ->
          # No key yet: creating it mints version 1, which is the rotation.
          with {:ok, created} <- create_key(name), do: {:ok, created["latest_version"]}

        _ ->
          with {:ok, rotated} <- post(transit_path("/keys/#{name}/rotate")),
               {:ok, data} <- transit_ok(rotated) do
            {:ok, data["latest_version"]}
          end
      end
    end
  end

  @doc """
  Irreversibly destroy every key version for a scope and record a tombstone.

  Returns `:ok` only when both the transit delete and the tombstone write succeeded.
  """
  @impl AshVault.KeyProvider
  @spec destroy(AshVault.KeyProvider.scope()) :: :ok | {:error, term()}
  def destroy(scope) do
    name = key_name(scope)

    case check_tombstone(scope) do
      :absent ->
        with :ok <- delete_transit_key(name), do: write_tombstone(scope)

      {:error, :destroyed} ->
        :ok

      other ->
        other
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
  def classify_transit_key(200, body) do
    if is_map(body) and is_map(Map.get(body, "data")) do
      :present
    else
      {:unavailable, {:ambiguous_transit_response, 200}}
    end
  end

  def classify_transit_key(404, body) do
    cond do
      route_missing_body?(body) -> {:unavailable, :transit_mount_unavailable}
      is_map(body) and Map.has_key?(body, "errors") and Map.get(body, "errors") == [] -> :absent
      true -> {:unavailable, {:ambiguous_transit_response, 404}}
    end
  end

  def classify_transit_key(status, _body) when is_integer(status),
    do: {:unavailable, {:http_status, status}}

  # ── transit ────────────────────────────────────────────────────────────────────

  defp meta_or_create(name) do
    case read_meta(name) do
      {:ok, :missing} -> create_key(name)
      {:ok, meta} -> {:ok, meta}
      {:error, error} -> {:error, error}
    end
  end

  defp read_meta(name) do
    case get(transit_path("/keys/#{name}")) do
      {:ok, %{status: status, body: body}} ->
        case classify_transit_key(status, body) do
          :present -> {:ok, data(body)}
          :absent -> {:ok, :missing}
          {:unavailable, reason} -> {:error, unavailable(reason)}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp create_key(name) do
    body = %{
      type: key_type(),
      exportable: true,
      allow_plaintext_backup: false
    }

    with {:ok, response} <- post(transit_path("/keys/#{name}"), body) do
      transit_ok(response)
    end
  end

  # Erasure is decided by STATE, never by parsing an error message.
  #
  # The old code matched the bare substring "not found" on the *config* call — which is
  # issued before any delete — and on a match returned `:ok` without ever issuing the
  # delete. "not found" also appears in policy denials and proxy-surfaced 400s, so a
  # denied `deletion_allowed` config call reported a successful destroy while the key
  # stayed present and exportable, and `destroy/1` went on to write the tombstone.
  defp delete_transit_key(name) do
    case read_transit_key(name) do
      # Nothing to delete. `destroy/1` is still meaningful: the tombstone is what stops
      # `current_key/1` minting a fresh v1 for this scope later.
      {:ok, :absent} ->
        :ok

      {:ok, :present} ->
        with :ok <- allow_deletion(name),
             :ok <- issue_delete(name) do
          confirm_absent(name)
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp read_transit_key(name) do
    case get(transit_path("/keys/#{name}")) do
      {:ok, %{status: status, body: body}} ->
        case classify_transit_key(status, body) do
          {:unavailable, reason} -> {:error, unavailable(reason)}
          state -> {:ok, state}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp allow_deletion(name) do
    case post(transit_path("/keys/#{name}/config"), %{deletion_allowed: true}) do
      {:ok, %{status: 200}} -> :ok
      {:ok, response} -> unavailable!(response)
      {:error, error} -> {:error, error}
    end
  end

  defp issue_delete(name) do
    case request(:delete, transit_path("/keys/#{name}")) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, response} -> unavailable!(response)
      {:error, error} -> {:error, error}
    end
  end

  # The load-bearing check: the key must be positively gone before `destroy/1` will
  # write a tombstone and report success. An operator who closes a deletion ticket on
  # the strength of a `:ok` deserves the key to actually be gone.
  defp confirm_absent(name) do
    case read_transit_key(name) do
      {:ok, :absent} -> :ok
      {:ok, :present} -> {:error, unavailable({:transit_key_still_present, name})}
      {:error, error} -> {:error, error}
    end
  end

  defp export(name, version) do
    path = transit_path("/export/encryption-key/#{name}/#{version}")

    case get(path) do
      {:ok, %{status: 200, body: body}} ->
        body
        |> data()
        |> Map.get("keys", %{})
        |> Map.get(to_string(version))
        |> decode_key()

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      # A version above `latest_version`, or below `min_decryption_version`, is a 400
      # on this server, not a 404.
      {:ok, %{status: 400} = response} ->
        if unknown_version?(response), do: {:error, :not_found}, else: unavailable!(response)

      {:ok, response} ->
        unavailable!(response)

      {:error, error} ->
        {:error, error}
    end
  end

  defp decode_key(encoded) when is_binary(encoded) do
    case Base.decode64(encoded) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, unavailable(:malformed_key_material)}
    end
  end

  defp decode_key(_), do: {:error, :not_found}

  defp transit_ok(%{status: 200, body: body}), do: {:ok, data(body)}
  defp transit_ok(response), do: unavailable!(response)

  @doc """
  Extract a key version's creation time from transit key metadata.

  Returns `{:error, %AshVault.Errors.ProviderUnavailable{}}` rather than fabricating a
  timestamp. A key whose `created_at` is always `DateTime.utc_now()` is never older
  than a `max_age`, so every age-based `AshVault.RotationPolicy` silently never fires
  and nothing anywhere logs a reason. `AshVault.KeyProviders.Local` refuses the same
  fabrication (`decode_meta/2`) for the same reason.

  Public so the refusal can be tested against metadata shapes a live server will not
  produce on demand.
  """
  @doc since: "0.1.0"
  @spec created_at(map(), term()) :: {:ok, DateTime.t()} | {:error, Exception.t()}
  def created_at(meta, version) do
    meta
    |> key_entry(version)
    |> to_datetime()
    |> case do
      {:ok, datetime} -> {:ok, datetime}
      :error -> {:error, unavailable({:malformed_key_metadata, version})}
    end
  end

  defp key_entry(meta, version) when is_map(meta) do
    case Map.get(meta, "keys") do
      keys when is_map(keys) -> Map.get(keys, to_string(version))
      _ -> nil
    end
  end

  defp key_entry(_meta, _version), do: nil

  defp to_datetime(seconds) when is_integer(seconds) do
    case DateTime.from_unix(seconds) do
      {:ok, datetime} -> {:ok, datetime}
      {:error, _reason} -> :error
    end
  end

  defp to_datetime(%{"creation_time" => time}) when is_binary(time) do
    case DateTime.from_iso8601(time) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> :error
    end
  end

  defp to_datetime(_), do: :error

  # ── tombstones ─────────────────────────────────────────────────────────────────

  defp check_tombstone(scope) do
    case get(kv_path("/data/tombstones/#{key_name(scope)}")) do
      {:ok, %{status: status, body: body}} ->
        case classify_tombstone(status, body) do
          :destroyed -> {:error, :destroyed}
          :absent -> :absent
          {:unavailable, reason} -> {:error, unavailable(reason)}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Classify a raw tombstone-read response into `:destroyed`, `:absent` or
  `{:unavailable, reason}`.

  Public so the fail-closed rules can be tested directly against the exact bodies an
  OpenBao server, and an ingress in front of one, actually return. Every branch demands
  a **positive** identification of the body; a status code alone decides nothing.
  """
  @doc since: "0.1.0"
  @spec classify_tombstone(integer(), term()) :: :destroyed | :absent | {:unavailable, term()}
  def classify_tombstone(200, body) do
    # A proxy answering 200 with an HTML page at the tombstone path must not make every
    # scope in the system report `KeyDestroyed`. Fail-closed is not an excuse for
    # deciding erasure from a status code.
    if is_map(body) and is_map(Map.get(body, "data")) do
      :destroyed
    else
      {:unavailable, {:ambiguous_tombstone_response, 200}}
    end
  end

  def classify_tombstone(404, body) do
    cond do
      # A soft-deleted tombstone still carries its metadata (`data: {"data": null,
      # "metadata": {...}}`): it existed, so it counts as destroyed.
      is_map(body) and is_map(Map.get(body, "data")) ->
        :destroyed

      # A missing KV mount is status-identical to "no tombstone here". It is an
      # outage, never "not destroyed", and the mount is NEVER created here: a freshly
      # created, empty tombstone store reports every erased scope as intact.
      route_missing_body?(body) ->
        {:unavailable, :kv_mount_unavailable}

      # The one shape a genuinely absent KV-v2 secret returns, verified live against
      # openbao 2.6.2: `404 {"errors":[]}`. Anything else — an ingress HTML 404 during
      # a config reload, a gateway error page, a body that is not a map at all — is an
      # outage. `Map.has_key?/2` is load-bearing: a body with no "errors" key must not
      # be read as an empty error list.
      is_map(body) and Map.get(body, "errors") == [] and Map.has_key?(body, "errors") ->
        :absent

      true ->
        {:unavailable, {:ambiguous_tombstone_response, 404}}
    end
  end

  def classify_tombstone(status, _body) when is_integer(status),
    do: {:unavailable, {:http_status, status}}

  defp write_tombstone(scope, retried? \\ false) do
    body = %{data: %{destroyed_at: DateTime.to_iso8601(DateTime.utc_now())}}

    case post(kv_path("/data/tombstones/#{key_name(scope)}"), body) do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: 404} = response} ->
        if route_missing?(response) and not retried? do
          with :ok <- ensure_kv_mount(), do: write_tombstone(scope, true)
        else
          unavailable!(response)
        end

      {:ok, response} ->
        unavailable!(response)

      {:error, error} ->
        {:error, error}
    end
  end

  defp ensure_kv_mount do
    body = %{type: "kv", options: %{version: "2"}}

    case post("/v1/sys/mounts/#{kv_mount()}", body) do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: 400} = response} ->
        if already_mounted?(response), do: :ok, else: unavailable!(response)

      {:ok, response} ->
        unavailable!(response)

      {:error, error} ->
        {:error, error}
    end
  end

  # ── HTTP ───────────────────────────────────────────────────────────────────────

  defp get(path), do: request(:get, path)

  defp post(path, body \\ %{}), do: request(:post, path, body)

  defp request(method, path, body \\ nil) do
    with {:ok, token} <- token() do
      options =
        [
          method: method,
          base_url: address(),
          url: path,
          headers: [{"x-vault-token", token}],
          receive_timeout: receive_timeout(),
          retry: :transient,
          max_retries: max_retries()
        ]
        |> then(fn options -> if body, do: Keyword.put(options, :json, body), else: options end)

      perform(options)
    end
  end

  # `Req.request/1` returns `{:error, exception}` for a transport failure, but it also
  # *raises* (a bad `:base_url`, an unsupported scheme, a broken step) and can exit
  # (an out-of-range port). An exception escaping a Req step as a non-AshVault error
  # would be classified by callers as "some unknown failure" rather than a provider
  # outage — and, worse, such an exception can carry the whole `Req.Request`, whose
  # headers hold the token. Everything becomes `ProviderUnavailable`, carrying only the
  # kind and reason.
  defp perform(options) do
    case options |> Req.new() |> Req.request() do
      {:ok, response} -> {:ok, response}
      {:error, exception} -> {:error, unavailable(transport_reason(exception))}
    end
  rescue
    exception -> {:error, unavailable(transport_reason(exception))}
  catch
    :exit, _reason -> {:error, unavailable({:transport, :exit})}
    :throw, _value -> {:error, unavailable({:transport, :throw})}
  end

  # Only the exception's *kind* and reason travel into the error struct — never the
  # request, whose headers carry the token, and never the exception's message, which for
  # several Req/Finch errors interpolates the request.
  defp transport_reason(%Req.TransportError{reason: reason}), do: {:transport, reason}
  defp transport_reason(%{__struct__: module}), do: {:transport, module}
  defp transport_reason(_), do: :transport_error

  defp data(body) when is_map(body), do: Map.get(body, "data") || %{}
  defp data(_), do: %{}

  defp errors(%{body: body}) when is_map(body) do
    case Map.get(body, "errors") do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp errors(_), do: []

  defp error_message(response) do
    response |> errors() |> Enum.filter(&is_binary/1) |> Enum.join(" ")
  end

  defp route_missing?(response), do: error_message(response) =~ "no handler for route"

  defp route_missing_body?(body), do: route_missing?(%{body: body})

  defp already_mounted?(response), do: error_message(response) =~ "already in use"

  defp unknown_version?(response) do
    error_message(response) =~ ~r/version|no existing key|not found/i
  end

  defp unavailable!(response), do: {:error, unavailable(response)}

  defp unavailable(%Req.Response{status: status}), do: unavailable({:http_status, status})

  defp unavailable(%{status: status}) when is_integer(status),
    do: unavailable({:http_status, status})

  defp unavailable(reason) do
    ProviderUnavailable.exception(provider: __MODULE__, reason: normalise_reason(reason))
  end

  defp normalise_reason({:http_status, 403}), do: :forbidden
  defp normalise_reason(reason), do: reason

  # ── configuration ──────────────────────────────────────────────────────────────

  defp config, do: Application.get_env(:ash_vault, __MODULE__, [])

  defp address, do: Keyword.get(config(), :address) || @default_address

  defp transit_mount, do: Keyword.get(config(), :transit_mount) || @default_transit_mount

  defp kv_mount, do: Keyword.get(config(), :kv_mount) || @default_kv_mount

  defp key_type, do: Keyword.get(config(), :key_type) || @default_key_type

  defp receive_timeout, do: Keyword.get(config(), :receive_timeout) || @default_receive_timeout

  defp max_retries do
    case Keyword.get(config(), :max_retries) do
      retries when is_integer(retries) and retries >= 0 -> retries
      _ -> @default_max_retries
    end
  end

  defp transit_path(suffix), do: "/v1/#{transit_mount()}#{suffix}"

  defp kv_path(suffix), do: "/v1/#{kv_mount()}#{suffix}"

  # Resolves the token without ever placing it in a log line or an error struct.
  defp token do
    case Keyword.get(config(), :token) do
      token when is_binary(token) and token != "" -> {:ok, token}
      {:system, variable} when is_binary(variable) -> from_env(variable)
      fun when is_function(fun, 0) -> from_fun(fun)
      _ -> {:error, unavailable(:missing_token)}
    end
  end

  defp from_env(variable) do
    case System.get_env(variable) do
      token when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, unavailable(:missing_token)}
    end
  end

  defp from_fun(fun) do
    case fun.() do
      token when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, unavailable(:missing_token)}
    end
  end

  # Deliberately NOT `:erlang.term_to_binary/1`. The external term format is not
  # guaranteed stable across OTP releases, and it feeds BOTH the transit key name and
  # the tombstone path: an encoding change would relocate the tombstone (scope
  # resurrects with a fresh key) and the key name (every existing ciphertext becomes
  # `KeyNotFound`). CORE_SPEC §6 requires scope keys stable across releases.
  defp validate_scope!(scope) when is_binary(scope), do: scope

  defp validate_scope!(scope) do
    raise ArgumentError, """
    #{inspect(__MODULE__)} scopes must be binaries, got: #{inspect(scope)}.

    Scopes reach a key provider already normalised to a binary by the vault's
    `AshVault.Scope` implementation.
    """
  end
end
