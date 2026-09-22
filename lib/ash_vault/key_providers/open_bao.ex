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

  `:token` accepts a literal binary, `{:system, "VAR"}`, or a zero-arity function. The
  token is never logged, never placed in an error struct and never inspected.

  ## Tombstones

  Deleting a transit key makes its name simply *absent*: a naive `current_key/1` would
  happily create it again and mint a fresh version 1, silently resurrecting an erased
  scope. So `destroy/1` also writes a tombstone to a KV-v2 mount (mounted on demand),
  and `current_key/1`, `get_key/2` and `rotate/1` all check the tombstone **first**,
  before touching transit.

  The tombstone read fails *closed*: only a `404` that positively means "no such
  secret" is read as "not destroyed". A forbidden token, a server error, a transport
  failure, or a missing KV mount all raise `AshVault.Errors.ProviderUnavailable`
  rather than being mistaken for an intact scope. Equally, an outage is never reported
  as `{:error, :destroyed}`.

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
    * `destroy/1` returns `:ok` only when both the transit delete and the tombstone
      write succeeded.
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
    "ashvault_" <> Base.url_encode64(to_binary(scope), padding: false)
  end

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
         {:ok, key} <- export(name, version) do
      {:ok, %{version: version, key: key, created_at: created_at(meta, version)}}
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
      {:ok, %{status: 200, body: body}} -> {:ok, data(body)}
      {:ok, %{status: 404}} -> {:ok, :missing}
      {:ok, response} -> {:error, unavailable(response)}
      {:error, error} -> {:error, error}
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

  # `deletion_allowed` is ignored by the create endpoint, so it must be set here.
  # A 400 naming a missing key means there is nothing to delete, which is not an error.
  defp delete_transit_key(name) do
    case post(transit_path("/keys/#{name}/config"), %{deletion_allowed: true}) do
      {:ok, %{status: 200}} ->
        issue_delete(name)

      {:ok, %{status: 404}} ->
        :ok

      {:ok, %{status: 400} = response} ->
        if missing_key?(response), do: :ok, else: unavailable!(response)

      {:ok, response} ->
        unavailable!(response)

      {:error, error} ->
        {:error, error}
    end
  end

  defp issue_delete(name) do
    case request(:delete, transit_path("/keys/#{name}")) do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: 404}} ->
        :ok

      {:ok, %{status: 400} = response} ->
        if missing_key?(response), do: :ok, else: unavailable!(response)

      {:ok, response} ->
        unavailable!(response)

      {:error, error} ->
        {:error, error}
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

  defp created_at(meta, version) do
    meta
    |> Map.get("keys", %{})
    |> Map.get(to_string(version))
    |> to_datetime()
  end

  defp to_datetime(seconds) when is_integer(seconds), do: DateTime.from_unix!(seconds)

  defp to_datetime(%{"creation_time" => time}) when is_binary(time) do
    case DateTime.from_iso8601(time) do
      {:ok, datetime, _offset} -> datetime
      _ -> DateTime.utc_now()
    end
  end

  defp to_datetime(_), do: DateTime.utc_now()

  # ── tombstones ─────────────────────────────────────────────────────────────────

  # Fails closed: only a 404 that positively means "no such secret" reads as `:absent`.
  defp check_tombstone(scope, retried? \\ false) do
    case get(kv_path("/data/tombstones/#{key_name(scope)}")) do
      {:ok, %{status: 200}} ->
        {:error, :destroyed}

      {:ok, %{status: 404} = response} ->
        classify_missing_tombstone(scope, response, retried?)

      {:ok, response} ->
        {:error, unavailable(response)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp classify_missing_tombstone(scope, response, retried?) do
    cond do
      # A soft-deleted tombstone still carries its metadata: it existed, so it counts.
      is_map(response.body) and is_map(response.body["data"]) ->
        {:error, :destroyed}

      # The KV engine is not mounted. Mount it and look again rather than concluding
      # "not destroyed" from a missing mount.
      route_missing?(response) and not retried? ->
        with :ok <- ensure_kv_mount(), do: check_tombstone(scope, true)

      route_missing?(response) ->
        {:error, unavailable(:kv_mount_unavailable)}

      errors(response) == [] ->
        :absent

      true ->
        {:error, unavailable(response)}
    end
  end

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

      case options |> Req.new() |> Req.request() do
        {:ok, response} -> {:ok, response}
        {:error, exception} -> {:error, unavailable(transport_reason(exception))}
      end
    end
  end

  # Only the exception's *kind* and reason travel into the error struct — never the
  # request, whose headers carry the token.
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

  defp already_mounted?(response), do: error_message(response) =~ "already in use"

  defp missing_key?(response) do
    error_message(response) =~ ~r/no existing key|not found|unknown key/i
  end

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

  defp to_binary(scope) when is_binary(scope), do: scope
  defp to_binary(scope), do: :erlang.term_to_binary(scope)
end
