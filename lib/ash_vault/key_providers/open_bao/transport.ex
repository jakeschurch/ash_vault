defmodule AshVault.KeyProviders.OpenBao.Transport do
  @moduledoc """
  The HTTP, configuration, tombstone and error-classification layer shared by the two
  OpenBao-backed key providers.

  `AshVault.KeyProviders.OpenBao` (which exports raw key material) and
  `AshVault.KeyProviders.OpenBaoTransit` (which never does) differ only in what they do
  with a transit key once they have one. Everything underneath — resolving a token
  without ever logging it, turning a raised `Req` step into
  `AshVault.Errors.ProviderUnavailable`, deciding whether a `404` at a tombstone path
  means "not destroyed" or "your KV mount is gone" — is identical, and is therefore
  written once, here.

  Every function takes the **calling provider module** as its first argument. That
  module is both the configuration key (`AshVault.KeyProvider.config/1`) and the
  `:provider` recorded on every `AshVault.Errors.ProviderUnavailable`, so an operator
  reading an error is told which provider failed, not that "the transport" did.

  This module is public because its classification rules are security controls that are
  tested directly against the exact bodies a live server returns. It is not a stable
  API for anything outside AshVault.
  """

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao.KubernetesAuth

  @default_address "http://127.0.0.1:8200"
  @default_transit_mount "transit"
  @default_kv_mount "ashvault"
  @default_receive_timeout 5_000
  @default_max_retries 2

  # ── scope encoding ─────────────────────────────────────────────────────────────

  @doc """
  The transit key name a scope maps to, under `prefix`.

  Transit key names are restricted to `[a-zA-Z0-9_.-]`, so the scope is base64url
  encoded. The encoding is total and **injective** — the padding-free alphabet is used
  verbatim, because rewriting `-` to `_` (as an earlier spec said) collapses
  `Base.url_encode64("ab>") == "YWI-"` and `Base.url_encode64("ab?") == "YWI_"` onto one
  name, which would let destroying one tenant crypto-erase another.

  Tombstone paths use the same name, so a scope containing `/` cannot reshape the KV
  hierarchy.
  """
  @spec key_name(module(), String.t(), AshVault.KeyProvider.scope()) :: String.t()
  def key_name(provider, prefix, scope) do
    prefix <> Base.url_encode64(validate_scope!(provider, scope), padding: false)
  end

  @doc """
  Assert that a scope is a binary, raising `ArgumentError` naming `provider` if not.

  Deliberately **not** `:erlang.term_to_binary/1`. The external term format is not
  guaranteed stable across OTP releases, and it feeds BOTH the transit key name and the
  tombstone path: an encoding change would relocate the tombstone (the scope resurrects
  with a fresh key) and the key name (every existing ciphertext becomes
  `AshVault.Errors.KeyNotFound`). CORE_SPEC §6 requires scope keys stable across
  releases.
  """
  @spec validate_scope!(module(), AshVault.KeyProvider.scope()) :: binary()
  def validate_scope!(_provider, scope) when is_binary(scope), do: scope

  def validate_scope!(provider, scope) do
    raise ArgumentError, """
    #{inspect(provider)} scopes must be binaries, got: #{inspect(scope)}.

    Scopes reach a key provider already normalised to a binary by the vault's
    `AshVault.Scope` implementation.
    """
  end

  # ── transit metadata ───────────────────────────────────────────────────────────

  @doc """
  Classify a raw transit key metadata read into `:present`, `:absent` or
  `{:unavailable, reason}`.

  Public because this is the state check `destroy/1` requires before it will write a
  tombstone and report success, and because a status code alone decides nothing here.
  """
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

  @doc """
  Read a transit key's metadata, or `{:ok, :missing}` when it does not exist.
  """
  @spec read_meta(module(), String.t()) :: {:ok, map() | :missing} | {:error, Exception.t()}
  def read_meta(provider, name) do
    case get(provider, transit_path(provider, "/keys/#{name}")) do
      {:ok, %{status: status, body: body}} ->
        case classify_transit_key(status, body) do
          :present -> {:ok, data(body)}
          :absent -> {:ok, :missing}
          {:unavailable, reason} -> {:error, unavailable(provider, reason)}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Read a transit key's presence only: `{:ok, :present}` or `{:ok, :absent}`.
  """
  @spec read_transit_key(module(), String.t()) ::
          {:ok, :present | :absent} | {:error, Exception.t()}
  def read_transit_key(provider, name) do
    case read_meta(provider, name) do
      {:ok, :missing} -> {:ok, :absent}
      {:ok, _meta} -> {:ok, :present}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Delete a transit key, returning `:ok` only once it is **confirmed absent** by a fresh
  read.

  An operator who closes a deletion ticket on the strength of an `:ok` deserves the key
  to actually be gone. Erasure is decided by state, never by parsing an error message:
  `"not found"` also appears in policy denials, and a denied `deletion_allowed` call
  once reported a successful destroy while the key stayed present and exportable.
  """
  @spec delete_transit_key(module(), String.t()) :: :ok | {:error, Exception.t()}
  def delete_transit_key(provider, name) do
    case read_transit_key(provider, name) do
      # Nothing to delete. `destroy/1` is still meaningful: the tombstone is what stops
      # `current_key/1` minting a fresh v1 for this scope later.
      {:ok, :absent} ->
        :ok

      {:ok, :present} ->
        with :ok <- allow_deletion(provider, name),
             :ok <- issue_delete(provider, name) do
          confirm_absent(provider, name)
        end

      {:error, error} ->
        {:error, error}
    end
  end

  defp allow_deletion(provider, name) do
    case post(provider, transit_path(provider, "/keys/#{name}/config"), %{deletion_allowed: true}) do
      {:ok, %{status: 200}} -> :ok
      {:ok, response} -> unavailable!(provider, response)
      {:error, error} -> {:error, error}
    end
  end

  defp issue_delete(provider, name) do
    case request(provider, :delete, transit_path(provider, "/keys/#{name}")) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, response} -> unavailable!(provider, response)
      {:error, error} -> {:error, error}
    end
  end

  defp confirm_absent(provider, name) do
    case read_transit_key(provider, name) do
      {:ok, :absent} -> :ok
      {:ok, :present} -> {:error, unavailable(provider, {:transit_key_still_present, name})}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Extract a key version's creation time from transit key metadata.

  Returns `{:error, %AshVault.Errors.ProviderUnavailable{}}` rather than fabricating a
  timestamp. A key whose `created_at` is always `DateTime.utc_now()` is never older than
  a `max_age`, so every age-based `AshVault.RotationPolicy` silently never fires and
  nothing anywhere logs a reason.
  """
  @spec created_at(module(), map(), term()) :: {:ok, DateTime.t()} | {:error, Exception.t()}
  def created_at(provider, meta, version) do
    meta
    |> key_entry(version)
    |> to_datetime()
    |> case do
      {:ok, datetime} -> {:ok, datetime}
      :error -> {:error, unavailable(provider, {:malformed_key_metadata, version})}
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

  @doc """
  Read a scope's tombstone, fail-closed.

  Returns `:absent`, `{:error, :destroyed}`, or
  `{:error, %AshVault.Errors.ProviderUnavailable{}}`. An outage is never reported as
  erasure, and erasure is never reported as an outage.
  """
  @spec check_tombstone(module(), String.t()) :: :absent | {:error, term()}
  def check_tombstone(provider, name) do
    case get(provider, kv_path(provider, "/data/tombstones/#{name}")) do
      {:ok, %{status: status, body: body}} ->
        case classify_tombstone(status, body) do
          :destroyed -> {:error, :destroyed}
          :absent -> :absent
          {:unavailable, reason} -> {:error, unavailable(provider, reason)}
        end

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Classify a raw tombstone-read response into `:destroyed`, `:absent` or
  `{:unavailable, reason}`.

  Every branch demands a **positive** identification of the body; a status code alone
  decides nothing.
  """
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
      # openbao 2.6.2: `404 {"errors":[]}`. `Map.has_key?/2` is load-bearing: a body
      # with no "errors" key must not be read as an empty error list.
      is_map(body) and Map.get(body, "errors") == [] and Map.has_key?(body, "errors") ->
        :absent

      true ->
        {:unavailable, {:ambiguous_tombstone_response, 404}}
    end
  end

  def classify_tombstone(status, _body) when is_integer(status),
    do: {:unavailable, {:http_status, status}}

  @doc """
  Write a scope's tombstone, mounting the KV engine on demand and retrying once.

  Creating the store in order to record an erasure cannot lose an erasure, which is why
  the **write** path may mount and the read path never may.
  """
  @spec write_tombstone(module(), String.t(), boolean()) :: :ok | {:error, Exception.t()}
  def write_tombstone(provider, name, retried? \\ false) do
    body = %{data: %{destroyed_at: DateTime.to_iso8601(DateTime.utc_now())}}

    case post(provider, kv_path(provider, "/data/tombstones/#{name}"), body) do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: 404} = response} ->
        if route_missing?(response) and not retried? do
          with :ok <- ensure_kv_mount(provider), do: write_tombstone(provider, name, true)
        else
          unavailable!(provider, response)
        end

      {:ok, response} ->
        unavailable!(provider, response)

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Mount the KV-v2 engine that holds tombstones, if it is not already mounted.

  `POST /v1/sys/mounts/<path>` is **not** idempotent — an existing mount is
  `400 "path is already in use"` — so idempotency is synthesised here.
  """
  @spec ensure_kv_mount(module()) :: :ok | {:error, Exception.t()}
  def ensure_kv_mount(provider) do
    body = %{type: "kv", options: %{version: "2"}}

    case post(provider, "/v1/sys/mounts/#{kv_mount(provider)}", body) do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: 400} = response} ->
        if already_mounted?(response), do: :ok, else: unavailable!(provider, response)

      {:ok, response} ->
        unavailable!(provider, response)

      {:error, error} ->
        {:error, error}
    end
  end

  # ── HTTP ───────────────────────────────────────────────────────────────────────

  @doc "Issue a GET against the configured OpenBao address."
  @spec get(module(), String.t()) :: {:ok, term()} | {:error, Exception.t()}
  def get(provider, path), do: request(provider, :get, path)

  @doc "Issue a POST against the configured OpenBao address."
  @spec post(module(), String.t(), map()) :: {:ok, term()} | {:error, Exception.t()}
  def post(provider, path, body \\ %{}), do: request(provider, :post, path, body)

  @doc """
  Issue an arbitrary request, turning every failure mode into
  `AshVault.Errors.ProviderUnavailable`.
  """
  @spec request(module(), atom(), String.t(), map() | nil) ::
          {:ok, term()} | {:error, Exception.t()}
  def request(provider, method, path, body \\ nil) do
    with {:ok, token} <- token(provider),
         {:ok, base} <- base_options(provider) do
      options =
        Keyword.merge(base,
          method: method,
          url: path,
          headers: [{"x-vault-token", token}],
          retry: :transient,
          max_retries: max_retries(provider)
        )
        |> then(fn options -> if body, do: Keyword.put(options, :json, body), else: options end)

      perform(provider, options)
    end
  end

  @doc """
  The token-free `Req` options every request to `provider` shares: address, timeout and
  TLS.

  `:cacertfile` becomes `connect_options: [transport_opts: [cacertfile: path, verify:
  :verify_peer]]`, merged over any `:connect_options` given. Mint keeps its own hostname
  check and server name indication on top. `verify: :verify_none` is refused outright.

  A `:cacertfile` that is not a readable regular file is
  `{:error, %ProviderUnavailable{reason: {:cacertfile_unreadable, path}}}`, checked
  before any connection: otherwise Mint's own read raises inside the request and the
  failure is indistinguishable from a network outage.
  """
  @spec base_options(module()) :: {:ok, keyword()} | {:error, Exception.t()}
  def base_options(provider) do
    config = config(provider)

    with {:ok, connect_options} <- connect_options(provider, config) do
      options =
        Keyword.get(config, :req_options, [])
        |> Keyword.merge(base_url: address(provider), receive_timeout: receive_timeout(provider))
        |> then(fn options ->
          if connect_options == [],
            do: options,
            else: Keyword.put(options, :connect_options, connect_options)
        end)

      {:ok, options}
    end
  end

  defp connect_options(provider, config) do
    connect_options = Keyword.get(config, :connect_options, [])
    transport_opts = Keyword.get(connect_options, :transport_opts, [])

    if Keyword.get(transport_opts, :verify) == :verify_none do
      raise ArgumentError, """
      #{inspect(provider)} refuses connect_options transport_opts verify: :verify_none.

      Point :cacertfile at the CA that signed the OpenBao server certificate instead.
      """
    end

    case Keyword.get(config, :cacertfile) do
      nil ->
        {:ok, connect_options}

      path when is_binary(path) ->
        if File.regular?(path) do
          transport_opts = Keyword.merge(transport_opts, cacertfile: path, verify: :verify_peer)
          {:ok, Keyword.put(connect_options, :transport_opts, transport_opts)}
        else
          {:error, unavailable(provider, {:cacertfile_unreadable, path})}
        end

      other ->
        raise ArgumentError,
              "#{inspect(provider)} :cacertfile must be a path string, got: #{inspect(other)}"
    end
  end

  # ── Kubernetes auth ────────────────────────────────────────────────────────────

  @doc """
  The validated `auth: {:kubernetes, opts}` options for `provider`.

  Raises `ArgumentError` if `provider` is not configured for Kubernetes auth.
  """
  @spec kubernetes_options!(module()) :: AshVault.KeyProviders.OpenBao.KubernetesAuth.options()
  def kubernetes_options!(provider) do
    case Keyword.get(config(provider), :auth) do
      {:kubernetes, opts} -> KubernetesAuth.options!(provider, opts)
      _ -> raise ArgumentError, "#{inspect(provider)} is not configured for Kubernetes auth"
    end
  end

  @doc """
  Log in with the Kubernetes auth method: read the service-account JWT, `POST` it to
  `/v1/auth/<mount>/login`, and return `{:ok, client_token, lease_seconds}`.

  Sends no `x-vault-token` header and does not retry: the token holder owns backoff.
  Every failure is `ProviderUnavailable` with reason `{:kubernetes_auth, reason}`; the
  response body, which carries the token, never reaches the error.
  """
  @spec kubernetes_login(module(), AshVault.KeyProviders.OpenBao.KubernetesAuth.options()) ::
          {:ok, String.t(), non_neg_integer()} | {:error, Exception.t()}
  def kubernetes_login(provider, options) do
    with {:ok, jwt} <- read_jwt(provider, options.jwt_path),
         {:ok, base} <- base_options(provider) do
      request =
        Keyword.merge(base,
          method: :post,
          url: "/v1/auth/#{options.mount}/login",
          json: %{role: options.role, jwt: jwt},
          retry: false
        )

      case perform(provider, request) do
        {:ok, %{status: 200, body: body}} ->
          login_result(provider, body)

        {:ok, %{status: status}} ->
          {:error, kubernetes_error(provider, {:http_status, status})}

        {:error, %ProviderUnavailable{reason: {:not_started, _app}} = error} ->
          {:error, error}

        {:error, %ProviderUnavailable{reason: reason}} ->
          {:error, kubernetes_error(provider, reason)}
      end
    end
  end

  defp read_jwt(provider, path) do
    case File.read(path) do
      {:ok, contents} ->
        case String.trim(contents) do
          "" -> {:error, kubernetes_error(provider, {:jwt_empty, path})}
          jwt -> {:ok, jwt}
        end

      {:error, posix} ->
        {:error, kubernetes_error(provider, {:jwt_unreadable, path, posix})}
    end
  end

  defp login_result(provider, %{"auth" => %{"client_token" => token} = auth})
       when is_binary(token) and token != "" do
    case Map.get(auth, "lease_duration") do
      lease when is_integer(lease) and lease >= 0 -> {:ok, token, lease}
      _ -> {:error, kubernetes_error(provider, :malformed_login_response)}
    end
  end

  defp login_result(provider, _body),
    do: {:error, kubernetes_error(provider, :malformed_login_response)}

  defp kubernetes_error(provider, {:http_status, 403}),
    do: unavailable(provider, {:kubernetes_auth, :forbidden})

  defp kubernetes_error(provider, reason), do: unavailable(provider, {:kubernetes_auth, reason})

  # `Req.request/1` returns `{:error, exception}` for a transport failure, but it also
  # *raises* (a bad `:base_url`, an unsupported scheme, a broken step) and can exit
  # (an out-of-range port). An exception escaping a Req step as a non-AshVault error
  # would be classified by callers as "some unknown failure" rather than a provider
  # outage — and, worse, such an exception can carry the whole `Req.Request`, whose
  # headers hold the token. Everything becomes `ProviderUnavailable`, carrying only the
  # kind and reason.
  defp perform(provider, options) do
    case transport_status() do
      :ready ->
        case options |> Req.new() |> Req.request() do
          {:ok, response} -> {:ok, response}
          {:error, exception} -> {:error, unavailable(provider, transport_reason(exception))}
        end

      {:not_started, app} ->
        {:error, unavailable(provider, {:not_started, app})}
    end
  rescue
    exception -> {:error, unavailable(provider, transport_reason(exception))}
  catch
    :exit, _reason -> {:error, unavailable(provider, {:transport, :exit})}
    :throw, _value -> {:error, unavailable(provider, {:transport, :throw})}
  end

  @doc """
  Whether the HTTP transport the OpenBao providers need is actually running.

  A missing OTP application is **not** an outage, and reporting it as one is the single
  most expensive confusion this code can cause: with `:req` unstarted, every call comes
  back looking byte-for-byte like a genuinely unreachable OpenBao, so an operator pages
  whoever owns the secrets infrastructure over a missing line in `extra_applications`.

  The check is positive and cheap: `Req`'s default pool is a supervisor registered under
  the name `Req.Finch`, so a live pid there settles it in one `Process.whereis/1`.

  Deliberately **not** done by matching on the exception's message: several `Req`/`Finch`
  messages interpolate the request, whose headers carry the token.
  """
  @spec transport_status() :: :ready | {:not_started, :req | :finch}
  def transport_status do
    cond do
      is_pid(Process.whereis(Req.Finch)) -> :ready
      # `:req` first, and it is the actionable one: starting `:req` starts `:finch`
      # with it, so naming `:finch` to someone who is missing both sends them to fix
      # the wrong dependency.
      not started?(:req) -> {:not_started, :req}
      not started?(:finch) -> {:not_started, :finch}
      # `:req` is up and has been pointed at a pool that is not `Req.Finch`. Nothing to
      # report: let the request run and fail on its own terms if it is going to.
      true -> :ready
    end
  end

  defp started?(app), do: List.keymember?(Application.started_applications(), app, 0)

  # Only the exception's *kind* and reason travel into the error struct — never the
  # request, whose headers carry the token, and never the exception's message, which for
  # several Req/Finch errors interpolates the request.
  defp transport_reason(%Req.TransportError{reason: reason}), do: {:transport, reason}

  defp transport_reason(%ArgumentError{}) do
    case transport_status() do
      {:not_started, app} -> {:not_started, app}
      :ready -> {:transport, ArgumentError}
    end
  end

  defp transport_reason(%{__struct__: module}), do: {:transport, module}
  defp transport_reason(_), do: :transport_error

  # ── response helpers ───────────────────────────────────────────────────────────

  @doc "The `\"data\"` sub-map of an OpenBao response body, or `%{}`."
  @spec data(term()) :: map()
  def data(body) when is_map(body), do: Map.get(body, "data") || %{}
  def data(_), do: %{}

  @doc "The joined `\"errors\"` strings of a response, for substring classification."
  @spec error_message(term()) :: String.t()
  def error_message(response) do
    response |> errors() |> Enum.filter(&is_binary/1) |> Enum.join(" ")
  end

  defp errors(%{body: body}) when is_map(body) do
    case Map.get(body, "errors") do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp errors(_), do: []

  @doc false
  @spec route_missing?(term()) :: boolean()
  def route_missing?(response), do: error_message(response) =~ "no handler for route"

  defp route_missing_body?(body), do: route_missing?(%{body: body})

  defp already_mounted?(response), do: error_message(response) =~ "already in use"

  @doc false
  @spec unavailable!(module(), term()) :: {:error, Exception.t()}
  def unavailable!(provider, response), do: {:error, unavailable(provider, response)}

  @doc """
  Build a `AshVault.Errors.ProviderUnavailable` attributed to `provider`.
  """
  @spec unavailable(module(), term()) :: Exception.t()
  def unavailable(provider, %Req.Response{status: status}),
    do: unavailable(provider, {:http_status, status})

  def unavailable(provider, %{status: status}) when is_integer(status),
    do: unavailable(provider, {:http_status, status})

  def unavailable(provider, reason) do
    ProviderUnavailable.exception(provider: provider, reason: normalise_reason(reason))
  end

  defp normalise_reason({:http_status, 403}), do: :forbidden
  defp normalise_reason(reason), do: reason

  # ── configuration ──────────────────────────────────────────────────────────────

  defp config(provider), do: AshVault.KeyProvider.config(provider)

  @doc false
  @spec address(module()) :: String.t()
  def address(provider), do: Keyword.get(config(provider), :address) || @default_address

  @doc false
  @spec transit_mount(module()) :: String.t()
  def transit_mount(provider),
    do: Keyword.get(config(provider), :transit_mount) || @default_transit_mount

  @doc false
  @spec kv_mount(module()) :: String.t()
  def kv_mount(provider), do: Keyword.get(config(provider), :kv_mount) || @default_kv_mount

  @doc false
  @spec receive_timeout(module()) :: pos_integer()
  def receive_timeout(provider),
    do: Keyword.get(config(provider), :receive_timeout) || @default_receive_timeout

  @doc false
  @spec max_retries(module()) :: non_neg_integer()
  def max_retries(provider) do
    case Keyword.get(config(provider), :max_retries) do
      retries when is_integer(retries) and retries >= 0 -> retries
      _ -> @default_max_retries
    end
  end

  @doc "A path under the configured transit mount."
  @spec transit_path(module(), String.t()) :: String.t()
  def transit_path(provider, suffix), do: "/v1/#{transit_mount(provider)}#{suffix}"

  @doc "A path under the configured KV mount."
  @spec kv_path(module(), String.t()) :: String.t()
  def kv_path(provider, suffix), do: "/v1/#{kv_mount(provider)}#{suffix}"

  # Resolves the token without ever placing it in a log line or an error struct.
  defp token(provider) do
    config = config(provider)

    case {Keyword.get(config, :auth), Keyword.get(config, :token)} do
      {nil, token} ->
        static_token(provider, token)

      {{:kubernetes, opts}, nil} ->
        KubernetesAuth.token(provider, KubernetesAuth.options!(provider, opts))

      {{:kubernetes, _opts}, _token} ->
        raise ArgumentError, """
        #{inspect(provider)} is configured with both :token and auth: {:kubernetes, ...}.

        Remove one. AshVault will not guess which credential you meant.
        """

      {auth, _token} ->
        raise ArgumentError, """
        #{inspect(provider)} has an unsupported :auth #{inspect(auth_kind(auth))}.

        The supported form is auth: {:kubernetes, role: "..."}.
        """
    end
  end

  defp auth_kind({kind, _opts}) when is_atom(kind), do: kind
  defp auth_kind(_auth), do: :unknown

  defp static_token(provider, token) do
    case token do
      token when is_binary(token) and token != "" -> {:ok, token}
      {:system, variable} when is_binary(variable) -> from_env(provider, variable)
      fun when is_function(fun, 0) -> from_fun(provider, fun)
      _ -> {:error, unavailable(provider, :missing_token)}
    end
  end

  defp from_env(provider, variable) do
    case System.get_env(variable) do
      token when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, unavailable(provider, :missing_token)}
    end
  end

  defp from_fun(provider, fun) do
    case fun.() do
      token when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, unavailable(provider, :missing_token)}
    end
  end
end
