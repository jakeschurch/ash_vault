defmodule AshVault.KeyProviders.OpenBao.KubernetesAuth do
  @moduledoc """
  A supervised OpenBao token holder for the Kubernetes auth method.

  Configured per provider with `auth: {:kubernetes, opts}` instead of `:token`:

      config :my_app, AshVault.KeyProviders.OpenBaoTransit,
        address: "https://openbao.foundry.svc:8200",
        cacertfile: "/etc/openbao-ca/ca.crt",
        auth: {:kubernetes, role: "ashvault-foundry"}

  ## Options

    * `:role` (required) — the `auth/<mount>/role/<role>` to log in as.
    * `:mount` — the auth mount path. Default `"kubernetes"`.
    * `:jwt_path` — the projected service-account token. Default
      `"/var/run/secrets/kubernetes.io/serviceaccount/token"`.
    * `:refresh_fraction` — log in again once this fraction of the lease has elapsed.
      Default `2/3`.
    * `:backoff_min` / `:backoff_max` — milliseconds between failed logins, doubling
      from min to max. Defaults `1_000` and `30_000`.
    * `:login_timeout` — milliseconds a caller waits for an in-flight login. Default
      `15_000`.

  ## Behaviour

  One holder runs per provider module, started on first use under AshVault's own
  supervisor. It logs in with `POST /v1/auth/<mount>/login`, caches the client token,
  and logs in **again** — rather than calling `renew-self` — once `:refresh_fraction` of
  the lease has passed. A fresh login re-reads the service-account JWT every time (the
  kubelet rotates projected tokens), and is not capped by the role's `token_max_ttl`
  the way renewal is. A `lease_duration` of `0` is a token that never expires and is
  never refreshed.

  The login runs in a task, so callers holding a still-valid token are never blocked by
  a refresh. Concurrent callers arriving with no valid token share one login.

  A failed refresh keeps serving the old token until it actually expires, and retries
  with exponential backoff. Once there is no valid token, a caller inside the backoff
  window gets the last failure immediately instead of triggering another login. Every
  failure is `AshVault.Errors.ProviderUnavailable` with reason
  `{:kubernetes_auth, reason}`: retryable, never `KeyDestroyed`.

  ## Secrets

  The JWT is read, sent and dropped; it is never kept in state. The client token is
  kept in state, and `format_status/1` redacts it (and the task reply that carries it)
  from `:sys.get_status/1` and crash reports. Neither value, nor the login response
  body, ever reaches a log line or an error struct.
  """

  use GenServer

  require Logger

  alias AshVault.KeyProviders.OpenBao.Transport

  @registry AshVault.KeyProviders.OpenBao.AuthRegistry
  @supervisor AshVault.KeyProviders.OpenBao.AuthSupervisor
  @task_supervisor AshVault.KeyProviders.OpenBao.AuthTaskSupervisor

  @default_mount "kubernetes"
  @default_jwt_path "/var/run/secrets/kubernetes.io/serviceaccount/token"
  @default_refresh_fraction 2 / 3
  @default_backoff_min 1_000
  @default_backoff_max 30_000
  @default_login_timeout 15_000

  defmodule State do
    @moduledoc false
    @derive {Inspect, except: [:token]}
    defstruct [
      :provider,
      :token,
      :expires_at,
      :login,
      :next_attempt_at,
      :last_error,
      :timer,
      waiters: [],
      failures: 0
    ]
  end

  @typedoc "Validated Kubernetes auth options."
  @type options :: %{
          role: String.t(),
          mount: String.t(),
          jwt_path: Path.t(),
          refresh_fraction: float(),
          backoff_min: pos_integer(),
          backoff_max: pos_integer(),
          login_timeout: pos_integer()
        }

  @doc """
  Validate `auth: {:kubernetes, opts}` options, filling defaults.

  Raises `ArgumentError` on a configuration fault: retrying cannot fix it.
  """
  @spec options!(module(), keyword()) :: options()
  def options!(provider, opts) when is_list(opts) do
    role = Keyword.get(opts, :role)

    unless is_binary(role) and role != "" do
      raise ArgumentError,
            "#{inspect(provider)} auth: {:kubernetes, opts} requires a non-empty :role"
    end

    fraction = Keyword.get(opts, :refresh_fraction, @default_refresh_fraction)

    unless is_number(fraction) and fraction > 0 and fraction < 1 do
      raise ArgumentError,
            "#{inspect(provider)} Kubernetes auth :refresh_fraction must be between 0 and 1"
    end

    %{
      role: role,
      mount: Keyword.get(opts, :mount, @default_mount),
      jwt_path: Keyword.get(opts, :jwt_path, @default_jwt_path),
      refresh_fraction: fraction / 1,
      backoff_min: positive!(provider, opts, :backoff_min, @default_backoff_min),
      backoff_max: positive!(provider, opts, :backoff_max, @default_backoff_max),
      login_timeout: positive!(provider, opts, :login_timeout, @default_login_timeout)
    }
  end

  def options!(provider, _opts) do
    raise ArgumentError,
          "#{inspect(provider)} auth: {:kubernetes, opts} expects a keyword list of options"
  end

  defp positive!(provider, opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 ->
        value

      _ ->
        raise ArgumentError,
              "#{inspect(provider)} Kubernetes auth #{inspect(key)} must be a positive integer"
    end
  end

  @doc """
  The current client token for `provider`, logging in first if there is none.
  """
  @spec token(module(), options()) :: {:ok, String.t()} | {:error, Exception.t()}
  def token(provider, options) do
    with {:ok, pid} <- ensure_started(provider) do
      GenServer.call(pid, :token, options.login_timeout)
    end
  catch
    :exit, _reason ->
      {:error, Transport.unavailable(provider, {:kubernetes_auth, :login_timeout})}
  end

  @doc false
  @spec stop(module()) :: :ok
  def stop(provider) do
    case Registry.lookup(@registry, provider) do
      [{pid, _value}] -> DynamicSupervisor.terminate_child(@supervisor, pid)
      [] -> :ok
    end

    :ok
  end

  defp ensure_started(provider) do
    case Registry.lookup(@registry, provider) do
      [{pid, _value}] -> {:ok, pid}
      [] -> start(provider)
    end
  rescue
    ArgumentError -> {:error, Transport.unavailable(provider, {:not_started, :ash_vault})}
  end

  defp start(provider) do
    case DynamicSupervisor.start_child(@supervisor, {__MODULE__, provider}) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, _reason} -> {:error, Transport.unavailable(provider, {:kubernetes_auth, :start})}
    end
  end

  @doc false
  def child_spec(provider) do
    %{
      id: {__MODULE__, provider},
      start: {__MODULE__, :start_link, [provider]},
      restart: :transient
    }
  end

  @doc false
  def start_link(provider) do
    GenServer.start_link(__MODULE__, provider, name: {:via, Registry, {@registry, provider}})
  end

  @impl GenServer
  def init(provider), do: {:ok, %State{provider: provider}}

  @impl GenServer
  def handle_call(:token, from, state) do
    now = now()

    cond do
      valid?(state, now) ->
        {:reply, {:ok, state.token}, state}

      state.login != nil ->
        {:noreply, %{state | waiters: [from | state.waiters]}}

      state.next_attempt_at != nil and now < state.next_attempt_at ->
        {:reply, {:error, state.last_error}, state}

      true ->
        {:noreply, state |> start_login() |> Map.update!(:waiters, &[from | &1])}
    end
  end

  @impl GenServer
  def handle_info(:refresh, state) do
    state = %{state | timer: nil}
    if state.login, do: {:noreply, state}, else: {:noreply, start_login(state)}
  end

  def handle_info({ref, result}, %State{login: ref} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, finish_login(%{state | login: nil}, result)}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %State{login: ref} = state) do
    error = Transport.unavailable(state.provider, {:kubernetes_auth, :login_crashed})
    {:noreply, finish_login(%{state | login: nil}, {:error, error})}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl GenServer
  def format_status(status) do
    status
    |> Map.update(:state, nil, &redact_state/1)
    |> Map.update(:message, nil, &redact_message/1)
  end

  defp redact_state(%State{} = state), do: %{state | token: state.token && :redacted}
  defp redact_state(other), do: other

  defp redact_message({ref, {:ok, _token, lease}}) when is_reference(ref),
    do: {ref, {:ok, :redacted, lease}}

  defp redact_message(message), do: message

  defp start_login(state) do
    provider = state.provider

    task =
      Task.Supervisor.async_nolink(@task_supervisor, fn ->
        login(provider)
      end)

    %{state | login: task.ref}
  end

  defp login(provider) do
    options = Transport.kubernetes_options!(provider)
    Transport.kubernetes_login(provider, options)
  rescue
    exception in ArgumentError ->
      {:error,
       Transport.unavailable(provider, {:kubernetes_auth, {:invalid_config, exception.message}})}
  end

  defp finish_login(state, {:ok, token, lease_seconds}) do
    now = now()
    options = current_options(state.provider)

    {expires_at, refresh_in} =
      case lease_seconds do
        0 -> {:never, nil}
        seconds -> {now + seconds * 1_000, trunc(seconds * 1_000 * options.refresh_fraction)}
      end

    Logger.debug(
      "AshVault: Kubernetes auth login for #{inspect(state.provider)} succeeded, lease #{lease_seconds}s"
    )

    Enum.each(state.waiters, &GenServer.reply(&1, {:ok, token}))

    %{
      state
      | token: token,
        expires_at: expires_at,
        failures: 0,
        next_attempt_at: nil,
        last_error: nil,
        waiters: []
    }
    |> schedule(refresh_in)
  end

  defp finish_login(state, {:error, error}) do
    now = now()
    options = current_options(state.provider)
    failures = state.failures + 1
    backoff = backoff(options, failures)

    Logger.warning(
      "AshVault: Kubernetes auth login for #{inspect(state.provider)} failed " <>
        "(#{inspect(reason(error))}); retrying in #{backoff}ms"
    )

    Enum.each(state.waiters, &GenServer.reply(&1, {:error, error}))

    retry_in =
      case state.expires_at do
        expires_at when is_integer(expires_at) and expires_at > now ->
          min(backoff, expires_at - now)

        _ ->
          backoff
      end

    %{
      state
      | failures: failures,
        next_attempt_at: now + backoff,
        last_error: error,
        waiters: []
    }
    |> schedule(retry_in)
  end

  @doc false
  @spec backoff(options(), pos_integer()) :: pos_integer()
  def backoff(options, failures) do
    exponent = min(failures - 1, 20)
    min(options.backoff_max, options.backoff_min * Integer.pow(2, exponent))
  end

  defp reason(%{reason: reason}), do: reason
  defp reason(_error), do: :unknown

  defp current_options(provider) do
    Transport.kubernetes_options!(provider)
  rescue
    ArgumentError -> options!(provider, role: "unconfigured")
  end

  defp schedule(state, nil), do: cancel(state)

  defp schedule(state, milliseconds) do
    state = cancel(state)
    %{state | timer: Process.send_after(self(), :refresh, max(milliseconds, 0))}
  end

  defp cancel(%State{timer: nil} = state), do: state

  defp cancel(state) do
    Process.cancel_timer(state.timer)
    %{state | timer: nil}
  end

  defp valid?(%State{token: nil}, _now), do: false
  defp valid?(%State{expires_at: :never}, _now), do: true
  defp valid?(%State{expires_at: expires_at}, now), do: now < expires_at

  defp now, do: System.monotonic_time(:millisecond)
end
