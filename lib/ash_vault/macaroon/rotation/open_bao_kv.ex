defmodule AshVault.Macaroon.Rotation.OpenBaoKV do
  @moduledoc """
  A `AshVault.Macaroon.Rotation.Delivery` that writes each token to OpenBao KV v2, one
  path per consumer, for consumers that read it through External Secrets Operator (an
  `ExternalSecret` per consumer namespace, through a `SecretStore` whose policy reads
  only that path).

  Configuration, under the vault's OTP app like a key provider's:

      config :my_app, AshVault.Macaroon.Rotation.OpenBaoKV,
        provider: AshVault.KeyProviders.OpenBaoTransit,
        mount: "my-app-credentials"

    * `:provider` — the OpenBao key provider whose connection to reuse: its `address`,
      `auth` (a static token or `{:kubernetes, role: ...}`), `cacertfile` and
      `req_options`. The login, its token cache and its refusal to follow redirects are
      shared; nothing here logs in separately. Grant that role a policy for this mount
      (below).
    * `:mount` — the KV v2 mount. Required; give rotated credentials a mount of their own.

  ## Layout

    * `staging/<ref>` — the staged token of each rotated credential. Only the minting
      service reads it: a consumer's policy must never cover `staging/`.
    * each consumer's `path` (a consumer is `%{name: ..., path: ...}`, string or atom
      keys).

  Every write is `{"token": <token>, "credential_id": <id>}`. An `ExternalSecret`
  extracts `property: token`; `credential_id` lets `staged/2` tell whether staging still
  holds the credential rotation expects. The writer policy needs
  `["create", "update", "read"]` on `<mount>/data/staging/*` and
  `["create", "update"]` on each consumer path; a consumer's policy needs `["read"]` on
  its own path only.

  ## Timing

  An `ExternalSecret` syncs on its `refreshInterval`, so a consumer's Secret changes up
  to that long after delivery. Rotation revokes the predecessor only after the quiet
  period passes with no use of it, so keep `refreshInterval` well under the quiet period
  (e.g. 5 minutes against an hour); otherwise an idle consumer can have its old token
  revoked before its Secret changes. A consumer that reads the token only at start
  needs a restart when the Secret changes: annotate it for Stakater Reloader
  (`secret.reloader.stakater.com/reload: <secret>`).

  Response bodies are never put into errors or logs: a read of staging carries the
  token. Errors are `{:openbao_kv, op, path, status}` or the provider's
  `AshVault.Errors.ProviderUnavailable`.
  """

  @behaviour AshVault.Macaroon.Rotation.Delivery

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao.Transport
  alias AshVault.Macaroon.Rotation.Secret

  @segment ~r/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/

  @impl true
  def stage(context, id, %Secret{} = secret) do
    with {:ok, path} <- staging_path(context.ref), do: put(path, id, secret)
  end

  @impl true
  def staged(context, id) do
    with {:ok, path} <- staging_path(context.ref), {:ok, config} <- config() do
      case Transport.get(config.provider, data_path(config, path)) do
        {:ok, %{status: 200, body: %{"data" => %{"data" => %{} = data}}}} ->
          case data do
            %{"credential_id" => ^id, "token" => token} when is_binary(token) and token != "" ->
              {:ok, Secret.new(token)}

            _other ->
              :lost
          end

        {:ok, %{status: 404}} ->
          :lost

        {:ok, %{status: status}} ->
          {:error, {:openbao_kv, :read, path, status}}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  @impl true
  def deliver(_context, consumer, id, %Secret{} = secret) do
    with {:ok, path} <- consumer_path(consumer), do: put(path, id, secret)
  end

  @impl true
  def consumer_name(%{name: name}) when is_binary(name), do: name
  def consumer_name(%{"name" => name}) when is_binary(name), do: name

  @impl true
  def describe_error({:openbao_kv, op, path, status}) when is_integer(status),
    do: "openbao kv #{op} #{path}: HTTP #{status}"

  def describe_error({:openbao_kv, :path, path}), do: "openbao kv: invalid path #{path}"
  def describe_error({:openbao_kv, :config, message}), do: "openbao kv: #{message}"

  def describe_error(%ProviderUnavailable{provider: provider}),
    do: "openbao unavailable (#{inspect(provider)})"

  def describe_error(_other), do: nil

  defp put(path, id, secret) do
    with {:ok, config} <- config() do
      body = %{"data" => %{"token" => Secret.reveal(secret), "credential_id" => id}}

      case Transport.post(config.provider, data_path(config, path), body) do
        {:ok, %{status: status}} when status in [200, 204] -> :ok
        {:ok, %{status: status}} -> {:error, {:openbao_kv, :write, path, status}}
        {:error, error} -> {:error, error}
      end
    end
  end

  defp data_path(config, path), do: "/v1/#{config.mount}/data/#{path}"

  @doc false
  @spec staging_path(String.t()) :: {:ok, String.t()} | {:error, term()}
  def staging_path(ref), do: checked("staging/" <> ref)

  @doc false
  @spec consumer_path(map()) :: {:ok, String.t()} | {:error, term()}
  def consumer_path(consumer) do
    path = Map.get(consumer, :path) || Map.get(consumer, "path")

    case is_binary(path) && checked(path) do
      {:ok, "staging/" <> _} -> {:error, {:openbao_kv, :path, path}}
      {:ok, path} -> {:ok, path}
      _ -> {:error, {:openbao_kv, :path, inspect_path(path)}}
    end
  end

  defp inspect_path(path) when is_binary(path), do: path
  defp inspect_path(_path), do: "(missing)"

  defp checked(path) do
    segments = String.split(path, "/")

    if segments != [] and Enum.all?(segments, &Regex.match?(@segment, &1)),
      do: {:ok, path},
      else: {:error, {:openbao_kv, :path, path}}
  end

  defp config do
    config = AshVault.KeyProvider.config(__MODULE__)

    case {Keyword.get(config, :provider), Keyword.get(config, :mount)} do
      {provider, mount} when is_atom(provider) and not is_nil(provider) and is_binary(mount) ->
        if Regex.match?(@segment, mount),
          do: {:ok, %{provider: provider, mount: mount}},
          else: {:error, {:openbao_kv, :config, "invalid :mount"}}

      _ ->
        {:error, {:openbao_kv, :config, "set :provider and :mount for #{inspect(__MODULE__)}"}}
    end
  end
end
