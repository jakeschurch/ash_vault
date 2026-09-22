defmodule AshVault.Mix.Shared do
  @moduledoc """
  Argument parsing, resolution and output helpers shared by the `ash_vault.*` Mix tasks.

  The tasks themselves are deliberately thin: they parse `argv`, call into
  `AshVault.Backfill` or `AshVault` and format the result. Everything they have in common
  — starting the app, turning `"MyApp.User"` into a module, resolving a vault and a scope
  without minting key material, printing one `key=value` line per unit of progress —
  lives here.

  ## Output contract

  Every task prints `key=value` lines that a deploy script can grep, then a human summary
  on the last line. Failures raise `Mix.Error`, which exits non-zero.
  """

  @doc """
  Start the host application so resources, repos and key providers are running.
  """
  @spec start_app!([String.t()]) :: :ok
  def start_app!(_argv \\ []) do
    Mix.Task.run("app.start")
    :ok
  end

  @doc """
  Resolve a resource module name given on the command line, failing clearly when it is
  not a loadable Ash resource.
  """
  @spec resource!(String.t()) :: module()
  def resource!(name) do
    module = Module.concat([name])

    case Code.ensure_compiled(module) do
      {:module, module} ->
        unless Spark.Dsl.is?(module, Ash.Resource) do
          abort!("#{inspect(module)} is not an Ash resource.")
        end

        module

      {:error, reason} ->
        abort!("could not load #{inspect(module)}: #{inspect(reason)}")
    end
  end

  @doc """
  Resolve an optional `--domain` option to a module.
  """
  @spec domain(keyword()) :: module() | nil
  def domain(opts) do
    case opts[:domain] do
      nil -> nil
      name -> Module.concat([name])
    end
  end

  @doc """
  The tenants a task should operate over: `[nil]` when the scope needs no tenant, the one
  `--tenant`, or every tenant returned by `--all-tenants Module.function/0`.
  """
  @spec tenants!(keyword()) :: [term()]
  def tenants!(opts) do
    case {opts[:tenant], opts[:all_tenants]} do
      {nil, nil} ->
        [nil]

      {tenant, nil} ->
        [tenant]

      {nil, mfa} ->
        case apply_mfa!(mfa) do
          [] -> abort!("`--all-tenants #{mfa}` returned no tenants.")
          tenants when is_list(tenants) -> tenants
          other -> abort!("`--all-tenants #{mfa}` returned #{inspect(other)}, expected a list.")
        end

      {_tenant, _mfa} ->
        abort!("pass either `--tenant` or `--all-tenants`, not both.")
    end
  end

  @doc """
  Parse and call a `"Module.function/arity"` string, as accepted by `--all-tenants`.
  """
  @spec apply_mfa!(String.t()) :: term()
  def apply_mfa!(string) do
    with [call, arity] <- String.split(string, "/", parts: 2),
         {arity, ""} <- Integer.parse(arity),
         {module, function} <- split_call(call) do
      unless arity == 0 do
        abort!("`--all-tenants` needs a zero-arity function, got #{string}")
      end

      case Code.ensure_compiled(module) do
        {:module, _} -> apply(module, function, [])
        {:error, reason} -> abort!("could not load #{inspect(module)}: #{inspect(reason)}")
      end
    else
      _ -> abort!("`--all-tenants` expects `Module.function/0`, got #{inspect(string)}")
    end
  end

  defp split_call(call) do
    parts = String.split(call, ".")
    {function, module_parts} = List.pop_at(parts, -1)
    {Module.concat(module_parts), String.to_atom(function)}
  end

  @doc """
  Resolve the vault, scope module, scope key and key provider for a resource and tenant,
  without touching the provider.
  """
  @spec resolve!(module(), term(), atom()) ::
          %{vault: module(), scope: term(), scope_module: module(), provider: module()}
  def resolve!(resource, tenant, field \\ :__key_lifecycle__) do
    ash_context = %{tenant: tenant, actor: nil, source_context: %{}, phase: :write}

    vault =
      try do
        AshVault.Info.vault!(resource, ash_context)
      rescue
        _ ->
          abort!("#{inspect(resource)} does not use the `AshVault` extension.")
      end

    scope_module = vault.__ash_vault__(:scope)
    context = %AshVault.Context{resource: resource, field: field, ash_context: ash_context}

    scope =
      try do
        scope_module.resolve!(context)
      rescue
        error in [AshVault.Errors.MissingScope] ->
          abort!(
            Exception.message(error) <>
              "\nPass `--tenant TENANT`, or `--all-tenants Module.function/0`."
          )
      end

    %{
      vault: vault,
      scope: scope,
      scope_module: scope_module,
      provider: vault.__ash_vault__(:key_provider)
    }
  end

  @doc """
  Inspect a scope's key state **without minting anything**.

  `current_key/1` mints version 1 on first use, so a read-only task must probe
  `get_key/2` first. Returns `:destroyed`, `:not_minted`, or
  `{:active, %{version:, created_at:, versions:}}`.
  """
  @spec key_state(module(), term()) ::
          :destroyed | :not_minted | {:active, map()} | {:error, term()}
  def key_state(provider, scope) do
    case provider.get_key(scope, 1) do
      {:error, :destroyed} ->
        :destroyed

      {:error, :not_found} ->
        :not_minted

      {:error, reason} ->
        {:error, reason}

      {:ok, _key} ->
        case provider.current_key(scope) do
          {:ok, %{version: version, created_at: created_at}} ->
            {:active,
             %{
               version: version,
               created_at: created_at,
               versions: versions(provider, scope, version)
             }}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp versions(provider, scope, current) do
    Enum.filter(1..current//1, fn version ->
      match?({:ok, _}, provider.get_key(scope, version))
    end)
  end

  @doc """
  Every `resource.field` in the project encrypted by `vault` under the same scope module.

  This is what `mix ash_vault.destroy_keys` prints as "about to become undecryptable".
  """
  @spec encrypted_fields_for_vault([module()], module(), term()) :: [{module(), atom()}]
  def encrypted_fields_for_vault(domains, vault, tenant) do
    ash_context = %{tenant: tenant, actor: nil, source_context: %{}, phase: :write}

    for domain <- domains,
        resource <- Ash.Domain.Info.resources(domain),
        Spark.Dsl.is?(resource, Ash.Resource),
        AshVault in Spark.extensions(resource),
        resolves_to?(resource, ash_context, vault),
        field <- AshVault.Info.encrypted_field_names(resource) do
      {resource, field}
    end
  end

  defp resolves_to?(resource, ash_context, vault) do
    AshVault.Info.vault!(resource, ash_context) == vault
  rescue
    _ -> false
  end

  @doc """
  The Ash domains of the current project, honouring `--domain`.
  """
  @spec domains(keyword()) :: [module()]
  def domains(opts) do
    case domain(opts) do
      nil ->
        apps()
        |> Enum.flat_map(&Application.get_env(&1, :ash_domains, []))
        |> Enum.uniq()

      domain ->
        [domain]
    end
  end

  defp apps do
    if apps_paths = Mix.Project.apps_paths() do
      apps_paths |> Map.keys() |> Enum.sort()
    else
      [Mix.Project.config()[:app]]
    end
  end

  @doc """
  Print one parseable `key=value` line.
  """
  @spec kv(keyword() | map()) :: :ok
  def kv(pairs) do
    pairs
    |> Enum.map(fn {key, value} -> "#{key}=#{format(value)}" end)
    |> Enum.join(" ")
    |> Mix.shell().info()
  end

  @doc """
  Print a human-readable line.
  """
  @spec say(IO.chardata()) :: :ok
  def say(message), do: Mix.shell().info(message)

  @doc """
  Format one value for a `key=value` line.
  """
  @spec format(term()) :: String.t()
  def format(nil), do: "-"
  def format(true), do: "true"
  def format(false), do: "false"
  def format(value) when is_binary(value), do: value

  def format(value) when is_atom(value) do
    case Atom.to_string(value) do
      "Elixir." <> _ -> inspect(value)
      other -> other
    end
  end

  def format(value) when is_number(value), do: to_string(value)
  def format(%DateTime{} = value), do: DateTime.to_iso8601(value)
  def format(value) when is_list(value), do: Enum.map_join(value, ",", &format/1)
  def format(value), do: inspect(value)

  @doc """
  Ask for confirmation unless `--yes` was given. Aborts when declined.
  """
  @spec confirm!(String.t(), keyword()) :: :ok
  def confirm!(question, opts) do
    if opts[:yes] do
      :ok
    else
      if Mix.shell().yes?(question) do
        :ok
      else
        abort!("aborted by operator.")
      end
    end
  end

  @doc """
  Fail the task with a non-zero exit status.
  """
  @spec abort!(IO.chardata()) :: no_return()
  def abort!(message), do: Mix.raise(IO.iodata_to_binary(message))
end
