defmodule AshVault.Macaroon.Preparations.Verify do
  @moduledoc """
  Backs the generated `:<name>_by_token` read action, and any read action you declare
  yourself to sign in with a macaroon.

      read :sign_in_with_token do
        argument :token, :string, allow_nil?: false, sensitive?: true
        get? true
        prepare {AshVault.Macaroon.Preparations.Verify, macaroon: :api, mode: :sign_in}
      end

  ## What it does

    1. verifies the token (`AshVault.Macaroon.Runtime.verify/4`): envelope, prefix, scope,
       root signature at the stated `:mac` key version, the caveat chain in constant
       time, the key-version window, expiry
    2. sets the query's tenant to the token's scope (a `:tenant`-scoped resource), after
       the signature has verified and only if the request did not already carry a
       tenant — one that disagrees is `:scope_mismatch`
    3. filters to the record the token names, and evaluates `revoked_when` alongside it
    4. after the read: no record is `InvalidMacaroon` (`:not_found`), a `revoked_when`
       that is not exactly `false` is `MacaroonRevoked` (`:record`), and every
       `phase: :verify` caveat check runs against the loaded record
    5. puts `macaroon: %AshVault.Macaroon.Verified{}` and `using_macaroon?: true` into the
       record's metadata

  ## Options

    * `:macaroon` — required, the macaroon's name
    * `:argument` — the token argument, default `:token`
    * `:require_enforcement?` — refuse a token that carries `phase: :authorize` caveats
      (`InvalidMacaroon`, `:unenforced_caveats`) unless the caller asserts they will be
      enforced with `context: %{ash_vault: %{authorize_caveats_enforced?: true}}`.
      Defaults to the macaroon's `require_authorize_enforcement?`. Turn it on where a
      verified actor may reach code whose policies do not use
      `AshVault.Checks.MacaroonAllows`.
    * `:mode` — `:error` (default) returns every failure as an error. `:sign_in` follows
      AshAuthentication's sign-in convention: an invalid or revoked token reads as **no
      record** (`[]`), so a plug answers 401. An outage
      (`AshVault.Errors.ProviderUnavailable`) is still an error in both modes: an outage
      must never look like a bad credential, and never like a good one.

  The record load is the action's own read, so the resource's policies apply to it. A
  token-authenticated read usually has no actor yet; authorize the action itself
  (`policy action(:api_by_token) do authorize_if always() end`) — the token is the
  credential.
  """

  use Ash.Resource.Preparation

  alias AshVault.Errors.InvalidMacaroon
  alias AshVault.Errors.MacaroonRevoked
  alias AshVault.Macaroon.CheckContext
  alias AshVault.Macaroon.Record
  alias AshVault.Macaroon.Runtime

  @impl Ash.Resource.Preparation
  def init(opts) do
    cond do
      not is_atom(opts[:macaroon]) or is_nil(opts[:macaroon]) ->
        {:error, "AshVault.Macaroon.Preparations.Verify requires a `:macaroon` name"}

      not is_boolean(Keyword.get(opts, :require_enforcement?, false)) ->
        {:error, "`:require_enforcement?` must be a boolean"}

      Keyword.get(opts, :mode, :error) not in [:error, :sign_in] ->
        {:error, "`:mode` must be :error or :sign_in"}

      true ->
        {:ok, opts}
    end
  end

  @impl Ash.Resource.Preparation
  def prepare(query, opts, context) do
    resource = query.resource
    definition = AshVault.Info.macaroon(resource, Keyword.fetch!(opts, :macaroon))
    mode = Keyword.get(opts, :mode, :error)
    token = Ash.Query.get_argument(query, Keyword.get(opts, :argument, :token))
    actor = Map.get(context, :actor)

    require? = Keyword.get(opts, :require_enforcement?, definition.require_authorize_enforcement?)

    case Runtime.verify(resource, definition, token,
           tenant: query.tenant,
           actor: actor,
           source_context: query.context
         ) do
      {:ok, verified} ->
        if require? and verified.authorize_caveats != [] and
             not enforcement_asserted?(query.context) do
          fail(query, Runtime.invalid(resource, definition, :unenforced_caveats), mode)
        else
          load(query, resource, definition, verified, mode, actor)
        end

      {:error, error} ->
        fail(query, error, mode)
    end
  end

  defp load(query, resource, definition, verified, mode, actor) do
    attribute = Runtime.identity_attribute(resource, definition)

    case Record.cast_id(attribute, verified.id) do
      {:ok, value} ->
        query
        |> maybe_set_tenant(Runtime.tenant_for(resource, verified))
        |> Record.filter_identity(attribute, value)
        |> Record.with_revocation(definition)
        |> Ash.Query.after_action(fn query, records ->
          after_load(query, records, resource, definition, verified, mode, actor)
        end)

      :error ->
        fail(query, Runtime.invalid(resource, definition, :not_found), mode)
    end
  end

  defp enforcement_asserted?(context) do
    match?(%{ash_vault: %{authorize_caveats_enforced?: true}}, context)
  end

  defp maybe_set_tenant(query, nil), do: query
  defp maybe_set_tenant(%{tenant: nil} = query, tenant), do: Ash.Query.set_tenant(query, tenant)
  defp maybe_set_tenant(query, _tenant), do: query

  defp after_load(query, [record], resource, definition, verified, mode, actor) do
    check_context = %CheckContext{
      phase: :verify,
      now: AshVault.Macaroon.Clock.now(),
      resource: resource,
      macaroon: definition.name,
      scope: verified.scope,
      tenant: query.tenant,
      actor: actor,
      record: record,
      context: query.context
    }

    with false <- Record.revoked?(record, definition),
         :ok <-
           Runtime.check_caveats(resource, definition, verified.caveats, :verify, check_context) do
      {:ok,
       [
         record
         |> Record.strip()
         |> Ash.Resource.put_metadata(:macaroon, verified)
         |> Ash.Resource.put_metadata(:using_macaroon?, true)
       ]}
    else
      true -> result(Runtime.revoked(resource, definition, :record), mode)
      {:error, error} -> result(error, mode)
    end
  end

  defp after_load(_query, [], resource, definition, _verified, mode, _actor),
    do: result(Runtime.invalid(resource, definition, :not_found), mode)

  defp after_load(_query, _many, resource, definition, _verified, _mode, _actor),
    do: {:error, Runtime.invalid(resource, definition, :not_found)}

  defp result(%error{}, :sign_in) when error in [InvalidMacaroon, MacaroonRevoked], do: {:ok, []}
  defp result(error, _mode), do: {:error, error}

  # A refused token has no trustworthy tenant, and a multitenant read without one fails
  # with `TenantRequired` — which a plug would report as a server error rather than a
  # bad credential. The result is fixed to `[]` and the filter to `false` first, so
  # waiving the tenant requirement cannot let the data layer run.
  defp fail(query, %error{}, :sign_in) when error in [InvalidMacaroon, MacaroonRevoked] do
    query
    |> Ash.Query.set_result({:ok, []})
    |> Ash.Query.filter(false)
    |> Ash.Query.set_context(%{private: %{multitenancy: :allow_global}})
  end

  defp fail(query, error, _mode), do: Ash.Query.add_error(query, error)
end
