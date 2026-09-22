defmodule AshVault.Query do
  @moduledoc """
  Query helpers for searchable encrypted fields.

  A lookup token is an HMAC, so nobody should ever be building one by hand to put in a
  filter — one wrong `String.downcase/1` and the query silently matches nothing. There
  are two supported ways to query a searchable field, and this module is the lower one.

  ## `filter_by/4`

      AshVault.Query.filter_by(MyApp.User, :email, "Jake@Example.com", tenant: "acme")
      |> Ash.read!()

  Returns an `Ash.Query` with the tenant set and a filter on `email_lookup`. The first
  argument may also be an existing `Ash.Query`, so this composes:

      MyApp.User
      |> Ash.Query.filter(active == true)
      |> AshVault.Query.filter_by(:email, "jake@example.com", tenant: "acme")

  ## The generated `:by_<field>` read action

  `encrypt :email, searchable?: true` also generates a read action, `:by_email`, taking
  the plaintext as a `sensitive?: true` argument. That is the form to expose through a
  code interface, which AshVault does not write for you:

      # in your domain
      resource MyApp.User do
        define :get_user_by_email, action: :by_email, args: [:email], get?: true
      end

      MyApp.Accounts.get_user_by_email!("jake@example.com", tenant: "acme")

  ## A missing tenant is an error, never an empty result

  Both paths resolve the scope through the resource's configured `AshVault.Scope`, from
  the query's tenant, exactly as a write does. A tenant-scoped query with no tenant
  therefore fails with `AshVault.Errors.MissingScope`.

  This is the single most important behaviour in this module. A lookup that quietly
  returned zero rows for a missing tenant would read as *"no such user"* — at a login
  form, at a "is this address taken?" check, at a dedupe pass — and it would look
  entirely healthy in review, in logs and in tests.

  The two paths report it differently, on purpose:

    * `filter_by/4` **raises**. It is a plain function with no query of its own to hang
      an error on, and returning `{:error, _}` from something that otherwise returns an
      `Ash.Query` would be easy to ignore.
    * the generated read action adds the error to the query with
      `Ash.Query.add_error/2`, so `Ash.read/2` returns `{:error, _}` and `Ash.read!/2`
      raises — which is what every other Ash error does, and what every other AshVault
      error path already does (`AshVault.encrypt_and_set/4` adds to the changeset,
      `AshVault.decrypt_value/5` returns a value). A preparation that raised would be the
      only place in AshVault where an error escapes a non-bang Ash call as an exception.
  """

  alias AshVault.Context.Builder

  @doc """
  Filter a resource or query on a searchable field's value.

  `context` may be:

    * a keyword list or map carrying `:tenant` (and optionally `:actor`) —
      `[tenant: "acme"]`
    * any Ash callback context struct, which carries `:tenant` already
    * `nil`, for a `scope :global` resource
    * any other term, which is taken to be the tenant itself

  Raises `AshVault.Errors.MissingScope` when the scope cannot be resolved,
  `AshVault.Errors.KeyDestroyed` when the scope has been crypto-erased, and
  `ArgumentError` when `field` is not a searchable field of the resource.
  """
  @spec filter_by(module() | Ash.Query.t(), atom(), term(), term()) :: Ash.Query.t()
  def filter_by(resource_or_query, field, value, context \\ nil) do
    query = Ash.Query.new(resource_or_query)
    resource = query.resource

    ash_context = normalize_context(context)
    query = maybe_set_tenant(query, ash_context)

    ensure_searchable!(resource, field)

    token =
      AshVault.Lookup.token_for!(
        resource,
        field,
        value,
        Builder.from_query(query, field, ash_context)
      )

    apply_filter(query, AshVault.lookup_field_name(field), token)
  end

  @doc """
  The filter clause `filter_by/4` applies, for a token already in hand.

  A `nil` token — from a `nil` plaintext — becomes `is_nil`, not `== nil`, so the query
  means what it says on every data layer.
  """
  @spec apply_filter(Ash.Query.t(), atom(), binary() | nil) :: Ash.Query.t()
  def apply_filter(query, lookup_field, nil),
    do: Ash.Query.do_filter(query, [{lookup_field, [is_nil: true]}])

  def apply_filter(query, lookup_field, token) when is_binary(token),
    do: Ash.Query.do_filter(query, [{lookup_field, token}])

  @doc """
  Normalize the `context` argument of `filter_by/4` into the map
  `AshVault.Context.Builder` expects.
  """
  @spec normalize_context(term()) :: map()
  def normalize_context(nil), do: %{tenant: nil, actor: nil, source_context: %{}}

  def normalize_context(context) when is_list(context) do
    if Keyword.keyword?(context) do
      context |> Map.new() |> normalize_context()
    else
      %{tenant: context, actor: nil, source_context: %{}}
    end
  end

  def normalize_context(%{} = context) do
    if Map.has_key?(context, :tenant) do
      %{
        tenant: Map.get(context, :tenant),
        actor: Map.get(context, :actor),
        source_context: Map.get(context, :source_context) || %{}
      }
    else
      # A bare tenant that happens to be a struct or a map — a loaded `%Organization{}`
      # is the normal case, and it has no `:tenant` key.
      %{tenant: context, actor: nil, source_context: %{}}
    end
  end

  def normalize_context(tenant), do: %{tenant: tenant, actor: nil, source_context: %{}}

  # Only when the caller supplied one. Overwriting a tenant already on the query with
  # `nil` would turn a perfectly good composed query into a MissingScope.
  defp maybe_set_tenant(query, %{tenant: nil}), do: query
  defp maybe_set_tenant(query, %{tenant: tenant}), do: Ash.Query.set_tenant(query, tenant)

  defp ensure_searchable!(resource, field) do
    unless AshVault.Info.searchable?(resource, field) do
      raise ArgumentError, """
      #{inspect(resource)}.#{field} is not a searchable encrypted field.

      Searchable fields on #{inspect(resource)}: \
      #{inspect(resource |> AshVault.Info.searchable_fields() |> Enum.map(& &1.name))}

      Add `searchable?: true` to its `encrypt` entity to give it a lookup token — and
      read `AshVault.Lookup` first: a token publishes the equality relation on that
      column into every backup you will ever take.
      """
    end

    :ok
  end
end
