defmodule AshVault.Info do
  @moduledoc """
  Introspection for the `AshVault` extension.

  `Spark.InfoGenerator` generates the raw option readers — `ash_vault_vault/1` and
  `ash_vault_vault!/1`, `ash_vault_scope/1`, `ash_vault_attributes/1`,
  `ash_vault_decrypt_by_default/1`, `ash_vault_encrypt_nil?/1`, `ash_vault_scope_owner?/1`,
  `ash_vault_options/1`, `ash_vault_key_lifecycle_rotate/1`, `ash_vault_key_lifecycle_destroy/1`
  — plus `ash_vault/1`, which returns the `encrypt` entities.

  Note the generator's naming rules: entity readers are named after the *section path*
  (hence `ash_vault/1`, not `ash_vault_encrypt/1`), `?`-suffixed options get only a
  predicate function with no bang variant, and options with a non-nil default never
  return `:error`.

  On top of those this module adds the helpers the extension itself uses.
  """

  use Spark.InfoGenerator, extension: AshVault, sections: [:ash_vault]

  alias AshVault.Encrypted

  @doc """
  Every encrypted field of a resource, as `%AshVault.Encrypted{}` structs.

  This merges the `attributes [...]` sugar with the explicit `encrypt` entities, so it
  returns the same answer before and after `AshVault.Transformers.ExpandAttributes` has
  run. Explicit entities win over sugar of the same name, and order is
  entities-then-sugar.
  """
  @spec encrypted_fields(module() | Spark.Dsl.t()) :: [Encrypted.t()]
  def encrypted_fields(resource_or_dsl) do
    entities = ash_vault(resource_or_dsl)
    known = MapSet.new(entities, & &1.name)

    sugar =
      resource_or_dsl
      |> ash_vault_attributes!()
      |> Enum.reject(&MapSet.member?(known, &1))
      |> Enum.uniq()
      |> Enum.map(&%Encrypted{name: &1})

    entities ++ sugar
  end

  @doc """
  The names of every encrypted field of a resource.
  """
  @spec encrypted_field_names(module() | Spark.Dsl.t()) :: [atom()]
  def encrypted_field_names(resource_or_dsl) do
    resource_or_dsl |> encrypted_fields() |> Enum.map(& &1.name)
  end

  @doc """
  One encrypted field by name, or `nil`.
  """
  @spec encrypted_field(module() | Spark.Dsl.t(), atom()) :: Encrypted.t() | nil
  def encrypted_field(resource_or_dsl, name) do
    resource_or_dsl |> encrypted_fields() |> Enum.find(&(&1.name == name))
  end

  @doc """
  Whether `nil` is encrypted for a field, resolving the per-field override against the
  section-level default.
  """
  @spec encrypt_nil?(module() | Spark.Dsl.t(), atom() | Encrypted.t()) :: boolean()
  def encrypt_nil?(resource_or_dsl, %Encrypted{encrypt_nil?: nil}),
    do: ash_vault_encrypt_nil?(resource_or_dsl)

  def encrypt_nil?(_resource_or_dsl, %Encrypted{encrypt_nil?: encrypt_nil?}), do: encrypt_nil?

  def encrypt_nil?(resource_or_dsl, name) when is_atom(name) do
    case encrypted_field(resource_or_dsl, name) do
      nil -> ash_vault_encrypt_nil?(resource_or_dsl)
      field -> encrypt_nil?(resource_or_dsl, field)
    end
  end

  @doc """
  The `AshVault.Scope` module for a resource's key scope.
  """
  @spec scope_module(module() | Spark.Dsl.t()) :: module()
  def scope_module(resource_or_dsl) do
    case ash_vault_scope!(resource_or_dsl) do
      :tenant -> AshVault.Scopes.AshTenant
      :global -> AshVault.Scopes.Global
      module when is_atom(module) -> module
    end
  end

  @doc """
  The vault module for a resource, resolving the `fun/2` and MFA forms against the
  callback context.

  The context handed here is always the **normalized** `ash_context` map built by
  `AshVault.Context.Builder` — `%{tenant:, actor:, source_context:, phase:}` — so a
  dynamic vault sees one shape on the write path, the read path and the lifecycle
  actions alike, rather than three different Ash callback structs.
  """
  @spec vault!(module() | Spark.Dsl.t(), term()) :: module()
  def vault!(resource_or_dsl, context) do
    case ash_vault_vault!(resource_or_dsl) do
      {m, f, a} -> apply(m, f, [resource_or_dsl, context | List.wrap(a)])
      fun when is_function(fun, 2) -> fun.(resource_or_dsl, context)
      vault -> vault
    end
  end
end
