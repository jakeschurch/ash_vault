defmodule AshVault.Macaroon.Record do
  @moduledoc false

  require Ash.Query

  @revoked :ash_vault_macaroon_revoked

  @spec filter_identity(Ash.Query.t(), Ash.Resource.Attribute.t(), term()) :: Ash.Query.t()
  def filter_identity(query, attribute, value) do
    Ash.Query.filter(query, ^Ash.Expr.ref(attribute.name) == ^value)
  end

  @spec with_revocation(Ash.Query.t(), AshVault.Macaroon.Definition.t()) :: Ash.Query.t()
  def with_revocation(query, %{revoked_when: nil}), do: query

  def with_revocation(query, %{revoked_when: expression}),
    do: Ash.Query.calculate(query, @revoked, :boolean, expression)

  @spec revoked?(Ash.Resource.record(), AshVault.Macaroon.Definition.t()) :: boolean()
  def revoked?(_record, %{revoked_when: nil}), do: false

  def revoked?(record, _definition) do
    Map.get(record.calculations, @revoked) !== false
  end

  @spec strip(Ash.Resource.record()) :: Ash.Resource.record()
  def strip(record), do: %{record | calculations: Map.delete(record.calculations, @revoked)}

  @spec cast_id(Ash.Resource.Attribute.t(), binary()) :: {:ok, term()} | :error
  def cast_id(attribute, id) do
    case Ash.Type.cast_input(attribute.type, id, attribute.constraints) do
      {:ok, value} when not is_nil(value) -> {:ok, value}
      _other -> :error
    end
  end
end
