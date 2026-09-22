defmodule AshVault.Transformers.ExpandAttributes do
  @moduledoc """
  Expands the `attributes [:a, :b]` sugar into real `%AshVault.Encrypted{}` entities.

  Names that already have an explicit `encrypt` entity are skipped, so options set there
  win. Entities are appended (`type: :append`) — `Spark.Dsl.Transformer.add_entity/4`
  *prepends* by default, which would silently reverse field order relative to the
  explicit entities.

  The `attributes` option is left in place afterwards; `AshVault.Info.encrypted_fields/1`
  de-duplicates against the entities, so running this transformer is idempotent and
  nothing downstream depends on whether it has run yet.
  """

  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  @doc false
  @impl Spark.Dsl.Transformer
  def before?(AshVault.Transformers.SetupEncryption), do: true
  def before?(_), do: false

  @doc false
  @impl Spark.Dsl.Transformer
  def transform(dsl) do
    existing = MapSet.new(AshVault.Info.ash_vault(dsl), & &1.name)

    dsl
    |> AshVault.Info.ash_vault_attributes!()
    |> Enum.uniq()
    |> Enum.reject(&MapSet.member?(existing, &1))
    |> Enum.reduce({:ok, dsl}, fn name, {:ok, dsl} ->
      {:ok,
       Transformer.add_entity(dsl, [:ash_vault], %AshVault.Encrypted{name: name}, type: :append)}
    end)
  end
end
