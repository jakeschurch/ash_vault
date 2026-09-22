defmodule AshVault.Transformers.SetupEncryption do
  @moduledoc """
  Replaces each encrypted attribute with a private ciphertext attribute plus a decrypt
  calculation, and rewrites the actions that used to accept it.

  ## Ordering is load-bearing

  This transformer runs **after** `Ash.Resource.Transformers.DefaultAccept`, which is what
  expands `:*`/`nil` accept lists into concrete attribute names. Running before it would
  make `attr.name in action.accept` false everywhere and rewrite zero actions — a silent,
  total failure in which nothing is ever encrypted.

  ## Per field

    1. remove the plaintext attribute entity — *this* is the non-persistence mechanism.
       There is no plaintext column, so no data layer can write one. `private?` and
       scrubbing are not relied on for that.
    2. add `encrypted_<name>` as a `:binary` attribute, `public?: false`,
       `sensitive?: true`, `allow_nil?: true`
    3. add a calculation of the original name, type and constraints backed by
       `AshVault.Calculations.Decrypt`
    4. for every create/update/destroy action that accepted the attribute: add an
       argument of the original type, prepend `AshVault.Changes.Encrypt`, and drop the
       attribute from `accept`

  ## Deviation from ash_cloak: `allow_nil?` on the backing attribute

  ash_cloak copies the original `attribute.allow_nil?` onto the ciphertext column. That is
  wrong whenever `encrypt_nil?: false`, because a `nil` value then legitimately stores SQL
  NULL in an `allow_nil?: false` column and the write fails. AshVault always sets the
  backing attribute to `allow_nil?: true` and enforces real nullability through the
  calculation's `allow_nil?` and the action argument's `allow_nil?` instead.
  """

  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias Spark.Dsl.Transformer

  @doc false
  @impl Spark.Dsl.Transformer
  def after?(Ash.Resource.Transformers.DefaultAccept), do: true
  def after?(_), do: false

  @doc false
  @impl Spark.Dsl.Transformer
  def transform(dsl) do
    module = Transformer.get_persisted(dsl, :module)
    fields = AshVault.Info.encrypted_fields(dsl)

    verify_no_duplicates!(module, fields)

    fields
    |> Enum.reduce_while({:ok, dsl}, fn field, {:ok, dsl} ->
      attribute = fetch_attribute!(module, dsl, field)

      dsl
      |> Transformer.remove_entity([:attributes], &(&1.name == attribute.name))
      |> Builder.add_attribute(AshVault.encrypted_field_name(attribute.name), :binary,
        allow_nil?: true,
        sensitive?: true,
        public?: false,
        description: "Encrypted #{attribute.name}"
      )
      |> Builder.add_calculation(
        attribute.name,
        attribute.type,
        {AshVault.Calculations.Decrypt,
         [field: AshVault.encrypted_field_name(attribute.name), plain_field: attribute.name]},
        [
          public?: attribute.public?,
          constraints: attribute.constraints,
          allow_nil?: attribute.allow_nil?,
          sensitive?: true,
          filterable?: false,
          sortable?: false
        ]
        |> maybe_description(attribute)
      )
      |> rewrite_actions(attribute)
      |> case do
        {:ok, dsl} -> {:cont, {:ok, dsl}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
    |> add_decrypt_by_default()
    |> add_key_lifecycle_actions()
  end

  defp verify_no_duplicates!(module, fields) do
    duplicates =
      fields
      |> Enum.frequencies_by(& &1.name)
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))

    if duplicates != [] do
      raise Spark.Error.DslError,
        module: module,
        path: [:ash_vault, :encrypt],
        message: "duplicate `encrypt` entries for #{inspect(duplicates)}"
    end
  end

  defp fetch_attribute!(module, dsl, field) do
    attribute = Ash.Resource.Info.attribute(dsl, field.name)

    cond do
      is_nil(attribute) ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message: "No attribute called #{inspect(field.name)} found"

      attribute.primary_key? ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message: "cannot encrypt primary key attribute #{inspect(field.name)}"

      Ash.Resource.Info.attribute(dsl, AshVault.encrypted_field_name(field.name)) ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message:
            "#{inspect(field.name)} already has an " <>
              "#{inspect(AshVault.encrypted_field_name(field.name))} sibling attribute"

      field.searchable? or field.unique? ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message:
            "`searchable?` and `unique?` are not implemented in v1 " <>
              "(on #{inspect(field.name)}). Remove them; lookup tokens are post-v1."

      true ->
        attribute
    end
  end

  defp maybe_description(opts, %{description: description}) when is_binary(description),
    do: Keyword.put(opts, :description, description)

  defp maybe_description(opts, _), do: opts

  defp rewrite_actions({:ok, dsl}, attr) do
    dsl
    |> Ash.Resource.Info.actions()
    |> Enum.filter(&(&1.type in [:create, :update, :destroy] && attr.name in &1.accept))
    |> Enum.reduce_while({:ok, dsl}, fn action, {:ok, dsl} ->
      opts =
        case action.type do
          :create ->
            [
              allow_nil?: attr.allow_nil?,
              constraints: attr.constraints,
              default: attr.default,
              sensitive?: true
            ]

          _ ->
            [constraints: attr.constraints, sensitive?: true]
        end

      with {:ok, argument} <- Builder.build_action_argument(attr.name, attr.type, opts),
           {:ok, change} <-
             Builder.build_action_change({AshVault.Changes.Encrypt, field: attr.name}) do
        {:cont,
         {:ok,
          Transformer.replace_entity(
            dsl,
            [:actions],
            %{
              action
              | arguments: [argument | Enum.reject(action.arguments, &(&1.name == attr.name))],
                changes: [change | action.changes],
                accept: action.accept -- [attr.name]
            },
            &(&1.name == action.name)
          )}}
      else
        other -> {:halt, other}
      end
    end)
  end

  defp rewrite_actions({:error, error}, _attr), do: {:error, error}

  defp add_decrypt_by_default({:ok, dsl}) do
    case AshVault.Info.ash_vault_decrypt_by_default!(dsl) do
      [] ->
        {:ok, dsl}

      fields ->
        dsl
        |> Builder.add_change({Ash.Resource.Change.Load, target: fields})
        |> Builder.add_preparation({Ash.Resource.Preparation.Build, options: [load: fields]})
    end
  end

  defp add_decrypt_by_default({:error, error}), do: {:error, error}

  defp add_key_lifecycle_actions({:ok, dsl}) do
    if AshVault.Info.ash_vault_scope_owner?(dsl) do
      dsl
      |> maybe_add_lifecycle_action(
        AshVault.Info.ash_vault_key_lifecycle_rotate(dsl),
        AshVault.Actions.RotateKey,
        :integer,
        "Rotate this scope's AshVault encryption key, returning the new key version."
      )
      |> maybe_add_lifecycle_action(
        AshVault.Info.ash_vault_key_lifecycle_destroy(dsl),
        AshVault.Actions.DestroyKeys,
        :atom,
        "Crypto-erase this scope: destroy every AshVault key version for it."
      )
      |> normalize()
    else
      {:ok, dsl}
    end
  end

  defp add_key_lifecycle_actions({:error, error}), do: {:error, error}

  defp maybe_add_lifecycle_action(dsl, {:ok, name}, implementation, returns, description)
       when is_atom(name) and not is_nil(name) do
    Builder.add_action(dsl, :action, name,
      run: {implementation, []},
      returns: returns,
      allow_nil?: false,
      description: description
    )
  end

  defp maybe_add_lifecycle_action(dsl, _name, _implementation, _returns, _description), do: dsl

  defp normalize({:ok, dsl}), do: {:ok, dsl}
  defp normalize({:error, error}), do: {:error, error}
  defp normalize(dsl), do: {:ok, dsl}
end
