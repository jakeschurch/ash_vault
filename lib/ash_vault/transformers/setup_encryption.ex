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

  ## Per searchable field, additionally

    5. add `<name>_lookup` as a `:binary` attribute — `public?: false`, `sensitive?: true`,
       `allow_nil?: true`, `filterable?: true`, and out of the default select wherever the
       data layer can select
    6. for `unique?: true`, an identity named `<name>_lookup_unique` on `[<name>_lookup]`.
       The multitenancy attribute is deliberately NOT listed: Ash adds it itself, both to
       the generated unique index and to the eager/pre-check query, whenever
       `all_tenants?` is false. See the comment on `add_lookup_identity/3`.
    7. a `:by_<name>` read action taking the plaintext as a `sensitive?: true` argument,
       backed by `AshVault.Preparations.FilterByLookup`

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

  @searchable_types [Ash.Type.String, Ash.Type.CiString, Ash.Type.Binary, Ash.Type.UUID]

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
      |> add_lookup(field, attribute)
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

      field.searchable? and
          Ash.Resource.Info.attribute(dsl, AshVault.lookup_field_name(field.name)) ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message:
            "#{inspect(field.name)} already has an " <>
              "#{inspect(AshVault.lookup_field_name(field.name))} sibling attribute"

      field.unique? and not field.searchable? ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message: """
          `unique?: true` on #{inspect(field.name)} requires `searchable?: true`.

          Uniqueness is enforced on the lookup token, not on the ciphertext: AES-GCM
          draws a fresh nonce per write, so two rows holding the same plaintext have
          completely different `#{AshVault.encrypted_field_name(field.name)}` bytes and a
          unique index on that column constrains nothing at all.

              encrypt #{inspect(field.name)}, searchable?: true, unique?: true
          """

      field.searchable? and not searchable_type?(attribute.type) and
          field.normalize in [:none, :downcase, :downcase_trim] ->
        raise Spark.Error.DslError,
          module: module,
          path: [:ash_vault, :encrypt],
          message: """
          `searchable?: true` on #{inspect(field.name)} needs a `normalize:` that returns \
          a binary, because #{inspect(attribute.type)} values are not binaries.

          A lookup token is `HMAC-SHA256(key, normalized_plaintext)`, so the normalized
          value has to be bytes. AshVault will not `to_string/1` a struct, a map or a
          number for you: `inspect/1` output is a stable-looking string that would
          quietly become the searchable identity of the row, and two values differing
          only where `inspect/1` truncates would collide.

          Either give it an explicit normalizer:

              encrypt #{inspect(field.name)}, searchable?: true,
                normalize: {MyApp.Normalize, :#{field.name}, []}

          or drop `searchable?: true`. Types searchable without one: \
          #{inspect(@searchable_types)}.
          """

      true ->
        attribute
    end
  end

  # `Ash.CiString` values are structs at runtime, not binaries, so `AshVault.Lookup`
  # unwraps them explicitly. Allowing the type here without that clause there would be
  # a compile-time promise the runtime breaks.
  defp searchable_type?(type), do: Ash.Type.get_type(type) in @searchable_types

  # -- searchable fields ------------------------------------------------------

  defp add_lookup({:error, error}, _field, _attribute), do: {:error, error}

  defp add_lookup({:ok, dsl}, %{searchable?: false}, _attribute), do: {:ok, dsl}

  defp add_lookup({:ok, dsl}, field, attribute) do
    lookup = AshVault.lookup_field_name(field.name)

    dsl
    |> Builder.add_attribute(lookup, :binary,
      allow_nil?: true,
      sensitive?: true,
      public?: false,
      filterable?: true,
      # The token is only ever read by a filter. Leaving it out of the default select
      # keeps a stable, per-scope fingerprint of the plaintext out of every
      # `%Resource{}` struct that reaches a log line, a template or an APM trace.
      #
      # Only where the data layer can actually select, though:
      # `Ash.Resource.Verifiers.VerifySelectedByDefault` *raises* for
      # `select_by_default?: false` on one that cannot, because every attribute is
      # always selected there and Ash refuses to let a resource claim otherwise.
      # `Ash.DataLayer.Ets` is such a layer, so an unconditional option here would make
      # searchable fields a compile error on every ETS-backed resource.
      select_by_default?: not selectable?(dsl),
      description: "Lookup token for #{attribute.name}"
    )
    |> add_lookup_identity(field, lookup)
    |> add_lookup_action(field, attribute)
  end

  # `keys: [:email_lookup]` ONLY.
  #
  # SEARCHABLE_SPEC asks for the tenant attribute to be added to the identity's keys for
  # an attribute-multitenant resource. Ash already does that itself, in both places it
  # matters, whenever `all_tenants?` is false — which is the default:
  #
  #   * the migration generator prepends the multitenancy attribute to the unique index
  #     columns (`deps/ash_postgres/lib/migration_generator/operation.ex:142-148`)
  #   * eager/pre-check runs the uniqueness query with `changeset.tenant`
  #     (`deps/ash/lib/ash/actions/create/create.ex:298-307`,
  #     `deps/ash/lib/ash/changeset/changeset.ex:3288-3305`)
  #
  # Listing the tenant attribute here as well would be redundant in the index (`Enum.uniq`
  # de-dupes it) and actively wrong in the identity's contract: `keys` is what
  # `Ash.get/3` by identity and upsert-by-identity require as *inputs*, so it would make
  # callers pass a tenant id they already pass as the tenant.
  #
  # `nils_distinct?` defaults to true (`deps/ash/lib/ash/resource/identity.ex:50-54`),
  # which is what lets any number of rows hold a nil plaintext — matching Postgres, where
  # NULLs never conflict in a unique index.
  # `select_by_default?: false` means "not selected unless asked for", which a data layer
  # that cannot select attributes cannot honour. Ash's own verifier treats claiming it
  # anyway as a DSL error rather than a no-op.
  defp selectable?(dsl) do
    case Ash.DataLayer.data_layer(dsl) do
      nil -> false
      data_layer -> Ash.DataLayer.can?(data_layer, dsl, :select)
    end
  end

  defp add_lookup_identity({:error, error}, _field, _lookup), do: {:error, error}

  defp add_lookup_identity({:ok, dsl}, %{unique?: false}, _lookup), do: {:ok, dsl}

  defp add_lookup_identity({:ok, dsl}, field, lookup) do
    Builder.add_identity(dsl, :"#{lookup}_unique", [lookup],
      description:
        "Unique #{field.name} (per tenant), enforced on the lookup token rather than " <>
          "on the randomized ciphertext."
    )
  end

  defp add_lookup_action({:error, error}, _field, _attribute), do: {:error, error}

  defp add_lookup_action({:ok, dsl}, field, attribute) do
    name = AshVault.lookup_action_name(field.name)

    if Ash.Resource.Info.action(dsl, name) do
      {:ok, dsl}
    else
      with {:ok, argument} <-
             Builder.build_action_argument(field.name, attribute.type,
               allow_nil?: false,
               constraints: attribute.constraints,
               sensitive?: true,
               description: "The plaintext #{field.name} to look up."
             ),
           {:ok, preparation} <-
             Builder.build_preparation({AshVault.Preparations.FilterByLookup, field: field.name}) do
        Builder.add_action(dsl, :read, name,
          arguments: [argument],
          preparations: [preparation],
          description:
            "Find rows whose #{field.name} equals the given plaintext, by its lookup token."
        )
      end
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
        [returns: :integer],
        "Rotate this scope's AshVault encryption key, returning the new key version."
      )
      |> maybe_add_lifecycle_action(
        AshVault.Info.ash_vault_key_lifecycle_destroy(dsl),
        AshVault.Actions.DestroyKeys,
        [returns: :struct, constraints: [instance_of: AshVault.Erasure]],
        "Crypto-erase this scope: destroy every AshVault key version for it."
      )
      |> normalize()
    else
      {:ok, dsl}
    end
  end

  defp add_key_lifecycle_actions({:error, error}), do: {:error, error}

  defp maybe_add_lifecycle_action(dsl, {:ok, name}, implementation, return_opts, description)
       when is_atom(name) and not is_nil(name) do
    Builder.add_action(
      dsl,
      :action,
      name,
      [run: {implementation, []}, allow_nil?: false, description: description] ++ return_opts
    )
  end

  defp maybe_add_lifecycle_action(dsl, _name, _implementation, _return_opts, _description),
    do: dsl

  defp normalize({:ok, dsl}), do: {:ok, dsl}
  defp normalize({:error, error}), do: {:error, error}
  defp normalize(dsl), do: {:ok, dsl}
end
