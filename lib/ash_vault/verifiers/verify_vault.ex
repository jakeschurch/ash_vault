defmodule AshVault.Verifiers.VerifyVault do
  @moduledoc """
  Post-compile checks on the `ash_vault` section.

  Verifiers run after the resource module is compiled, so cross-module checks — such as
  "does the configured vault actually implement the callbacks?" — cost no compile-time
  dependency on the vault.

  Checks:

    * a plain-module `vault` exports `encrypt!/2`, `decrypt!/2`, `rotate!/1` and
      `destroy!/1` (the `fun/2` and MFA forms are resolved at runtime, so they are
      skipped)
    * the resource's key `scope` agrees with the vault's own scope module. The *effective*
      encryption scope is the vault's — `AshVault.Vault.Runtime` resolves it from the
      vault's `:scope` option — while the resource's `scope` is what the `key_lifecycle`
      actions rotate and destroy. Letting the two disagree would act on a different scope
      than the one the data was encrypted under.

      This is deliberately stricter than EXTENSION_SPEC §1: spark materializes schema
      defaults into the DSL state, so `Spark.Dsl.Extension.fetch_opt/3` cannot tell a
      written `scope :tenant` from the default one. Rather than let a silent mismatch
      through, AshVault requires a resource to **restate** a non-default scope. Both
      defaults are `AshVault.Scopes.AshTenant`, so the common case never trips; a vault
      built with `scope: MyApp.CustomScope` needs `scope MyApp.CustomScope` on the
      resource too.
    * `decrypt_by_default` names only encrypted fields
    * `backfill_from` names an attribute that still exists
    * `key_lifecycle` is only configured on a `scope_owner? true` resource
    * no duplicate `encrypt` entries
    * nothing else on the resource still points at the plaintext attribute in a way that
      the encrypted form cannot honour — see `Constructs an encrypted attribute voids`
      below

  `use Spark.Dsl.Extension` auto-prepends `Spark.Dsl.Verifiers.VerifyEntityUniqueness` and
  `VerifySectionSingletonEntities` to the verifier list, so entity-level uniqueness is
  already covered; the duplicate check here catches sugar/entity collisions.

  ## Constructs an encrypted attribute voids

  `AshVault.Transformers.SetupEncryption` *removes* the plaintext attribute and replaces
  it with a `filterable?: false, sortable?: false` calculation. Anything elsewhere on the
  resource that was declared against that attribute is therefore now declared against
  something that is not a column, and most of those constructs fail **silently** rather
  than loudly.

  Ash and AshPostgres already catch most of them, and this verifier deliberately does not
  duplicate their errors:

    * a relationship's `source_attribute` —
      `deps/ash/lib/ash/resource/verifiers/validate_relationship_attributes.ex:33-40`
      raises "expects source attribute `email` to be defined"; the other side is caught on
      the other resource at `:75-83` of the same file.
    * the multitenancy attribute —
      `deps/ash/lib/ash/resource/verifiers/validate_multitenancy.ex:57-66` raises
      "Attribute email used in multitenancy configuration does not exist".
    * a `postgres` `check_constraints` entry —
      `deps/ash_postgres/lib/verifiers/validate_check_constraints.ex:17-30` raises.

  Two do not, and this verifier covers them:

    * **an identity whose `keys` include the encrypted field.** Ash's own
      `deps/ash/lib/ash/resource/verifiers/verify_identities.ex:16` accepts a key that is
      *either* an attribute *or* a calculation — and the encrypted field is now exactly
      that, a calculation. So `identity :unique_email, [:email]` compiles with no
      complaint whatsoever on a Postgres-backed resource, the migration generator has no
      column to index, and duplicates start landing while the developer believes the
      field is unique. (ETS-backed resources happen to fail via
      `Ash.DataLayer.Verifiers.RequirePreCheckWith`, but that is an ETS-only accident:
      Postgres enforces identities with a real index and needs no pre-check, so the
      realistic configuration is the unguarded one.)

    * **a `postgres` `custom_indexes` entry naming the encrypted field.** Nothing in
      AshPostgres validates those field names — `AshPostgres.DataLayer.Info.custom_indexes/1`
      hands them straight to the migration generator — so the index is generated against
      a column that does not exist.
  """

  use Spark.Dsl.Verifier

  alias Spark.Dsl.Verifier

  @required_callbacks [encrypt!: 2, decrypt!: 2, rotate!: 1, destroy!: 1]

  @doc false
  @impl Spark.Dsl.Verifier
  def verify(dsl) do
    module = Verifier.get_persisted(dsl, :module)

    with :ok <- verify_vault(dsl, module),
         :ok <- verify_scope_agreement(dsl, module),
         :ok <- verify_no_duplicates(dsl, module),
         :ok <- verify_decrypt_by_default(dsl, module),
         :ok <- verify_backfill_from(dsl, module),
         :ok <- verify_searchable(dsl, module),
         :ok <- verify_no_plaintext_identity(dsl, module),
         :ok <- verify_no_plaintext_custom_index(dsl, module) do
      verify_key_lifecycle(dsl, module)
    end
  end

  # A `searchable?: true` field needs a lookup key, and a provider is free not to have
  # one — `c:AshVault.KeyProvider.lookup_key/1` is optional. Catching that here names the
  # provider at compile time instead of failing on the first login attempt in production.
  #
  # `AshVault.KeyProvider.supports_lookup?/1` fails OPEN for a provider that is not
  # compiled yet, matching `verify_vault/2`'s treatment of an uncompiled vault: a
  # compile-order-dependent DSL error would be worse than the clean
  # `AshVault.Errors.LookupUnsupported` the runtime raises in the same situation.
  defp verify_searchable(dsl, module) do
    searchable = AshVault.Info.searchable_fields(dsl)

    with [_ | _] <- searchable,
         vault when is_atom(vault) and not is_nil(vault) <- AshVault.Info.ash_vault_vault!(dsl),
         {:module, ^vault} <- Code.ensure_compiled(vault),
         true <- function_exported?(vault, :__ash_vault__, 1),
         provider = vault.__ash_vault__(:key_provider),
         false <- AshVault.KeyProvider.supports_lookup?(provider) do
      error(
        module,
        [:ash_vault, :encrypt],
        """
        #{inspect(provider)} does not implement `AshVault.KeyProvider.lookup_key/1`, so \
        #{inspect(Enum.map(searchable, & &1.name))} cannot be `searchable?: true`.

        A lookup token is an HMAC under a **separate, non-rotating, per-scope** secret —
        never the encryption key, and never derived from it. Deriving it from the key
        `current_key/1` serves would make every stored token stop matching the moment the
        scope is rotated, with nothing raised anywhere: existing rows become unfindable,
        `unique?` stops preventing duplicates, and users cannot log in.

        Implement the optional callback on #{inspect(provider)}:

            @impl AshVault.KeyProvider
            def lookup_key(scope) do
              # minted once per scope; `rotate/1` never changes it,
              # `destroy/1` erases it along with everything else
            end

        `AshVault.KeyProviders.Memory`, `AshVault.KeyProviders.Local` and
        `AshVault.KeyProviders.OpenBao` all implement it.
        """
      )
    else
      _ok -> :ok
    end
  end

  # Ash's own identity verifier accepts a calculation as an identity key
  # (deps/ash/lib/ash/resource/verifiers/verify_identities.ex:16), and the encrypted
  # field is a calculation by the time it runs — so `identity :unique_email, [:email]`
  # sails through while enforcing nothing at all.
  #
  # The identity `AshVault.Transformers.SetupEncryption` generates for `unique?: true` is
  # keyed on `<field>_lookup`, never on `<field>`, so it cannot trip this check.
  defp verify_no_plaintext_identity(dsl, module) do
    encrypted = AshVault.Info.encrypted_field_names(dsl)

    dsl
    |> Ash.Resource.Info.identities()
    |> Enum.find_value(fn identity ->
      case Enum.filter(identity.keys, &(&1 in encrypted)) do
        [] -> nil
        keys -> {identity, keys}
      end
    end)
    |> case do
      nil ->
        :ok

      {identity, keys} ->
        error(
          module,
          [:identities, identity.name],
          """
          `identity #{inspect(identity.name)}, #{inspect(identity.keys)}` is keyed on \
          #{inspect(keys)}, which #{plural(keys, "is an encrypted field", "are encrypted fields")}.

          That identity enforces nothing. `encrypt` removes the plaintext attribute
          entirely, so there is no column for a unique index to cover, and AES-GCM draws a
          fresh nonce per write — two rows holding the same plaintext have completely
          different ciphertext bytes. Ash accepts the identity anyway, because the
          encrypted field is now a *calculation* and calculations are legal identity keys
          (deps/ash/lib/ash/resource/verifiers/verify_identities.ex:16). Nothing raises,
          nothing is enforced, and duplicates land silently.

          Uniqueness on an encrypted field is enforced on its deterministic lookup token:

              ash_vault do
                encrypt #{inspect(hd(keys))}, searchable?: true, unique?: true
              end

          which generates the `#{AshVault.lookup_field_name(hd(keys))}` column and an
          identity named `:#{AshVault.lookup_field_name(hd(keys))}_unique` on it. Read
          `AshVault.Lookup` first: a token publishes the equality relation on that column
          into every backup you will ever take.

          Then delete `identity #{inspect(identity.name)}`.
          """
        )
    end
  end

  # Nothing in AshPostgres validates `custom_indexes` field names, so an index on a
  # removed column is generated into a migration that cannot run. `check_constraints`
  # *are* validated (deps/ash_postgres/lib/verifiers/validate_check_constraints.ex:17-30),
  # which is why only this one is covered here.
  defp verify_no_plaintext_custom_index(dsl, module) do
    encrypted = AshVault.Info.encrypted_field_names(dsl)

    # `apply/3` rather than a direct call: ash_postgres is a dev/test dependency of
    # AshVault, so a compile-time reference to it would warn in any application that
    # uses a different data layer.
    with true <- Code.ensure_loaded?(AshPostgres.DataLayer.Info),
         AshPostgres.DataLayer <- Ash.DataLayer.data_layer(dsl),
         {index, [_ | _] = fields} <- offending_custom_index(dsl, encrypted) do
      error(
        module,
        [:postgres, :custom_indexes],
        """
        The custom index on #{inspect(index.fields)} names #{inspect(fields)}, which \
        #{plural(fields, "is an encrypted field", "are encrypted fields")}.

        `encrypt` removes the plaintext attribute, so there is no such column to index: \
        the migration generator emits \
        `CREATE INDEX ... (#{Enum.map_join(fields, ", ", &to_string/1)})` against a table \
        that does not have #{plural(fields, "it", "them")}.

        An index on the `encrypted_` column instead would be useless anyway. AES-GCM \
        draws a fresh nonce per write, so equal plaintexts are unequal bytes.

        The indexable column is the deterministic lookup token:

            ash_vault do
              encrypt #{inspect(hd(fields))}, searchable?: true
            end

        which generates `#{AshVault.lookup_field_name(hd(fields))}`. Index that, or add
        `unique?: true` and let AshVault generate the unique identity for you.
        """
      )
    else
      _no_offence -> :ok
    end
  end

  defp offending_custom_index(dsl, encrypted) do
    AshPostgres.DataLayer.Info
    |> apply(:custom_indexes, [dsl])
    |> Enum.find_value(fn index ->
      fields =
        index.fields
        |> List.wrap()
        |> Enum.map(&to_field_name/1)
        |> Enum.filter(&(&1 in encrypted))

      if fields == [], do: nil, else: {index, fields}
    end)
  end

  # `custom_indexes` accepts atoms, strings and expression fragments. Only the first two
  # can name an attribute; anything else is left alone rather than guessed at.
  defp to_field_name(field) when is_atom(field), do: field

  defp to_field_name(field) when is_binary(field) do
    String.to_existing_atom(field)
  rescue
    ArgumentError -> nil
  end

  defp to_field_name(_field), do: nil

  defp plural([_one], singular, _plural), do: singular
  defp plural(_many, _singular, plural), do: plural

  defp verify_vault(dsl, module) do
    case AshVault.Info.ash_vault_vault!(dsl) do
      vault when is_atom(vault) and not is_nil(vault) ->
        case Code.ensure_compiled(vault) do
          {:module, ^vault} ->
            missing =
              Enum.reject(@required_callbacks, fn {fun, arity} ->
                function_exported?(vault, fun, arity)
              end)

            if missing == [] do
              :ok
            else
              error(
                module,
                [:ash_vault, :vault],
                "#{inspect(vault)} is not an AshVault vault: it does not export " <>
                  Enum.map_join(missing, ", ", fn {f, a} -> "#{f}/#{a}" end) <>
                  ".\n\nDefine it with `use AshVault.Vault, key_provider: ...`."
              )
            end

          _other ->
            # The vault is not compiled (yet). Nothing to check without forcing a
            # compile-time dependency, so accept it.
            :ok
        end

      _fun_or_mfa ->
        :ok
    end
  end

  defp verify_scope_agreement(dsl, module) do
    with vault when is_atom(vault) and not is_nil(vault) <- AshVault.Info.ash_vault_vault!(dsl),
         {:module, ^vault} <- Code.ensure_compiled(vault),
         true <- function_exported?(vault, :__ash_vault__, 1) do
      resource_scope = AshVault.Info.scope_module(dsl)
      vault_scope = vault.__ash_vault__(:scope)

      if resource_scope == vault_scope do
        :ok
      else
        error(
          module,
          [:ash_vault, :scope],
          """
          This resource's key scope is #{inspect(resource_scope)} but #{inspect(vault)} \
          encrypts with #{inspect(vault_scope)}.

          The vault resolves the scope every value is actually encrypted under, while the
          resource's `scope` is what the `key_lifecycle` actions rotate and destroy. If the
          two disagree, rotation and cryptographic erasure act on the wrong keys.

          Either set `scope` to match the vault, or point at a vault built with
          `use AshVault.Vault, scope: #{inspect(resource_scope)}`.
          """
        )
      end
    else
      _not_checkable -> :ok
    end
  end

  defp verify_no_duplicates(dsl, module) do
    duplicates =
      dsl
      |> AshVault.Info.encrypted_field_names()
      |> Enum.frequencies()
      |> Enum.filter(fn {_name, count} -> count > 1 end)
      |> Enum.map(&elem(&1, 0))

    if duplicates == [] do
      :ok
    else
      error(
        module,
        [:ash_vault, :encrypt],
        "duplicate `encrypt` entries for #{inspect(duplicates)}"
      )
    end
  end

  defp verify_decrypt_by_default(dsl, module) do
    encrypted = AshVault.Info.encrypted_field_names(dsl)

    case Enum.reject(AshVault.Info.ash_vault_decrypt_by_default!(dsl), &(&1 in encrypted)) do
      [] ->
        :ok

      unknown ->
        error(
          module,
          [:ash_vault, :decrypt_by_default],
          "#{inspect(unknown)} is not an encrypted field. " <>
            "Encrypted fields are #{inspect(encrypted)}."
        )
    end
  end

  defp verify_backfill_from(dsl, module) do
    dsl
    |> AshVault.Info.encrypted_fields()
    |> Enum.reject(&is_nil(&1.backfill_from))
    |> Enum.reduce_while(:ok, fn field, :ok ->
      if Ash.Resource.Info.attribute(dsl, field.backfill_from) do
        {:cont, :ok}
      else
        {:halt,
         error(
           module,
           [:ash_vault, :encrypt],
           "`backfill_from: #{inspect(field.backfill_from)}` on #{inspect(field.name)} " <>
             "does not name an existing attribute."
         )}
      end
    end)
  end

  defp verify_key_lifecycle(dsl, module) do
    configured? =
      match?({:ok, name} when not is_nil(name), AshVault.Info.ash_vault_key_lifecycle_rotate(dsl)) or
        match?(
          {:ok, name} when not is_nil(name),
          AshVault.Info.ash_vault_key_lifecycle_destroy(dsl)
        )

    if configured? and not AshVault.Info.ash_vault_scope_owner?(dsl) do
      error(
        module,
        [:ash_vault, :key_lifecycle],
        """
        `key_lifecycle` requires `scope_owner? true`.

        Key rotation and cryptographic erasure act on a whole key scope, so they belong on
        the resource that *owns* the scope — your tenant or organization — not on every
        resource that happens to have encrypted fields.
        """
      )
    else
      :ok
    end
  end

  defp error(module, path, message) do
    {:error, Spark.Error.DslError.exception(module: module, path: path, message: message)}
  end
end
