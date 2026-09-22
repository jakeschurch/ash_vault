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

  `use Spark.Dsl.Extension` auto-prepends `Spark.Dsl.Verifiers.VerifyEntityUniqueness` and
  `VerifySectionSingletonEntities` to the verifier list, so entity-level uniqueness is
  already covered; the duplicate check here catches sugar/entity collisions.
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
         :ok <- verify_backfill_from(dsl, module) do
      verify_key_lifecycle(dsl, module)
    end
  end

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
