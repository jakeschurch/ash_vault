defmodule AshVault.Verifiers.VerifyMacaroons do
  @moduledoc """
  Post-compile checks on every `macaroon` in the `ash_vault` section:

    * `prefix` is 2-32 characters of `[a-z][a-z0-9]*` (no `_`: it separates the prefix
      from the payload) and unique among the resource's macaroons
    * `identity` names the single primary key attribute or a one-key identity — so it is
      unique — of a type a token can carry (string, ci_string, UUID, integer)
    * the scope is resolvable from a token: `:global`, or `:tenant` on a resource with
      multitenancy. A custom `AshVault.Scope` cannot be inverted from a token's scope
      back to a tenant, so it is refused
    * the vault (a plain module) exports `mac_at!/3` and `mac_key_version!/1`, and its key
      provider serves the `:mac` purpose
    * the resource has a primary read action, which the mint action loads through
    * every caveat has a type with a stable encoding (`AshVault.Macaroon.CaveatCodec`), a
      name other than the reserved `:expires_at`, and a check module that is compiled
      and exports `check/3`
  """

  use Spark.Dsl.Verifier

  alias AshVault.Macaroon.CaveatCodec
  alias AshVault.Macaroon.Envelope
  alias Spark.Dsl.Verifier

  @identity_types [
    Ash.Type.String,
    Ash.Type.CiString,
    Ash.Type.UUID,
    Ash.Type.UUIDv7,
    Ash.Type.Integer
  ]

  @doc false
  @impl Spark.Dsl.Verifier
  def verify(dsl) do
    module = Verifier.get_persisted(dsl, :module)
    macaroons = AshVault.Info.macaroons(dsl)

    with :ok <- verify_unique_prefixes(module, macaroons),
         :ok <- verify_vault(dsl, module, macaroons) do
      Enum.reduce_while(macaroons, :ok, fn definition, :ok ->
        case verify_one(dsl, module, definition) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    end
  end

  defp verify_one(dsl, module, definition) do
    with :ok <- verify_prefix(module, definition),
         :ok <- verify_identity(dsl, module, definition),
         :ok <- verify_scope(dsl, module, definition),
         :ok <- verify_primary_read(dsl, module, definition) do
      verify_caveats(module, definition)
    end
  end

  defp verify_primary_read(dsl, module, definition) do
    if Ash.Resource.Info.primary_action(dsl, :read) do
      :ok
    else
      error(
        module,
        path(definition, :identity),
        "the mint action loads the record through the primary read action, and this " <>
          "resource has none. Mark a read action `primary? true`."
      )
    end
  end

  defp verify_unique_prefixes(module, macaroons) do
    case macaroons |> Enum.frequencies_by(& &1.prefix) |> Enum.find(fn {_, n} -> n > 1 end) do
      nil ->
        :ok

      {prefix, _} ->
        error(module, [:ash_vault, :macaroon], "prefix #{inspect(prefix)} is used twice")
    end
  end

  defp verify_prefix(module, definition) do
    if Envelope.valid_prefix?(definition.prefix) do
      :ok
    else
      error(
        module,
        path(definition, :prefix),
        "prefix must be 2-32 characters of [a-z][a-z0-9]* (no underscore: `_` separates " <>
          "the prefix from the payload), got: #{inspect(definition.prefix)}"
      )
    end
  end

  defp verify_identity(dsl, module, definition) do
    case AshVault.Macaroon.Runtime.identity_attribute(dsl, definition) do
      nil ->
        error(
          module,
          path(definition, :identity),
          "`identity #{inspect(definition.identity)}` must name the single primary key " <>
            "attribute or an identity with exactly one key"
        )

      attribute ->
        if Ash.Type.get_type(attribute.type) in @identity_types do
          :ok
        else
          error(
            module,
            path(definition, :identity),
            "identity attribute #{inspect(attribute.name)} has type #{inspect(attribute.type)}; " <>
              "a token can carry #{inspect(@identity_types)}"
          )
        end
    end
  end

  defp verify_scope(dsl, module, definition) do
    case AshVault.Info.scope_module(dsl) do
      AshVault.Scopes.Global ->
        :ok

      AshVault.Scopes.AshTenant ->
        if Ash.Resource.Info.multitenancy_strategy(dsl) do
          :ok
        else
          error(
            module,
            path(definition, :identity),
            "a `scope :tenant` macaroon needs multitenancy on the resource, so a token's " <>
              "scope can be set as the tenant of the record load. Configure " <>
              "`multitenancy`, or use `scope :global`."
          )
        end

      custom ->
        error(
          module,
          [:ash_vault, :scope],
          "macaroons support `scope :tenant` and `scope :global`; #{inspect(custom)} cannot " <>
            "be inverted from a token's scope back to a tenant"
        )
    end
  end

  defp verify_vault(_dsl, _module, []), do: :ok

  defp verify_vault(dsl, module, _macaroons) do
    with vault when is_atom(vault) and not is_nil(vault) <- AshVault.Info.ash_vault_vault!(dsl),
         {:module, ^vault} <- Code.ensure_compiled(vault) do
      cond do
        not (function_exported?(vault, :mac_at!, 3) and
                 function_exported?(vault, :mac_key_version!, 1)) ->
          error(
            module,
            [:ash_vault, :vault],
            "#{inspect(vault)} does not export mac_at!/3 and mac_key_version!/1, which " <>
              "macaroons need. Vaults built with `use AshVault.Vault` have both."
          )

        function_exported?(vault, :__ash_vault__, 1) and
            not AshVault.KeyProvider.supports_purpose?(vault.__ash_vault__(:key_provider), :mac) ->
          error(
            module,
            [:ash_vault, :vault],
            "#{inspect(vault)}'s key provider cannot serve :mac keys, which macaroons are " <>
              "signed with. See \"Key purposes and MACs\"."
          )

        true ->
          :ok
      end
    else
      _dynamic_or_uncompiled -> :ok
    end
  end

  defp verify_caveats(module, definition) do
    Enum.reduce_while(definition.caveats, :ok, fn caveat, :ok ->
      case verify_caveat(module, definition, caveat) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp verify_caveat(module, definition, caveat) do
    {check, _opts} = caveat.check

    cond do
      caveat.name == :expires_at ->
        error(module, path(definition, :caveat), "`:expires_at` is reserved; use `default_ttl`")

      CaveatCodec.tag_for_type(caveat.type) == :error ->
        error(
          module,
          path(definition, :caveat),
          "caveat #{inspect(caveat.name)} has type #{inspect(caveat.type)}, which has no " <>
            "stable token encoding. Use :string, :integer, :boolean, :utc_datetime, " <>
            ":utc_datetime_usec, {:array, :string} or {:array, :integer}."
        )

      not (match?({:module, _}, Code.ensure_compiled(check)) and
               function_exported?(check, :check, 3)) ->
        error(
          module,
          path(definition, :caveat),
          "caveat #{inspect(caveat.name)}'s check #{inspect(check)} is not a compiled " <>
            "module exporting check/3 (`AshVault.Macaroon.Caveat`)"
        )

      true ->
        :ok
    end
  end

  defp path(definition, key), do: [:ash_vault, :macaroon, definition.name, key]

  defp error(module, path, message),
    do: {:error, Spark.Error.DslError.exception(module: module, path: path, message: message)}
end
