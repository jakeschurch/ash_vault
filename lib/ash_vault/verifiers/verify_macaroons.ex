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
    * warns when a macaroon declares `phase: :authorize` caveats and none of the
      resource's own policies reference `AshVault.Checks.MacaroonAllows` (unless the
      macaroon sets `require_authorize_enforcement? true`)
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
         :ok <- verify_vault(dsl, module, macaroons),
         :ok <-
           Enum.reduce_while(macaroons, :ok, fn definition, :ok ->
             case verify_one(dsl, module, definition) do
               :ok -> {:cont, :ok}
               error -> {:halt, error}
             end
           end) do
      warn_unenforced(dsl, module, macaroons)
    end
  end

  # Authorize-phase caveats are enforced only by `AshVault.Checks.MacaroonAllows`. If the
  # declaring resource's own policies never reference it, the most likely place for a
  # macaroon actor to act is unguarded — say so at compile time. Other resources'
  # policies cannot be seen from here, so silence is not proof of enforcement.
  defp warn_unenforced(dsl, module, macaroons) do
    unenforced =
      for definition <- macaroons,
          Enum.any?(definition.caveats, &(&1.phase == :authorize)),
          not definition.require_authorize_enforcement?,
          do: definition.name

    if unenforced == [] or references_macaroon_allows?(dsl) do
      :ok
    else
      {:warn,
       "#{inspect(module)}: macaroon(s) #{inspect(unenforced)} declare `phase: :authorize` " <>
         "caveats, but no policy on this resource uses AshVault.Checks.MacaroonAllows. " <>
         "Those caveats are enforced only by that check: wherever it is absent, a macaroon " <>
         "actor is not restricted by them. Add the check, or set " <>
         "`require_authorize_enforcement? true` to refuse such tokens unless the caller " <>
         "asserts enforcement."}
    end
  end

  defp references_macaroon_allows?(dsl) do
    dsl
    |> Spark.Dsl.Extension.get_entities([:policies])
    |> mentions?(AshVault.Checks.MacaroonAllows)
  end

  defp mentions?(term, target) when is_atom(term), do: term == target
  defp mentions?(term, target) when is_list(term), do: Enum.any?(term, &mentions?(&1, target))

  defp mentions?(term, target) when is_tuple(term),
    do: term |> Tuple.to_list() |> mentions?(target)

  defp mentions?(%_{} = term, target),
    do: term |> Map.from_struct() |> Map.values() |> mentions?(target)

  defp mentions?(term, target) when is_map(term), do: term |> Map.values() |> mentions?(target)
  defp mentions?(_term, _target), do: false

  defp verify_one(dsl, module, definition) do
    with :ok <- verify_prefix(module, definition),
         :ok <- verify_identity(dsl, module, definition),
         :ok <- verify_scope(dsl, module, definition),
         :ok <- verify_primary_read(dsl, module, definition),
         :ok <- verify_ttl(module, definition),
         :ok <- verify_key_window(module, definition) do
      verify_caveats(module, definition)
    end
  end

  defp verify_ttl(module, definition) do
    case {definition.default_ttl, definition.max_ttl} do
      {{_module, _opts}, max} when max in [nil, :infinity] ->
        error(
          module,
          path(definition, :max_ttl),
          "a function `default_ttl` requires a finite `max_ttl`, so a computed lifetime " <>
            "can never mint a near-permanent token"
        )

      {{ttl_module, _opts}, _max} ->
        verify_callback(module, definition, :default_ttl, ttl_module, :ttl, 2)

      {ttl, max} when is_integer(max) and (ttl == :infinity or ttl > max) ->
        error(module, path(definition, :default_ttl), "`default_ttl` exceeds `max_ttl`")

      _static ->
        :ok
    end
  end

  defp verify_key_window(module, definition) do
    case definition.accepted_key_versions do
      {window_module, function, args} when is_atom(function) and is_list(args) ->
        verify_callback(
          module,
          definition,
          :accepted_key_versions,
          window_module,
          function,
          length(args) + 1
        )

      {window_module, opts} when is_list(opts) ->
        verify_callback(
          module,
          definition,
          :accepted_key_versions,
          window_module,
          :accepted_key_versions,
          2
        )

      _static ->
        :ok
    end
  end

  defp verify_callback(module, definition, key, callback_module, function, arity) do
    if match?({:module, _}, Code.ensure_compiled(callback_module)) and
         function_exported?(callback_module, function, arity) do
      :ok
    else
      error(
        module,
        path(definition, key),
        "#{inspect(callback_module)} is not a compiled module exporting #{function}/#{arity}"
      )
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
