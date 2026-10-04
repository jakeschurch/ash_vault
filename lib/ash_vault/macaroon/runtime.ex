defmodule AshVault.Macaroon.Runtime do
  @moduledoc """
  Minting and verifying macaroons for a resource's `macaroon` declaration.

  The generated mint action (`AshVault.Macaroon.Actions.Mint`) and the verifying read
  preparation (`AshVault.Macaroon.Preparations.Verify`) are thin wrappers over
  `mint/4` and `verify/4`. Neither function touches the data layer; loading the record a
  token names, and checking its `revoked_when`, is the preparation's job.

  ## Error taxonomy

  `verify/4` returns `{:error, exception}` with exactly one of:

    * `AshVault.Errors.InvalidMacaroon` — the token is wrong (see its `:reason`)
    * `AshVault.Errors.MacaroonRevoked` — `:scope_destroyed` (the vault said
      `KeyDestroyed`) or `:key_retired` (outside `accepted_key_versions`)
    * `AshVault.Errors.ProviderUnavailable` — unchanged from the vault; retry. Never
      turned into "invalid", and never into "valid"
    * a configuration fault from the vault (`PurposeUnsupported`, `KeySizeMismatch`,
      `OpaqueKeyUnsupported`), unchanged

  ## Order of checks

  Everything that can be decided without a key provider is decided first (envelope,
  prefix, scope agreement). The root signature is then recomputed at the token's stated
  key version — a version-pinned `get_key`, which never mints — and the chain replayed
  and compared in constant time. Only after the signature verifies does anything call
  the current-version lookup (which mints a keyring on first use), so a forged token
  naming an unknown scope cannot make the provider create keys for it.
  """

  alias AshVault.Errors.InvalidMacaroon
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.MacaroonRevoked
  alias AshVault.Macaroon.CaveatCodec
  alias AshVault.Macaroon.Chain
  alias AshVault.Macaroon.Definition
  alias AshVault.Macaroon.Envelope
  alias AshVault.Macaroon.Verified

  @expires_at "expires_at"

  @typedoc """
  `:tenant`, `:actor` and `:source_context` describe the request; `:ttl` (mint only)
  overrides `default_ttl`.
  """
  @type opts :: [
          tenant: term(),
          actor: term(),
          source_context: map(),
          ttl: pos_integer() | :infinity
        ]

  @doc """
  Mint a token naming `id` (the record's identity value, already a string) with
  `caveats`, a list of `{name, value}` in declaration order with values already cast.
  """
  @spec mint(module(), Definition.t(), binary(), [{atom(), term()}], opts()) ::
          {:ok, binary()} | {:error, Exception.t()}
  def mint(resource, %Definition{} = definition, id, caveats, opts) do
    ctx = context(resource, definition, Keyword.get(opts, :tenant), opts)
    vault = AshVault.Info.vault!(resource, ctx.ash_context)
    scope = AshVault.Info.scope_module(resource).resolve!(ctx)
    ttl = Keyword.get(opts, :ttl) || definition.default_ttl

    with :ok <- check_mintable(definition, scope, id),
         {:ok, encoded} <- encode_caveats(resource, definition, expiry(ttl) ++ caveats) do
      version = vault.mac_key_version!(ctx)

      token = %Envelope{
        prefix: definition.prefix,
        scope: scope,
        key_version: version,
        id: id,
        caveats: encoded,
        sig: <<0::256>>
      }

      root = vault.mac_at!(Chain.root_data(token), version, ctx)

      Envelope.encode(%{token | sig: Chain.extend(root, encoded)})
      |> case do
        {:ok, string} -> {:ok, string}
        {:error, reason} -> {:error, invalid(resource, definition, reason)}
      end
    end
  rescue
    error in [
      KeyDestroyed,
      KeyNotFound,
      AshVault.Errors.ProviderUnavailable,
      AshVault.Errors.PurposeUnsupported,
      AshVault.Errors.KeySizeMismatch,
      AshVault.Errors.OpaqueKeyUnsupported,
      AshVault.Errors.MissingScope,
      AshVault.Errors.InvalidScope
    ] ->
      {:error, error}
  end

  defp check_mintable(definition, scope, id) do
    cond do
      not Envelope.valid_scope?(scope) ->
        {:error, argument_error(:tenant, "the scope cannot be carried in a macaroon")}

      not (is_binary(id) and byte_size(id) in 1..255) ->
        {:error, argument_error(definition.identity, "identity must encode to 1..255 bytes")}

      true ->
        :ok
    end
  end

  defp expiry(:infinity), do: []

  defp expiry(seconds) when is_integer(seconds) and seconds > 0,
    do: [{:expires_at, DateTime.add(AshVault.Macaroon.Clock.now(), seconds, :second)}]

  defp encode_caveats(resource, definition, caveats) do
    if length(caveats) > Envelope.max_caveats() do
      {:error, argument_error(:caveats, "at most #{Envelope.max_caveats()} caveats")}
    else
      Enum.reduce_while(caveats, {:ok, []}, fn {name, value}, {:ok, acc} ->
        with {:ok, tag} <- declared_tag(definition, name),
             {:ok, bytes} <- CaveatCodec.encode(to_string(name), tag, value) do
          {:cont, {:ok, [bytes | acc]}}
        else
          _ ->
            {:halt,
             {:error,
              argument_error(
                :caveats,
                "caveat #{inspect(name)} is not declared on #{inspect(resource)}, " <>
                  "or its value cannot be encoded"
              )}}
        end
      end)
      |> case do
        {:ok, encoded} -> {:ok, Enum.reverse(encoded)}
        error -> error
      end
    end
  end

  defp declared_tag(_definition, :expires_at), do: {:ok, :datetime}

  defp declared_tag(definition, name) do
    case Enum.find(definition.caveats, &(&1.name == name)) do
      nil -> :error
      caveat -> CaveatCodec.tag_for_type(caveat.type)
    end
  end

  @doc """
  Verify `token` against a macaroon declaration, up to (not including) the record load.

  `opts[:tenant]` is the tenant the request already carries, or `nil`. When present it
  must agree with the token's scope. Returns the `AshVault.Macaroon.Verified` whose
  `:verify`-phase caveats are still to be checked against the loaded record.
  """
  @spec verify(module(), Definition.t(), term(), opts()) ::
          {:ok, Verified.t()} | {:error, Exception.t()}
  def verify(resource, %Definition{} = definition, token, opts) do
    with {:ok, env} <- decode(resource, definition, token),
         {:ok, tenant} <- check_scope(resource, definition, env, Keyword.get(opts, :tenant)),
         ctx = context(resource, definition, tenant, opts),
         vault = AshVault.Info.vault!(resource, ctx.ash_context),
         :ok <- check_resolved_scope(resource, definition, ctx, env),
         :ok <- check_signature(resource, definition, vault, ctx, env),
         :ok <- check_key_window(resource, definition, vault, ctx, env),
         {:ok, caveats} <- decode_caveats(resource, definition, env),
         {:ok, expires_at} <- check_expiry(resource, definition, caveats) do
      {:ok,
       %Verified{
         resource: resource,
         macaroon: definition.name,
         scope: env.scope,
         key_version: env.key_version,
         id: env.id,
         expires_at: expires_at,
         caveats: caveats,
         authorize_caveats: authorize_caveats(definition, caveats)
       }}
    end
  rescue
    error in [
      AshVault.Errors.ProviderUnavailable,
      AshVault.Errors.PurposeUnsupported,
      AshVault.Errors.KeySizeMismatch,
      AshVault.Errors.OpaqueKeyUnsupported,
      AshVault.Errors.MissingScope,
      AshVault.Errors.InvalidScope
    ] ->
      {:error, error}
  end

  @doc """
  The tenant to run the record load under, for a verified token: the token's scope for a
  `:tenant`-scoped resource, `nil` for a `:global` one.
  """
  @spec tenant_for(module(), Verified.t()) :: binary() | nil
  def tenant_for(resource, %Verified{scope: scope}) do
    if AshVault.Info.scope_module(resource) == AshVault.Scopes.Global, do: nil, else: scope
  end

  defp decode(resource, definition, token) do
    case Envelope.decode(token) do
      {:ok, %Envelope{prefix: prefix} = env} ->
        if prefix == definition.prefix,
          do: {:ok, env},
          else: {:error, invalid(resource, definition, :wrong_prefix)}

      {:error, reason} ->
        {:error, invalid(resource, definition, reason)}
    end
  end

  defp check_scope(resource, definition, env, request_tenant) do
    case AshVault.Info.scope_module(resource) do
      AshVault.Scopes.Global ->
        if env.scope == "global",
          do: {:ok, nil},
          else: {:error, invalid(resource, definition, :scope_mismatch)}

      _tenant_scope ->
        cond do
          is_nil(request_tenant) ->
            {:ok, env.scope}

          AshVault.Scopes.AshTenant.to_scope_key(request_tenant) == env.scope ->
            {:ok, env.scope}

          true ->
            {:error, invalid(resource, definition, :scope_mismatch)}
        end
    end
  end

  defp check_resolved_scope(resource, definition, ctx, env) do
    if AshVault.Info.scope_module(resource).resolve!(ctx) == env.scope,
      do: :ok,
      else: {:error, invalid(resource, definition, :scope_mismatch)}
  end

  defp check_signature(resource, definition, vault, ctx, env) do
    root = vault.mac_at!(Chain.root_data(env), env.key_version, ctx)

    if Chain.equal?(Chain.extend(root, env.caveats), env.sig),
      do: :ok,
      else: {:error, invalid(resource, definition, :bad_signature)}
  rescue
    KeyDestroyed -> {:error, revoked(resource, definition, :scope_destroyed)}
    KeyNotFound -> {:error, invalid(resource, definition, :unknown_key_version)}
  end

  defp check_key_window(_resource, %Definition{accepted_key_versions: :all}, _vault, _ctx, _env),
    do: :ok

  defp check_key_window(resource, definition, vault, ctx, env) do
    current = vault.mac_key_version!(ctx)

    if env.key_version > current - definition.accepted_key_versions,
      do: :ok,
      else: {:error, revoked(resource, definition, :key_retired)}
  rescue
    KeyDestroyed -> {:error, revoked(resource, definition, :scope_destroyed)}
  end

  defp decode_caveats(resource, definition, env) do
    declared = Map.new(definition.caveats, &{Atom.to_string(&1.name), &1})

    env.caveats
    |> Enum.reduce_while({:ok, []}, fn bytes, {:ok, acc} ->
      case CaveatCodec.decode(bytes) do
        {:ok, {@expires_at, :datetime, value}} ->
          {:cont, {:ok, [{:expires_at, value} | acc]}}

        {:ok, {@expires_at, _tag, _value}} ->
          {:halt, {:error, invalid(resource, definition, :caveat_type)}}

        {:ok, {name, tag, value}} ->
          case Map.fetch(declared, name) do
            {:ok, caveat} ->
              if CaveatCodec.tag_for_type(caveat.type) == {:ok, tag},
                do: {:cont, {:ok, [{caveat.name, value} | acc]}},
                else: {:halt, {:error, invalid(resource, definition, :caveat_type)}}

            :error ->
              {:halt, {:error, invalid(resource, definition, :unknown_caveat)}}
          end

        :error ->
          {:halt, {:error, invalid(resource, definition, :malformed)}}
      end
    end)
    |> case do
      {:ok, caveats} -> {:ok, Enum.reverse(caveats)}
      error -> error
    end
  end

  defp check_expiry(resource, definition, caveats) do
    now = AshVault.Macaroon.Clock.now()

    expiries = for {:expires_at, at} <- caveats, do: at

    if Enum.all?(expiries, &(DateTime.compare(now, &1) == :lt)),
      do: {:ok, Enum.min(expiries, DateTime, fn -> nil end)},
      else: {:error, invalid(resource, definition, :expired)}
  end

  defp authorize_caveats(definition, caveats) do
    phases = Map.new(definition.caveats, &{&1.name, &1.phase})
    Enum.filter(caveats, fn {name, _value} -> Map.get(phases, name) == :authorize end)
  end

  @doc """
  Run `phase` caveat checks for a verified token. Returns `:ok` or an
  `AshVault.Errors.InvalidMacaroon` naming the first caveat that refused.
  """
  @spec check_caveats(
          module(),
          Definition.t(),
          [{atom(), term()}],
          :verify | :authorize,
          AshVault.Macaroon.CheckContext.t()
        ) :: :ok | {:error, Exception.t()}
  def check_caveats(resource, definition, caveats, phase, check_context) do
    declared = Map.new(definition.caveats, &{&1.name, &1})

    Enum.reduce_while(caveats, :ok, fn
      {:expires_at, _value}, :ok ->
        {:cont, :ok}

      {name, value}, :ok ->
        case Map.fetch(declared, name) do
          {:ok, %{phase: ^phase, check: check}} ->
            if AshVault.Macaroon.Caveat.admits?(check, value, check_context),
              do: {:cont, :ok},
              else: {:halt, {:error, invalid(resource, definition, {:caveat_failed, name})}}

          {:ok, _other_phase} ->
            {:cont, :ok}

          :error ->
            {:halt, {:error, invalid(resource, definition, :unknown_caveat)}}
        end
    end)
  end

  @doc "Encode an identity value as the token's `id` bytes."
  @spec encode_id(term()) :: {:ok, binary()} | :error
  def encode_id(value) when is_binary(value), do: {:ok, value}
  def encode_id(value) when is_integer(value), do: {:ok, Integer.to_string(value)}
  def encode_id(%Ash.CiString{} = value), do: {:ok, Ash.CiString.value(value)}
  def encode_id(_value), do: :error

  @doc "The attribute a macaroon's `identity` resolves to, or `nil`."
  @spec identity_attribute(module() | Spark.Dsl.t(), Definition.t()) ::
          Ash.Resource.Attribute.t() | nil
  def identity_attribute(resource, %Definition{identity: identity}) do
    case Ash.Resource.Info.identity(resource, identity) do
      %{keys: [key]} ->
        Ash.Resource.Info.attribute(resource, key)

      %{keys: _many} ->
        nil

      nil ->
        case {Ash.Resource.Info.primary_key(resource),
              Ash.Resource.Info.attribute(resource, identity)} do
          {[^identity], attribute} -> attribute
          _other -> nil
        end
    end
  end

  defp context(resource, definition, tenant, opts) do
    %AshVault.Context{
      resource: resource,
      field: definition.name,
      ash_context: %{
        tenant: tenant,
        actor: Keyword.get(opts, :actor),
        source_context: Keyword.get(opts, :source_context) || %{},
        phase: :read
      }
    }
  end

  @doc false
  @spec invalid(module(), Definition.t(), term()) :: Exception.t()
  def invalid(resource, definition, reason),
    do: InvalidMacaroon.exception(resource: resource, macaroon: definition.name, reason: reason)

  @doc false
  @spec revoked(module(), Definition.t(), atom()) :: Exception.t()
  def revoked(resource, definition, reason),
    do: MacaroonRevoked.exception(resource: resource, macaroon: definition.name, reason: reason)

  defp argument_error(field, message),
    do: Ash.Error.Action.InvalidArgument.exception(field: field, message: message)
end
