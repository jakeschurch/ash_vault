defmodule AshVault.Macaroon.Runtime do
  @moduledoc """
  Minting and verifying macaroons for a resource's `macaroon` declaration.

  The generated mint action (`AshVault.Macaroon.Actions.Mint`) and the verifying read
  preparation (`AshVault.Macaroon.Preparations.Verify`) are thin wrappers over
  `mint/4` and `verify/4`. Neither function touches the data layer; loading the record a
  token names, and checking its `revoked_when`, is the preparation's job.

  ## Error taxonomy

  `verify/4` returns `{:error, exception}` with exactly one of:

    * `AshVault.Errors.InvalidMacaroon` — the token is wrong (see its `:reason`). Every
      failure before the signature has verified — malformed, unknown version, wrong
      prefix, a scope with no key, a crypto-erased scope, a bad signature — is reported
      as `:bad_signature`, so a forged token learns nothing about which tenants exist or
      were erased. The precise reason is emitted on `[:ash_vault, :macaroon, :rejected]`.
    * `AshVault.Errors.MacaroonRevoked` — `:key_retired` (outside
      `accepted_key_versions`), or `:scope_destroyed` when erasure lands between the
      signature check and the key-window check
    * `AshVault.Errors.ProviderUnavailable` — unchanged from the vault; retry. Never
      turned into "invalid", and never into "valid"
    * a configuration fault from the vault (`PurposeUnsupported`, `KeySizeMismatch`,
      `OpaqueKeyUnsupported`), unchanged

  ## Order of checks

  Everything that can be decided without a key provider is decided first (envelope,
  prefix). The request's own tenant is compared with the token's only after the
  signature verifies. The root signature is then recomputed at the token's stated
  key version — a version-pinned `get_key`, which never mints — and the chain replayed
  and compared in constant time. Only after the signature verifies does anything call
  the current-version lookup (which mints a keyring on first use), so a forged token
  naming an unknown scope cannot make the provider create keys for it.
  """

  require Logger

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

    with {:ok, ttl} <- resolve_ttl(definition, Keyword.get(opts, :ttl), Keyword.get(opts, :input)),
         :ok <- check_mintable(definition, scope, id),
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

  @doc """
  The TTL a token is minted with: `requested` (the `:ttl` argument) when given, else
  `default_ttl` — static, or computed from the mint action `input` — always held to
  `max_ttl`.

  A requested TTL above `max_ttl` is refused (the caller asked for something it may not
  have). A computed one is clamped (the function is policy, `max_ttl` the ceiling). A
  function that raises or returns anything but a positive integer or `:infinity` refuses
  the mint.
  """
  @spec resolve_ttl(Definition.t(), pos_integer() | nil, Ash.ActionInput.t() | nil) ::
          {:ok, pos_integer() | :infinity} | {:error, Exception.t()}
  def resolve_ttl(definition, requested, input) do
    max = definition.max_ttl

    cond do
      is_integer(requested) and exceeds?(requested, max) ->
        {:error, argument_error(:ttl, "exceeds this macaroon's max_ttl of #{max} seconds")}

      is_integer(requested) ->
        {:ok, requested}

      true ->
        with {:ok, ttl} <- default_ttl(definition.default_ttl, input), do: {:ok, clamp(ttl, max)}
    end
  end

  defp default_ttl(ttl, _input) when (is_integer(ttl) and ttl > 0) or ttl == :infinity,
    do: {:ok, ttl}

  defp default_ttl({module, opts}, input) when is_atom(module) do
    case module.ttl(input, opts) do
      ttl when (is_integer(ttl) and ttl > 0) or ttl == :infinity -> {:ok, ttl}
      _other -> {:error, argument_error(:ttl, "default_ttl returned an invalid lifetime")}
    end
  rescue
    _error -> {:error, argument_error(:ttl, "default_ttl raised while computing a lifetime")}
  end

  defp exceeds?(_ttl, max) when max in [nil, :infinity], do: false
  defp exceeds?(ttl, max), do: ttl > max

  defp clamp(ttl, max) when max in [nil, :infinity], do: ttl
  defp clamp(:infinity, max), do: max
  defp clamp(ttl, max), do: min(ttl, max)

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
    case do_verify(resource, definition, token, opts) do
      {:ok, verified} ->
        {:ok, verified}

      {:error, {:pre_signature, reason}} ->
        rejected(resource, definition, reason)
        {:error, invalid(resource, definition, :bad_signature)}

      {:error, %{reason: reason} = error} ->
        rejected(resource, definition, reason)
        {:error, error}

      {:error, error} ->
        {:error, error}
    end
  end

  # Every failure that happens before the signature has verified leaves through one door:
  # `InvalidMacaroon{reason: :bad_signature}`. A forged token is attacker input, so
  # "this tenant has no key", "this tenant was erased", "wrong prefix" and "garbled bytes"
  # must not be distinguishable to it — otherwise forged tokens enumerate tenants and
  # reveal which ones were crypto-erased. The precise reason goes to telemetry only.
  defp do_verify(resource, definition, token, opts) do
    with {:ok, env} <- decode(definition, token),
         {:ok, tenant} <- token_tenant(resource, env),
         ctx = context(resource, definition, tenant, opts),
         vault = AshVault.Info.vault!(resource, ctx.ash_context),
         :ok <- check_resolved_scope(resource, ctx, env),
         :ok <- check_signature(vault, ctx, env),
         :ok <- check_request_tenant(resource, definition, env, Keyword.get(opts, :tenant)),
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

    KeyDestroyed ->
      {:error, {:pre_signature, :scope_destroyed}}

    KeyNotFound ->
      {:error, {:pre_signature, :unknown_key_version}}
  end

  defp rejected(resource, definition, reason) do
    :telemetry.execute([:ash_vault, :macaroon, :rejected], %{count: 1}, %{
      resource: resource,
      macaroon: definition.name,
      reason: reason
    })
  end

  @doc """
  The tenant to run the record load under, for a verified token: the token's scope for a
  `:tenant`-scoped resource, `nil` for a `:global` one.
  """
  @spec tenant_for(module(), Verified.t()) :: binary() | nil
  def tenant_for(resource, %Verified{scope: scope}) do
    if AshVault.Info.scope_module(resource) == AshVault.Scopes.Global, do: nil, else: scope
  end

  defp decode(definition, token) do
    case Envelope.decode(token) do
      {:ok, %Envelope{prefix: prefix} = env} ->
        if prefix == definition.prefix,
          do: {:ok, env},
          else: {:error, {:pre_signature, :wrong_prefix}}

      {:error, reason} ->
        {:error, {:pre_signature, reason}}
    end
  end

  defp token_tenant(resource, env) do
    case AshVault.Info.scope_module(resource) do
      AshVault.Scopes.Global ->
        if env.scope == "global",
          do: {:ok, nil},
          else: {:error, {:pre_signature, :scope_mismatch}}

      _tenant_scope ->
        {:ok, env.scope}
    end
  end

  defp check_resolved_scope(resource, ctx, env) do
    if AshVault.Info.scope_module(resource).resolve!(ctx) == env.scope,
      do: :ok,
      else: {:error, {:pre_signature, :scope_mismatch}}
  end

  # A scope with no key (or a destroyed one) answers from the provider without any MAC
  # being computed, which would make it measurably faster than a real verification. The
  # same local HMAC and chain replay run on that path under a throwaway key, so the
  # in-BEAM work is identical. What remains is documented in the guide: the provider's
  # own latency for a missing key versus a present one, and — under OpenBaoTransit — the
  # `transit/hmac` round trip a real verification makes and this path does not.
  defp check_signature(vault, ctx, env) do
    root = vault.mac_at!(Chain.root_data(env), env.key_version, ctx)

    if Chain.equal?(Chain.extend(root, env.caveats), env.sig),
      do: :ok,
      else: {:error, {:pre_signature, :bad_signature}}
  rescue
    KeyDestroyed ->
      equalize(env)
      {:error, {:pre_signature, :scope_destroyed}}

    KeyNotFound ->
      equalize(env)
      {:error, {:pre_signature, :unknown_key_version}}
  end

  @throwaway_key :crypto.strong_rand_bytes(32)

  defp equalize(env) do
    @throwaway_key
    |> AshVault.Macs.HmacSha256.hmac(AshVault.Mac.frame(Chain.root_data(env), ""))
    |> Chain.extend(env.caveats)
    |> Chain.equal?(env.sig)
  end

  defp check_request_tenant(resource, definition, env, request_tenant) do
    cond do
      AshVault.Info.scope_module(resource) == AshVault.Scopes.Global -> :ok
      is_nil(request_tenant) -> :ok
      AshVault.Scopes.AshTenant.to_scope_key(request_tenant) == env.scope -> :ok
      true -> {:error, invalid(resource, definition, :scope_mismatch)}
    end
  end

  defp check_key_window(resource, definition, vault, ctx, env) do
    case accepted_key_versions(definition, env.scope) do
      :all ->
        :ok

      window ->
        current = vault.mac_key_version!(ctx)

        if env.key_version > current - window,
          do: :ok,
          else: {:error, revoked(resource, definition, :key_retired)}
    end
  rescue
    KeyDestroyed -> {:error, revoked(resource, definition, :scope_destroyed)}
    KeyNotFound -> {:error, invalid(resource, definition, :unknown_key_version)}
  end

  @doc """
  The `accepted_key_versions` window for `scope`: the static value, or the configured
  `AshVault.Macaroon.KeyWindow` / MFA's answer. A dynamic answer that is not a positive
  integer or `:all`, or that raises, **fails closed to `1`** — only the current key
  version verifies — and logs a warning naming the scope by fingerprint only.
  """
  @spec accepted_key_versions(Definition.t(), binary()) :: pos_integer() | :all
  def accepted_key_versions(%Definition{accepted_key_versions: window}, _scope)
      when (is_integer(window) and window > 0) or window == :all,
      do: window

  def accepted_key_versions(%Definition{accepted_key_versions: window} = definition, scope) do
    result =
      case window do
        {module, function, args} -> apply(module, function, [scope | args])
        {module, opts} -> module.accepted_key_versions(scope, opts)
      end

    if (is_integer(result) and result > 0) or result == :all,
      do: result,
      else: window_fallback(definition, scope, {:invalid, result})
  rescue
    error -> window_fallback(definition, scope, {:raised, error.__struct__})
  end

  defp window_fallback(definition, scope, why) do
    Logger.warning(
      "AshVault: accepted_key_versions for macaroon #{inspect(definition.name)} in scope " <>
        "#{AshVault.Scope.fingerprint(scope)} failed (#{inspect(elem(why, 0))}); " <>
        "failing closed to 1"
    )

    1
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
      field: Definition.vault_field(definition),
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
