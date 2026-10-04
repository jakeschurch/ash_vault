defmodule AshVault.Vault.Runtime do
  @moduledoc """
  The implementation behind every module that `use`s `AshVault.Vault`.

  Generated vault modules are one-line delegations into this module, passing their
  compile-time configuration as an opts map. Keeping the logic here (rather than in the
  `use` macro) keeps generated code tiny, stack traces readable, and this code testable
  on its own.

  All functions here take `opts`, a map with the `:key_provider`, `:cipher`, `:envelope`,
  `:scope` and `:rotation_policy` modules, and — for `mac!/3` and `verify_mac!/5` — the
  `:mac` module. `:vault`, when present, labels telemetry.
  """

  require Logger

  alias AshVault.Cipher
  alias AshVault.Context
  alias AshVault.Envelope
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.InvalidMac
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.InvalidScope
  alias AshVault.Errors.KeyNotFound
  alias AshVault.Errors.KeySizeMismatch
  alias AshVault.Errors.MissingScope
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Errors.PurposeUnsupported
  alias AshVault.KeyProvider
  alias AshVault.RotationPolicy

  @type opts :: %{
          required(:key_provider) => module(),
          required(:cipher) => module(),
          required(:envelope) => module(),
          required(:scope) => module(),
          required(:rotation_policy) => module(),
          optional(:mac) => module(),
          optional(:vault) => module()
        }

  @doc """
  Encrypt `plaintext` for the given context, returning an encoded envelope.

  Raises `AshVault.Errors.MissingScope` if the scope cannot be resolved, and
  `AshVault.Errors.ProviderUnavailable` / `AshVault.Errors.KeyDestroyed` if the key
  provider cannot supply a current key.
  """
  @spec encrypt!(binary(), Context.t(), opts()) :: binary()
  def encrypt!(plaintext, %Context{} = ctx, opts) when is_binary(plaintext) do
    scope = resolve_scope!(ctx, opts.scope, :encrypt)
    key_info = current_key!(opts.key_provider, scope, ctx)
    key_info = maybe_rotate(key_info, scope, ctx, opts)

    aad = build_aad(scope, ctx)

    case opts.cipher.encrypt(plaintext, key_info.key, aad) do
      {:ok, payload} ->
        opts.envelope.encode(%{
          version: opts.envelope.version(),
          cipher: opts.cipher.id(),
          key_version: key_info.version,
          nonce: payload.nonce,
          tag: payload.tag,
          ciphertext: payload.ciphertext
        })

      # A key of the wrong size is a configuration fault. Reporting it as
      # `ProviderUnavailable` named the CIPHER as the "provider" and told the operator
      # to retry a permanent misconfiguration forever.
      {:error, {:invalid_key_size, actual}} ->
        raise key_size_mismatch(opts, actual)

      # Same reasoning, one step further out: the provider hands out opaque key handles
      # and this cipher cannot use one. Permanent, and nothing to do with tampering.
      {:error, :opaque_key_unsupported} ->
        raise opaque_key_unsupported(opts, opts.cipher, ctx, :encrypt)

      # A network-backed cipher already knows who was unavailable and why; re-wrapping it
      # would re-attribute the outage to the cipher module.
      {:error, %ProviderUnavailable{} = error} ->
        raise error

      {:error, reason} ->
        raise ProviderUnavailable.exception(provider: opts.cipher, reason: reason)
    end
  end

  defp opaque_key_unsupported(opts, cipher, ctx, operation) do
    AshVault.Errors.OpaqueKeyUnsupported.exception(
      cipher: cipher,
      provider: opts.key_provider,
      resource: ctx.resource,
      field: ctx.field,
      operation: operation
    )
  end

  defp key_size_mismatch(opts, actual, cipher \\ nil) do
    cipher = cipher || opts.cipher

    KeySizeMismatch.exception(
      provider: opts.key_provider,
      cipher: cipher,
      expected: cipher.key_bytes(),
      actual: actual
    )
  end

  @doc """
  Resolve `scope_module` against `ctx`, enforcing the scope invariant.

  One place enforces it, so a custom `AshVault.Scope` that returns a non-binary fails
  here with a clear message rather than differently in each provider — a provider's own
  `validate_scope!/1` would raise a bare `ArgumentError` naming the provider, which tells
  an operator nothing about the scope module that actually produced the bad term.

  Public because the lookup-token path (`AshVault.Lookup.field_key/3`) resolves a scope
  outside `encrypt!/3` and `decrypt!/3` and must reach the same check.

  Raises `AshVault.Errors.InvalidScope` for a non-binary, and re-raises
  `AshVault.Errors.MissingScope` tagged with `operation`.
  """
  @spec resolve_scope!(Context.t(), module(), atom()) :: binary()
  def resolve_scope!(%Context{} = ctx, scope_module, operation) do
    scope =
      try do
        scope_module.resolve!(ctx)
      rescue
        error in [MissingScope] ->
          reraise %{error | operation: operation}, __STACKTRACE__
      end

    if is_binary(scope) do
      scope
    else
      # A description, never the term. `structs: false` used to render a loaded tenant
      # record as a bare map with every field in it — name, email, billing address — into
      # an error that Ash then logs and ships to APM. The diagnosis needs the shape only:
      # "you returned a struct, not a binary".
      raise InvalidScope.exception(
              scope_module: scope_module,
              scope: AshVault.Scope.describe(scope),
              resource: ctx.resource,
              field: ctx.field
            )
    end
  end

  @doc """
  Decrypt an encoded envelope for the given context, returning the plaintext.

  The cipher is resolved from the envelope, not from the vault's configured default, so
  values keep decrypting after the default cipher changes.

  Raises `AshVault.Errors.InvalidCiphertext` or `AshVault.Errors.UnsupportedEnvelope` for
  unparseable input, `AshVault.Errors.KeyDestroyed` for crypto-erased scopes,
  `AshVault.Errors.KeyNotFound` for unknown key versions, and
  `AshVault.Errors.CiphertextIntegrityFailed` when the tag does not verify.
  """
  @spec decrypt!(binary(), Context.t(), opts()) :: binary()
  def decrypt!(blob, %Context{} = ctx, opts) do
    env =
      case Envelope.decode(blob) do
        {:ok, env} -> env
        {:error, error} -> raise error
      end

    cipher_mod =
      case Cipher.fetch(env.cipher) do
        {:ok, module} -> module
        {:error, error} -> raise error
      end

    scope = resolve_scope!(ctx, opts.scope, :decrypt)
    key = get_key!(opts.key_provider, scope, env.key_version, ctx)
    aad = build_aad(scope, ctx)

    payload = %{ciphertext: env.ciphertext, nonce: env.nonce, tag: env.tag}

    case cipher_mod.decrypt(payload, key, aad) do
      {:ok, plaintext} ->
        plaintext

      # Never CiphertextIntegrityFailed: a config typo is not "your data was tampered with".
      {:error, {:invalid_key_size, actual}} ->
        raise key_size_mismatch(opts, actual, cipher_mod)

      {:error, :opaque_key_unsupported} ->
        raise opaque_key_unsupported(opts, cipher_mod, ctx, :decrypt)

      # A cipher that reaches over the network — `AshVault.Ciphers.OpenBaoTransit` does
      # the AEAD inside OpenBao — can fail for reasons that have nothing to do with the
      # stored bytes. A 403, a deleted transit key or a connection refused must reach the
      # operator as the outage it is. Reporting it as CiphertextIntegrityFailed would tell
      # them their data was tampered with, which is this codebase's cardinal lie.
      {:error, %ProviderUnavailable{} = error} ->
        raise error

      {:error, _reason} ->
        raise CiphertextIntegrityFailed.exception(
                resource: ctx.resource,
                field: ctx.field,
                key_version: env.key_version
              )
    end
  end

  @doc """
  Rotate the `:data` key for a scope, raising on provider failure.
  """
  @spec rotate!(term(), opts()) :: {:ok, non_neg_integer()}
  def rotate!(scope, opts), do: rotate!(scope, :data, opts)

  @doc """
  Rotate a scope's keyring for `purpose`, raising on provider failure.

  `:data` calls the provider's `c:AshVault.KeyProvider.rotate/1`, exactly as `rotate!/2`
  always has. A purpose the provider does not serve raises
  `AshVault.Errors.PurposeUnsupported` — a configuration fault, never reported as an
  outage.
  """
  @spec rotate!(term(), KeyProvider.purpose(), opts()) :: {:ok, non_neg_integer()}
  def rotate!(scope, purpose, opts) do
    case KeyProvider.rotate(opts.key_provider, scope, purpose) do
      {:ok, version} ->
        {:ok, version}

      {:error, :destroyed} ->
        raise KeyDestroyed.exception(scope: scope, key_version: nil)

      {:error, {:purpose_unsupported, purpose}} ->
        raise PurposeUnsupported.exception(provider: opts.key_provider, purpose: purpose)

      {:error, %ProviderUnavailable{} = error} ->
        raise error

      {:error, reason} ->
        raise ProviderUnavailable.exception(provider: opts.key_provider, reason: reason)
    end
  end

  @doc """
  Compute a MAC over `data` for a context, under the scope's current `:mac` key.

  Returns `{key_version, tag}`: `tag` is the raw bytes `AshVault.Mac.c:mac/3` produced,
  and `key_version` is what `verify_mac!/5` needs back. The tag is bound to the scope,
  resource and field through the same associated data `encrypt!/3` uses
  (`build_aad/2`), so a tag minted for one tenant, resource or field never verifies for
  another.

  The scope's `:mac` keyring is minted on first use. Raises
  `AshVault.Errors.KeyDestroyed` for an erased scope, `AshVault.Errors.PurposeUnsupported`
  when the provider has no `:mac` keyring, and `AshVault.Errors.ProviderUnavailable` for
  an outage.

  Emits `[:ash_vault, :mac, :sign]`; see `AshVault.Telemetry`.
  """
  @spec mac!(binary(), Context.t(), opts()) :: {pos_integer(), binary()}
  def mac!(data, %Context{} = ctx, opts) when is_binary(data) do
    metadata = mac_metadata(ctx, opts, nil)

    :sign
    |> span(metadata, fn -> do_mac(data, ctx, opts) end, fn {version, _tag} -> version end)
    |> unwrap!()
  end

  defp do_mac(data, ctx, opts) do
    scope = resolve_scope!(ctx, opts.scope, :mac)
    key_info = current_mac_key!(opts.key_provider, scope, ctx)
    mac = mac_module(opts)

    case mac.mac(data, key_info.key, build_aad(scope, ctx)) do
      {:ok, tag} when is_binary(tag) ->
        {:ok, {key_info.version, tag}}

      {:error, reason} ->
        {:error, mac_error(reason, opts, ctx, :mac)}

      other ->
        {:error, ProviderUnavailable.exception(provider: mac, reason: {:unexpected, other})}
    end
  rescue
    error in [
      AshVault.Errors.MissingScope,
      AshVault.Errors.InvalidScope,
      KeyDestroyed,
      KeyNotFound,
      ProviderUnavailable,
      PurposeUnsupported
    ] ->
      {:error, error}
  end

  @doc """
  Verify a tag produced by `mac!/3`, returning `:ok` or raising.

  The key is fetched **before** the tag is looked at, so the answer about the key always
  wins over the answer about the tag:

    * `AshVault.Errors.KeyDestroyed` — the scope was erased. Every tag it issued is
      revoked, however valid it once was.
    * `AshVault.Errors.KeyNotFound` — `key_version` does not exist (including a
      non-integer one).
    * `AshVault.Errors.ProviderUnavailable` — the provider could not answer. Retryable,
      and never reported as an invalid tag.
    * `AshVault.Errors.InvalidMac` — everything was found and the tag is wrong: tampered,
      forged, paired with the wrong version, or minted under another scope, resource or
      field.

  Comparison is constant-time (`AshVault.Macs.HmacSha256`) or done by OpenBao
  (`AshVault.Macs.OpenBaoTransit`). Emits `[:ash_vault, :mac, :verify]`.
  """
  @spec verify_mac!(binary(), term(), term(), Context.t(), opts()) :: :ok
  def verify_mac!(data, key_version, tag, %Context{} = ctx, opts) when is_binary(data) do
    metadata = mac_metadata(ctx, opts, key_version)

    :verify
    |> span(metadata, fn -> do_verify_mac(data, key_version, tag, ctx, opts) end, fn _ ->
      key_version
    end)
    |> unwrap!()
  end

  defp do_verify_mac(data, key_version, tag, ctx, opts) do
    scope = resolve_scope!(ctx, opts.scope, :verify_mac)
    key = get_mac_key!(opts.key_provider, scope, key_version, ctx)
    mac = mac_module(opts)

    if is_binary(tag) do
      case mac.verify(data, tag, key, build_aad(scope, ctx)) do
        :ok -> {:ok, :ok}
        {:error, :invalid_tag} -> {:error, invalid_mac(ctx, key_version)}
        {:error, reason} -> {:error, mac_error(reason, opts, ctx, :verify_mac)}
      end
    else
      {:error, invalid_mac(ctx, key_version)}
    end
  rescue
    error in [
      AshVault.Errors.MissingScope,
      AshVault.Errors.InvalidScope,
      KeyDestroyed,
      KeyNotFound,
      ProviderUnavailable,
      PurposeUnsupported
    ] ->
      {:error, error}
  end

  defp invalid_mac(ctx, key_version) do
    InvalidMac.exception(resource: ctx.resource, field: ctx.field, key_version: key_version)
  end

  defp mac_module(opts), do: Map.get(opts, :mac) || AshVault.Macs.HmacSha256

  # The MAC's error vocabulary is the cipher's: the same three configuration and outage
  # answers, classified the same way. Anything unrecognised is an outage of the MAC
  # module, never a verdict on the tag.
  defp mac_error({:invalid_key_size, actual}, opts, _ctx, _operation) do
    mac = mac_module(opts)

    KeySizeMismatch.exception(
      provider: opts.key_provider,
      cipher: mac,
      expected: mac.key_bytes(),
      actual: actual
    )
  end

  defp mac_error(:opaque_key_unsupported, opts, ctx, operation),
    do: opaque_key_unsupported(opts, mac_module(opts), ctx, operation)

  defp mac_error(%ProviderUnavailable{} = error, _opts, _ctx, _operation), do: error

  defp mac_error(reason, opts, _ctx, _operation),
    do: ProviderUnavailable.exception(provider: mac_module(opts), reason: reason)

  defp current_mac_key!(provider, scope, ctx) do
    case KeyProvider.current_key(provider, scope, :mac) do
      {:ok, key_info} ->
        key_info

      {:error, {:purpose_unsupported, purpose}} ->
        raise PurposeUnsupported.exception(provider: provider, purpose: purpose)

      {:error, %ProviderUnavailable{} = error} ->
        raise error

      {:error, reason} ->
        case map_provider_error(reason, scope, ctx) do
          %ProviderUnavailable{} = error -> raise %{error | provider: provider}
          error -> raise error
        end
    end
  end

  defp get_mac_key!(provider, scope, version, ctx) do
    case KeyProvider.get_key(provider, scope, version, :mac) do
      {:ok, key} ->
        key

      {:error, :destroyed} ->
        raise KeyDestroyed.exception(
                scope: scope,
                key_version: version,
                resource: ctx.resource,
                field: ctx.field
              )

      {:error, :not_found} ->
        raise KeyNotFound.exception(scope: scope, key_version: version)

      {:error, {:purpose_unsupported, purpose}} ->
        raise PurposeUnsupported.exception(provider: provider, purpose: purpose)

      {:error, %ProviderUnavailable{} = error} ->
        raise error

      {:error, reason} ->
        raise ProviderUnavailable.exception(provider: provider, reason: reason)
    end
  end

  # The work runs inside the span and returns `{:ok, _} | {:error, exception}`; the raise
  # happens outside it. A raise inside would emit `:exception`, and `AshVault.Telemetry`
  # tells compliance handlers to watch `:stop` — a failed verification must reach them.
  defp span(event, metadata, fun, version_of) do
    :telemetry.span([:ash_vault, :mac, event], metadata, fn ->
      result = fun.()

      stop =
        metadata
        |> Map.merge(AshVault.Telemetry.result_metadata(result))
        |> Map.put(:key_version, stop_version(result, version_of, metadata))

      {result, stop}
    end)
  end

  defp stop_version({:ok, value}, version_of, _metadata), do: version_of.(value)
  defp stop_version(_result, _version_of, metadata), do: metadata.key_version

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, error}), do: raise(error)

  # Never the data, never the tag, never the scope (it is not on the per-operation events
  # either; see `AshVault.Telemetry`).
  defp mac_metadata(ctx, opts, key_version) do
    ctx
    |> AshVault.Telemetry.context_metadata()
    |> Map.merge(%{
      vault: Map.get(opts, :vault),
      mac: mac_module(opts),
      key_version: scalar_version(key_version)
    })
  end

  defp scalar_version(version) when is_integer(version), do: version
  defp scalar_version(_version), do: nil

  @doc """
  Destroy every key for a scope (crypto-erasure), raising on provider failure.

  Returns only once the provider has confirmed the destruction.
  """
  @spec destroy!(term(), opts()) :: :ok
  def destroy!(scope, opts) do
    # v1 has no key cache. When one lands, evict it here *before* destroying, so no
    # in-flight operation can use a cached copy of a key that is about to be erased:
    #
    #     AshVault.KeyCache.evict_scope(scope)
    case opts.key_provider.destroy(scope) do
      :ok ->
        :ok

      {:error, reason} ->
        raise ProviderUnavailable.exception(provider: opts.key_provider, reason: reason)
    end
  end

  @doc """
  Build the additional authenticated data bound into every ciphertext.

  The format is frozen:

      "ashvault:v1|" <> scope <> "|" <> inspect(resource) <> "|" <> field

  It is a stable, human-inspectable binary rather than `:erlang.term_to_binary/1`,
  because term encoding is not guaranteed stable across OTP releases and ciphertext must
  outlive OTP upgrades. Binding scope, resource and field means a value cannot be
  replayed into a different tenant, resource or column.
  """
  @spec build_aad(term(), Context.t()) :: binary()
  def build_aad(scope, %Context{resource: resource, field: field}) do
    "ashvault:v1|" <> to_string(scope) <> "|" <> inspect(resource) <> "|" <> to_string(field)
  end

  defp current_key!(provider, scope, ctx) do
    case provider.current_key(scope) do
      {:ok, key_info} ->
        key_info

      {:error, reason} ->
        case map_provider_error(reason, scope, ctx) do
          %ProviderUnavailable{} = error -> raise %{error | provider: provider}
          error -> raise error
        end
    end
  end

  defp get_key!(provider, scope, version, ctx) do
    case provider.get_key(scope, version) do
      {:ok, key} ->
        key

      {:error, :destroyed} ->
        raise KeyDestroyed.exception(
                scope: scope,
                key_version: version,
                resource: ctx.resource,
                field: ctx.field
              )

      {:error, :not_found} ->
        raise KeyNotFound.exception(scope: scope, key_version: version)

      {:error, reason} ->
        raise ProviderUnavailable.exception(provider: provider, reason: reason)
    end
  end

  @doc """
  Map a key provider's raw error term onto an AshVault error struct.
  """
  @spec map_provider_error(term(), term(), Context.t()) :: Exception.t()
  def map_provider_error(:destroyed, scope, ctx) do
    KeyDestroyed.exception(
      scope: scope,
      key_version: nil,
      resource: ctx.resource,
      field: ctx.field
    )
  end

  def map_provider_error(:not_found, scope, _ctx) do
    KeyNotFound.exception(scope: scope, key_version: nil)
  end

  def map_provider_error(reason, _scope, _ctx) do
    ProviderUnavailable.exception(provider: nil, reason: reason)
  end

  defp maybe_rotate(key_info, scope, ctx, opts) do
    policy = opts.rotation_policy.policy(scope, ctx)

    if policy.rotate_on_write? and RotationPolicy.due?(policy, key_info) do
      rotate_best_effort(key_info, scope, ctx, opts)
    else
      key_info
    end
  end

  defp rotate_best_effort(key_info, scope, ctx, opts) do
    with {:ok, _version} <- opts.key_provider.rotate(scope),
         {:ok, rotated} <- opts.key_provider.current_key(scope) do
      rotated
    else
      # A write racing a `destroy!` must NOT fall back to the pre-destroy key: that
      # write would "succeed" and store ciphertext nobody can ever read. Rotation
      # failures are best-effort; erasure is not a rotation failure.
      {:error, :destroyed} ->
        raise KeyDestroyed.exception(
                scope: scope,
                key_version: key_info.version,
                resource: ctx.resource,
                field: ctx.field
              )

      {:error, reason} ->
        # The scope key is fingerprinted, not interpolated: a tenant id is routinely an
        # email address or an organisation name, and this line goes to application logs,
        # which have a longer life and a wider audience than the database does. The
        # fingerprint is stable, so two failures for the same tenant still correlate.
        Logger.warning(
          "AshVault: key rotation for scope #{AshVault.Scope.fingerprint(scope)} failed " <>
            "(#{inspect(reason)}); continuing with the existing key for " <>
            "#{inspect(ctx.resource)}.#{ctx.field}"
        )

        key_info
    end
  end
end
