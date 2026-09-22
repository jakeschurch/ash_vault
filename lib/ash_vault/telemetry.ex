defmodule AshVault.Telemetry do
  @moduledoc """
  The `:telemetry` events AshVault emits, and the rules about what may appear in them.

  AshVault has no `on_decrypt` callback. It emits telemetry instead, because a compliance
  audit log, a metric, a trace span and a debug log are four different consumers of the
  same fact, and only one of them can be a callback.

  ## Events

  Every event is a [`:telemetry.span/3`](`:telemetry.span/3`), so each name below is a
  prefix with three concrete events under it — `:start`, `:stop` and `:exception` —
  following the same convention as `Ash`, `Ecto` and `Finch`.

  | Prefix | Emitted around |
  |---|---|
  | `[:ash_vault, :encrypt]` | `AshVault.encrypt_value/4` — one field of one record |
  | `[:ash_vault, :decrypt]` | `AshVault.decrypt_value/5` — one field of one record |
  | `[:ash_vault, :key, :rotate]` | `AshVault.rotate_key!/3` — a scope's key is rotated |
  | `[:ash_vault, :key, :destroy]` | `AshVault.destroy_keys!/3` — a scope is crypto-erased |

  `[:ash_vault, :key, :destroy]` is the compliance-critical one: it is the record that an
  erasure request was actually executed, and it is the only event whose absence is itself
  a finding.

  ### Measurements

  `:start` carries `%{system_time: System.system_time()}`. `:stop` and `:exception` carry
  `%{duration: native_time, monotonic_time: ..., system_time: ...}` — `:telemetry.span/3`'s
  standard shape. Convert a duration with
  `System.convert_time_unit(duration, :native, :microsecond)`.

  ### Metadata

  Common to every event:

    * `:actor_type` — the actor's struct module, `:map` for a bare map, `:scalar` for a
      bare id, `:unknown`, or `nil`
    * `:actor_id` — the actor's `:id`, and only if it is an atom, integer or binary
    * `:result` — `:ok` or `:error` (`:stop` only)
    * `:error` — the error **module**, e.g. `AshVault.Errors.KeyDestroyed` (`:stop`, and
      only when `result: :error`)

  Per event:

  | Prefix | Adds |
  |---|---|
  | `[:ash_vault, :encrypt]` | `:resource`, `:field`, `:phase` |
  | `[:ash_vault, :decrypt]` | `:resource`, `:field`, `:phase`, `:vault` |
  | `[:ash_vault, :key, :rotate]` | `:resource`, `:field`, `:phase`, `:vault`, `:scope`, `:scope_fingerprint`, `:key_version` |
  | `[:ash_vault, :key, :destroy]` | `:resource`, `:field`, `:phase`, `:vault`, `:scope`, `:scope_fingerprint` |

  `:phase` is `:write` or `:read`. `:key_version` is `nil` on rotate's `:start` and the
  newly minted version on its `:stop`. `:vault` is absent from `[:ash_vault, :encrypt]`
  because the vault can be configured as a `fun/2` or an MFA, and calling it a second
  time just to label a telemetry event would run user code twice per write.

  On the lifecycle events `:resource`, `:field` and `:phase` come from whatever context
  the caller passed, so they are `nil` when the rotation or erasure was driven by
  `mix ash_vault.rotate` / `mix ash_vault.destroy_keys` rather than by a generic action.
  `:actor_id` is `nil` there too — which is itself the audit-relevant fact: it was an
  operator at a shell, not a user in the application.

  ### `:exception` carries the exception

  `:telemetry.span/3` puts `:kind`, `:reason` and `:stacktrace` into the metadata of its
  `:exception` event. `:reason` is the raised `AshVault.Errors` struct, so this one event
  is the only place an error struct — not just its module name — reaches a handler.

  Those structs are operator-facing and hold no plaintext, no ciphertext and no key
  material, but they do hold a scope (a tenant id) and, for
  `AshVault.Errors.ProviderUnavailable`, a provider-supplied reason. Treat an
  `:exception` handler as you would an exception reporter, because that is what it is.

  In practice `[:ash_vault, :encrypt]` and `[:ash_vault, :decrypt]` almost never emit it:
  `AshVault.encrypt_value/4` and `AshVault.decrypt_value/5` rescue every `AshVault.Errors`
  struct and return it, so a destroyed key is a `:stop` with `result: :error`. **A
  compliance handler must watch `:stop`, not `:exception`** — watching only `:exception`
  would miss every crypto failure AshVault has a name for.

  ## The lifecycle events carry the raw scope {: .warning}

  `Logger` output in `AshVault.Vault.Runtime` reports a scope as
  `AshVault.Scope.fingerprint/1` — a truncated SHA-256 — because a scope key is
  frequently a tenant id and therefore frequently PII. The lifecycle telemetry events do
  **not** do the same: `[:ash_vault, :key, :rotate]` and `[:ash_vault, :key, :destroy]`
  put the raw `:scope` in their metadata.

  That asymmetry is deliberate. `[:ash_vault, :key, :destroy]` exists to be the record
  that an erasure request was executed, and the question an auditor asks of that record
  a year later is *which tenant*. A fingerprint cannot answer it: the raw scope is not
  recoverable from it, and reconstructing the mapping means keeping a second table of
  tenant-to-fingerprint — which is the tenant ids again, in a place with no retention
  policy. A compliance log that cannot name the subject of the erasure is not a
  compliance log. A `Logger` line, by contrast, is read by whoever is on call this
  afternoon, and the fingerprint is enough to tell one tenant's failures from another's.

  The consequence is yours to handle: **a handler that forwards this metadata to an
  external service is forwarding tenant identifiers.** That is the same exposure the
  `Logger` change addressed, and telemetry metadata lands in third-party APMs verbatim
  in most handlers anybody actually writes. Both events therefore also carry
  `:scope_fingerprint`, so a handler that forwards outward has something to forward —
  it is a convenience for handler authors, **not** a mitigation: the raw `:scope` is
  still sitting in the same map, and a handler that copies the metadata wholesale sends
  it. Forward `:scope_fingerprint` and drop `:scope` explicitly, or keep the handler's
  output somewhere you already treat as holding tenant data.

  ## What is never in the metadata

  Not the plaintext. Not the ciphertext. Not key material. Not the actor struct, not the
  changeset, not the record, and not an `AshVault.Errors` struct — only the error's module
  name, because a `MissingScope` struct describes the tenant and a `ProviderUnavailable`
  struct carries a provider-supplied reason.

  Telemetry metadata is copied verbatim into APM by every handler anybody actually
  writes, so the rule is that there must be nothing in it that would matter if it were —
  with exactly one deliberate exception, the lifecycle events' `:scope`, argued above.
  Everything else in this list is absolute.

  There is a corresponding rule for you: **a handler must not put plaintext back in.**
  `AshVault.encrypt_value/4` is called with the plaintext in scope, but it is not passed
  to the span, and the return value of `[:ash_vault, :encrypt]` is not in the stop
  metadata either.

  ## Two deliberate omissions

  **`:scope` is not on the encrypt and decrypt events.** It is not available at the
  extension boundary where these spans live — only `AshVault.Vault.Runtime` resolves it,
  one layer down. Resolving it here as well would call the configured `AshVault.Scope`
  module, which is *user code*, a second time per operation: it can raise (producing a
  second, different `MissingScope` from inside the telemetry path), and any side effect it
  has would happen twice. Building metadata must not be able to change behaviour.
  `:resource`, `:field` and the actor identify the operation; the lifecycle events, where
  the scope arrives as a plain argument, carry it for free.

  **`:key_version` is not on the encrypt and decrypt events** for the same reason: it
  lives inside the envelope, and getting it here would mean decoding the envelope a second
  time on every single field read.

  ## Telemetry is not a veto

  `ash_cloak`'s `on_decrypt` can return `{:error, reason}` to **deny** a decryption. A
  `:telemetry` handler cannot: its return value is discarded, and by the time `:stop` fires
  the decryption has already happened.

  That is deliberate, and it is the same decision as the threat model's *Authorization*
  non-goal. AshVault performs no authorization; `Ash.Policy.Authorizer` and field policies
  do, and they run *before* the data is read. A second, crypto-layer gate would be a second
  source of truth about who may read a field, and the two would drift. It would also be a
  gate that fails in the wrong direction: a handler that raises, or is detached by a raise
  in an unrelated handler, would either take down every read or silently stop enforcing —
  and telemetry handlers are detached, globally and permanently, the first time one raises.

  If you need to deny a read, deny it in a policy.

  ## A compliance audit handler

  See [Operations](operations.md) for a worked handler, and for the retention windows the
  regimes in question ask for.

      :telemetry.attach_many(
        "ash-vault-audit",
        [
          [:ash_vault, :decrypt, :stop],
          [:ash_vault, :key, :rotate, :stop],
          [:ash_vault, :key, :destroy, :stop]
        ],
        &MyApp.VaultAudit.handle/4,
        nil
      )
  """

  @doc """
  Reduce an actor to an identifier pair, `%{actor_type: ..., actor_id: ...}`.

  Never returns the actor. An Ash actor is usually a loaded `%User{}` and therefore
  usually carries an email address and a password hash, so nothing but the struct module
  and a scalar `:id` is allowed out.

  The `:id` guard is on the **value**, not just the key: a resource whose primary key is
  itself a struct or a map would otherwise walk straight through a `%{id: id}` match.

      iex> AshVault.Telemetry.actor_identity(nil)
      %{actor_type: nil, actor_id: nil}

      iex> AshVault.Telemetry.actor_identity(%{id: 7, email: "x@example.com"})
      %{actor_type: :map, actor_id: 7}

      iex> AshVault.Telemetry.actor_identity("system")
      %{actor_type: :scalar, actor_id: "system"}
  """
  @spec actor_identity(term()) :: %{actor_type: term(), actor_id: term()}
  def actor_identity(nil), do: %{actor_type: nil, actor_id: nil}

  def actor_identity(%struct{} = actor) do
    %{actor_type: struct, actor_id: scalar_id(Map.get(actor, :id))}
  end

  def actor_identity(actor) when is_map(actor) do
    %{actor_type: :map, actor_id: scalar_id(Map.get(actor, :id))}
  end

  def actor_identity(actor) when is_binary(actor) or is_integer(actor) or is_atom(actor) do
    %{actor_type: :scalar, actor_id: actor}
  end

  def actor_identity(_actor), do: %{actor_type: :unknown, actor_id: nil}

  defp scalar_id(id) when is_binary(id) or is_integer(id) or is_atom(id), do: id
  defp scalar_id(_id), do: nil

  @doc """
  Summarise a `{:ok, _} | {:error, exception} | other` result as stop metadata.

  Only the error's **module** survives. An `AshVault.Errors` struct is not safe to put in
  telemetry metadata: `MissingScope` describes the tenant, `ProviderUnavailable` carries a
  provider-supplied reason, and `InvalidCiphertext` carries bytes.
  """
  @spec result_metadata(term()) :: map()
  def result_metadata({:ok, _value}), do: %{result: :ok}
  def result_metadata(:ok), do: %{result: :ok}
  def result_metadata({:error, %module{}}), do: %{result: :error, error: module}
  def result_metadata({:error, _other}), do: %{result: :error, error: nil}
  def result_metadata(_other), do: %{result: :ok}

  @doc false
  # The Ash callback contexts are normalised to a plain map by `AshVault.Context.Builder`,
  # but a context can also be `nil` (a mix task) or a bare map (a test), so nothing here
  # may assume a key is present.
  @spec context_metadata(AshVault.Context.t() | nil) :: map()
  def context_metadata(%AshVault.Context{} = context) do
    ash_context = context.ash_context || %{}

    %{
      resource: context.resource,
      field: context.field,
      phase: Map.get(ash_context, :phase)
    }
    |> Map.merge(actor_identity(Map.get(ash_context, :actor)))
  end

  def context_metadata(_context) do
    %{resource: nil, field: nil, phase: nil, actor_type: nil, actor_id: nil}
  end
end
