defmodule AshVault.Macaroon.Rotation do
  @moduledoc """
  Automatic rotation of credentials whose tokens are macaroons: successor minting, an
  overlap, revocation once the predecessor has gone quiet, and failure handling that
  never leaves consumers without a valid token.

  Declared with a `rotation` entity inside a `macaroon` (see `AshVault.Dsl` and
  [Macaroon rotation](macaroon-rotation.md)); run by the generated rotate action, which
  an AshOban scheduled action (or any scheduler) calls every minute.

  ## One reconcile, per credential

    1. **Mint** when there is no current credential, the current one is due (two thirds
       of its lifetime) or no longer valid (revoked, expired, deleted), and no successor
       is pending. Issue a row with the `issue_action`, mint its token, stage it, and
       record the row as `pending`. A failed issue or mint changes nothing (the current
       credential stays). A failed staging revokes the new row at once: nobody holds it.
    2. **Distribute** a pending credential from staging to every consumer that does not
       have it yet. A failed delivery is retried next reconcile; the current credential
       stays valid meanwhile. Staging that lost the token revokes the pending row and
       mints again. Once every consumer has it, pending becomes current and current
       becomes `previous`. A consumer added later is handed the current credential.
    3. **Retire** the previous credential once nothing has used it for the quiet period
       after it was superseded (its `last_used_at`): that is the consumers'
       confirmation. One still in use is kept, flagged `in_use`, and expires at the end
       of its lifetime: the overlap is the last third of it.

  ## Telemetry

  Plain `:telemetry.execute/3` events, all with `:resource` and `:macaroon` metadata:

  | Event | Measurements | Adds |
  |---|---|---|
  | `[:ash_vault, :macaroon, :rotation, :reconciled]` | `timestamp` (unix seconds), `count` (credentials) | |
  | `[:ash_vault, :macaroon, :rotation, :status]` | `expires_in`, `rotate_in` (seconds, current credential; 0 without one), `pending`, `predecessor_in_use`, `healthy` (0/1) | `:rotation` (the item's ref) |
  | `[:ash_vault, :macaroon, :rotation, :failure]` | `count: 1` | `:rotation` (`"*"` for a failed `list/1`), `:reason` |
  | `[:ash_vault, :macaroon, :rotation, :minted]` | `count: 1` | `:rotation`, `:id` |
  | `[:ash_vault, :macaroon, :rotation, :promoted]` | `count: 1` | `:rotation`, `:id` |
  | `[:ash_vault, :macaroon, :rotation, :retired]` | `count: 1` | `:rotation`, `:id` |

  No event, log line or stored state carries a token: tokens exist only inside
  `AshVault.Macaroon.Rotation.Secret` on their way to the delivery.
  """

  require Logger

  alias AshVault.Macaroon.Clock
  alias AshVault.Macaroon.Definition
  alias AshVault.Macaroon.Record
  alias AshVault.Macaroon.Rotation.Context
  alias AshVault.Macaroon.Rotation.Entry
  alias AshVault.Macaroon.Rotation.Failure
  alias AshVault.Macaroon.Rotation.Item
  alias AshVault.Macaroon.Rotation.Secret
  alias AshVault.Macaroon.Rotation.Spec
  alias AshVault.Macaroon.Rotation.State
  alias AshVault.Macaroon.Runtime

  # Mint a successor at two thirds of the lifetime: the last third is the overlap in
  # which both are valid. A constant, not an option: it is what every alert and runbook
  # about rotation assumes.
  @rotate_numerator 2
  @rotate_denominator 3

  @doc "Where in a credential's lifetime its successor is minted: `{2, 3}`."
  @spec rotate_at_fraction() :: {pos_integer(), pos_integer()}
  def rotate_at_fraction, do: {@rotate_numerator, @rotate_denominator}

  @doc """
  Reconcile every credential the macaroon's rotation `source` lists.

  Options: `:actor` (used for every action rotation runs), `:now` (default
  `AshVault.Macaroon.Clock.now/0`).
  """
  @spec run(module(), atom(), keyword()) :: :ok | {:error, term()}
  def run(resource, macaroon, opts \\ []) do
    definition = AshVault.Info.macaroon(resource, macaroon)

    rotation =
      (definition && definition.rotation) ||
        raise ArgumentError, "#{inspect(resource)} macaroon #{inspect(macaroon)} has no rotation"

    base = %Context{
      resource: resource,
      macaroon: definition,
      rotation: rotation,
      actor: Keyword.get(opts, :actor),
      now: Keyword.get_lazy(opts, :now, &Clock.now/0)
    }

    case rotation.source.list(base) do
      {:ok, items} ->
        Enum.each(items, &reconcile(&1, base))

        emit(base, :reconciled, %{timestamp: DateTime.to_unix(base.now), count: length(items)})
        :ok

      {:error, reason} ->
        report(base, "*", :list, reason)
        {:error, reason}
    end
  end

  @doc """
  Reconcile one item and save its state through the source. Returns the state saved.
  """
  @spec reconcile(Item.t(), Context.t()) :: State.t()
  def reconcile(%Item{} = item, %Context{} = base) do
    context = %{base | ref: item.ref, meta: item.meta, spec: spec_or_nil(item.spec)}
    state = %{(item.state || %State{}) | failure: nil}

    state =
      case check_spec(item.spec, context) do
        :ok ->
          state
          |> mint(context)
          |> distribute(context)
          |> retire(context)

        {:error, message} ->
          fail(state, context, :invalid_spec, message)
      end
      |> finish(context)

    case context.rotation.source.save(item, state, context) do
      :ok -> :ok
      {:error, reason} -> report(context, item.ref, :status, reason)
    end

    observe(state, context)
    state
  end

  defp spec_or_nil(%Spec{} = spec), do: spec
  defp spec_or_nil(_invalid), do: nil

  ## Spec

  defp check_spec({:invalid, message}, _context) when is_binary(message), do: {:error, message}

  defp check_spec(%Spec{} = spec, context) do
    max = context.macaroon.max_ttl

    cond do
      not (is_integer(spec.lifetime) and spec.lifetime > 0) ->
        {:error, "lifetime must be a positive number of seconds"}

      is_integer(max) and spec.lifetime > max ->
        {:error, "lifetime exceeds the macaroon's max_ttl (#{max} seconds)"}

      not (is_nil(spec.quiet_period) or
               (is_integer(spec.quiet_period) and spec.quiet_period >= 0)) ->
        {:error, "quiet period must be a non-negative number of seconds"}

      List.wrap(spec.consumers) == [] ->
        {:error, "at least one consumer is required"}

      true ->
        delivery = context.rotation.delivery
        names = Enum.map(spec.consumers, &delivery.consumer_name/1)

        if length(Enum.uniq(names)) == length(names),
          do: :ok,
          else: {:error, "consumer names must be unique"}
    end
  end

  defp check_spec(_other, _context), do: {:error, "unreadable rotation spec"}

  ## 1. Mint

  defp mint(%State{pending: %Entry{}} = state, _context), do: state

  defp mint(state, context) do
    if due?(state.current, context), do: issue(state, context), else: state
  end

  defp due?(nil, _context), do: true

  defp due?(%Entry{id: id, rotate_at: rotate_at}, context) do
    case credential(context, id) do
      {:ok, row} -> not valid?(row, context) or DateTime.compare(context.now, rotate_at) != :lt
      :missing -> true
      # Unknown is not due: an outage must not mint a credential per minute.
      {:error, _} -> false
    end
  end

  defp issue(state, %Context{spec: spec, now: now} = context) do
    expires_at = DateTime.add(now, spec.lifetime, :second)

    with {:ok, row} <- create(context, expires_at),
         id = identity(context, row),
         {:ok, secret} <- mint_token(context, row, id, expires_at),
         :ok <- stage(context, id, secret) do
      Logger.info("macaroon rotation #{context.ref}: minted #{id}")
      emit(context, :minted, %{count: 1}, %{id: id})

      %{
        state
        | pending: %Entry{
            id: id,
            issued_at: now,
            expires_at: expires_at,
            rotate_at: rotate_at(now, spec.lifetime)
          }
      }
    else
      {:error, {:staging, reason}} -> fail(state, context, :staging, reason)
      {:error, reason} -> fail(state, context, :mint, reason)
    end
  end

  defp rotate_at(now, lifetime),
    do: DateTime.add(now, div(lifetime * @rotate_numerator, @rotate_denominator), :second)

  defp create(context, expires_at) do
    attributes =
      Map.put(context.spec.attributes, context.rotation.expires_at_attribute, expires_at)

    context.resource
    |> Ash.Changeset.for_create(context.rotation.issue_action, attributes, ash_opts(context))
    |> Ash.create()
  end

  # A row whose token could not be minted is held by nobody: revoke it.
  defp mint_token(context, row, id, expires_at) do
    attribute = Runtime.identity_attribute(context.resource, context.macaroon)
    ttl = max(DateTime.diff(expires_at, Clock.now()), 1)

    input = %{
      attribute.name => Map.fetch!(row, attribute.name),
      caveats: context.spec.caveats,
      ttl: ttl
    }

    context.resource
    |> Ash.ActionInput.for_action(
      Definition.mint_action(context.macaroon),
      input,
      ash_opts(context)
    )
    |> Ash.run_action()
    |> case do
      {:ok, token} when is_binary(token) ->
        {:ok, Secret.new(token)}

      {:error, reason} ->
        revoke(context, id)
        {:error, reason}
    end
  end

  # A token whose staging failed is held by nobody: revoke it at once rather than
  # leave a live orphan.
  defp stage(context, id, secret) do
    case context.rotation.delivery.stage(context, id, secret) do
      :ok ->
        :ok

      {:error, reason} ->
        revoke(context, id)
        {:error, {:staging, reason}}
    end
  end

  ## 2. Distribute

  defp distribute(%State{pending: %Entry{id: id} = pending} = state, context) do
    case context.rotation.delivery.staged(context, id) do
      {:ok, %Secret{} = secret} ->
        pending = deliver_all(pending, secret, context)

        case undelivered(pending, context) do
          [] ->
            promote(state, pending, context)

          names ->
            fail(
              %{state | pending: pending},
              context,
              :distribution,
              "not yet delivered to #{Enum.join(names, ", ")}"
            )
        end

      :lost ->
        revoke(context, id)

        %{state | pending: nil}
        |> fail(context, :staging_lost, "staging no longer holds #{id}")

      {:error, reason} ->
        fail(state, context, :distribution, reason)
    end
  end

  # No successor in flight: hand the current credential to a consumer added since it
  # was delivered. Staging still holds it (it is replaced only by the next mint); if it
  # does not, rotate early rather than leave that consumer without a token.
  defp distribute(%State{current: %Entry{id: id} = current} = state, context) do
    if undelivered(current, context) == [] do
      state
    else
      case context.rotation.delivery.staged(context, id) do
        {:ok, %Secret{} = secret} ->
          current = deliver_all(current, secret, context)
          state = %{state | current: current}

          case undelivered(current, context) do
            [] ->
              state

            names ->
              fail(
                state,
                context,
                :distribution,
                "not yet delivered to #{Enum.join(names, ", ")}"
              )
          end

        :lost ->
          %{state | current: %{current | rotate_at: context.now}}
          |> fail(context, :staging_lost, "staging no longer holds #{id}; rotating early")

        {:error, reason} ->
          fail(state, context, :distribution, reason)
      end
    end
  end

  defp distribute(state, _context), do: state

  defp deliver_all(entry, secret, context) do
    delivery = context.rotation.delivery

    delivered =
      for consumer <- context.spec.consumers,
          name = delivery.consumer_name(consumer),
          not Map.has_key?(entry.delivered, name),
          reduce: entry.delivered do
        delivered ->
          case delivery.deliver(context, consumer, entry.id, secret) do
            :ok ->
              Map.put(delivered, name, context.now)

            {:error, reason} ->
              Logger.warning(
                "macaroon rotation #{context.ref}: delivery of #{entry.id} to #{name} " <>
                  "failed: #{describe(context, reason)}"
              )

              delivered
          end
      end

    %{entry | delivered: delivered}
  end

  defp undelivered(entry, context) do
    for consumer <- context.spec.consumers,
        name = context.rotation.delivery.consumer_name(consumer),
        not Map.has_key?(entry.delivered, name),
        do: name
  end

  # A predecessor still listed at promotion is two rotations old: it has expired or
  # will within the overlap, and nothing can be handed it again.
  defp promote(state, pending, context) do
    if state.previous, do: revoke(context, state.previous.id)

    previous =
      case state.current do
        %Entry{} = current -> %{current | superseded_at: context.now, in_use: false}
        nil -> nil
      end

    Logger.info("macaroon rotation #{context.ref}: now uses #{pending.id}")
    emit(context, :promoted, %{count: 1}, %{id: pending.id})

    %{
      state
      | current: pending,
        previous: previous,
        pending: nil,
        last_rotation_at: context.now
    }
  end

  ## 3. Retire

  defp retire(%State{previous: %Entry{id: id} = previous} = state, context) do
    case credential(context, id) do
      {:ok, row} ->
        cond do
          not valid?(row, context) ->
            %{state | previous: nil}

          quiet?(row, previous, context) ->
            revoke(context, id)
            Logger.info("macaroon rotation #{context.ref}: retired #{id}")
            emit(context, :retired, %{count: 1}, %{id: id})
            %{state | previous: nil}

          true ->
            %{state | previous: %{previous | in_use: true}}
        end

      :missing ->
        %{state | previous: nil}

      {:error, reason} ->
        fail(state, context, :retire, reason)
    end
  end

  defp retire(state, _context), do: state

  defp quiet?(row, previous, context) do
    superseded = previous.superseded_at || context.now

    last =
      case Map.get(row, context.rotation.last_used_at_attribute) do
        %DateTime{} = used ->
          if DateTime.compare(used, superseded) == :gt, do: used, else: superseded

        _ ->
          superseded
      end

    DateTime.diff(context.now, last) >= quiet_period(context)
  end

  defp quiet_period(%Context{spec: %Spec{quiet_period: quiet}}) when is_integer(quiet),
    do: quiet

  defp quiet_period(context), do: context.rotation.quiet_period

  ## State and telemetry

  defp finish(state, context) do
    phase =
      cond do
        state.failure && is_nil(state.current) -> "Failed"
        state.pending || state.previous -> "Rotating"
        state.current -> "Ready"
        true -> "Pending"
      end

    %{state | phase: phase, last_reconcile_at: context.now}
  end

  defp observe(state, context) do
    seconds = fn
      %Entry{} = entry, key -> DateTime.diff(Map.fetch!(entry, key), context.now)
      nil, _key -> 0
    end

    emit(
      context,
      :status,
      %{
        expires_in: seconds.(state.current, :expires_at),
        rotate_in: seconds.(state.current, :rotate_at),
        pending: if(state.pending, do: 1, else: 0),
        predecessor_in_use: if(state.previous && state.previous.in_use, do: 1, else: 0),
        healthy: if(state.current && is_nil(state.failure), do: 1, else: 0)
      }
    )
  end

  defp fail(state, context, reason, detail) do
    message = report(context, context.ref, reason, detail)
    %{state | failure: %Failure{reason: reason, message: message, time: context.now}}
  end

  defp report(context, ref, reason, detail) do
    message = describe(context, detail)
    Logger.error("macaroon rotation #{ref}: #{reason}: #{message}")
    emit(context, :failure, %{count: 1}, %{rotation: ref, reason: reason})
    message
  end

  defp emit(context, event, measurements, metadata \\ %{}) do
    metadata =
      Map.merge(
        %{resource: context.resource, macaroon: context.macaroon.name, rotation: context.ref},
        metadata
      )

    :telemetry.execute([:ash_vault, :macaroon, :rotation, event], measurements, metadata)
  end

  # Never inspect the detail: error structs and changesets can carry inputs.
  @doc false
  def describe(context, detail) do
    described =
      Enum.find_value([context.rotation.delivery, context.rotation.source], fn module ->
        (Code.ensure_loaded?(module) and function_exported?(module, :describe_error, 1)) &&
          module.describe_error(detail)
      end)

    described || default_describe(detail)
  end

  defp default_describe(detail) when is_binary(detail), do: detail

  defp default_describe(%Ash.Error.Forbidden{}), do: "forbidden"

  defp default_describe(%{__exception__: true, errors: [first | _]} = error)
       when is_struct(first),
       do: module_name(error) <> ": " <> module_name(first)

  defp default_describe(%{__exception__: true} = error), do: module_name(error)
  defp default_describe(_other), do: "unexpected error"

  defp module_name(%module{}), do: module |> Module.split() |> Enum.join(".")

  ## Rows

  defp ash_opts(context) do
    [actor: context.actor, tenant: context.spec && context.spec.ash_tenant]
  end

  defp identity(context, row) do
    attribute = Runtime.identity_attribute(context.resource, context.macaroon)
    row |> Map.fetch!(attribute.name) |> to_string()
  end

  defp credential(context, id) do
    attribute = Runtime.identity_attribute(context.resource, context.macaroon)
    read = Ash.Resource.Info.primary_action!(context.resource, :read)

    case Record.cast_id(attribute, id) do
      {:ok, value} ->
        context.resource
        |> Ash.Query.for_read(read.name, %{}, ash_opts(context))
        |> Record.filter_identity(attribute, value)
        |> Record.with_revocation(context.macaroon)
        |> Ash.read_one()
        |> case do
          {:ok, nil} -> :missing
          {:ok, row} -> {:ok, row}
          {:error, error} -> {:error, error}
        end

      :error ->
        :missing
    end
  end

  defp valid?(row, context) do
    not Record.revoked?(row, context.macaroon) and
      case Map.get(row, context.rotation.expires_at_attribute) do
        %DateTime{} = expires_at -> DateTime.compare(expires_at, context.now) == :gt
        _ -> false
      end
  end

  # Revocation is best effort here: a revoke that fails leaves a credential that still
  # expires on its own, and the failure is logged. Rotation never re-issues it.
  defp revoke(context, id) do
    with {:ok, row} <- credential(context, id),
         false <- Record.revoked?(row, context.macaroon) do
      row
      |> Record.strip()
      |> Ash.Changeset.for_update(context.rotation.revoke_action, %{}, ash_opts(context))
      |> Ash.update()
      |> case do
        {:ok, _} ->
          :ok

        {:error, error} ->
          Logger.error(
            "macaroon rotation #{context.ref}: revoking #{id} failed: " <>
              describe(context, error)
          )
      end
    end

    source = context.rotation.source

    if Code.ensure_loaded?(source) and function_exported?(source, :revoked, 2),
      do: source.revoked(id, context)

    :ok
  end
end
