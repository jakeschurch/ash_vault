defmodule AshVault.Changes.MirrorLegacy do
  @moduledoc """
  The dual-write of an `encrypt ..., legacy: ...` field, added by
  `AshVault.Transformers.SetupEncryption` as a global change on every create and update.

  Whenever an action changes the legacy attribute — accepted input, `set_attribute`, a
  custom change, `force_change_attribute` inside an earlier `before_action` hook — the
  new value is also encrypted into the AshVault copy. An action that leaves the attribute
  alone is left alone, so its ciphertext is never rewritten and an atomic action stays
  atomic.

  ## What gets encrypted

  The value as the legacy type will read it back: it is dumped and cast through the
  legacy type before encryption. A JSON-backed legacy map turns atom keys into strings,
  for instance, so both copies read back identically and `AshVault.Backfill` verify
  agrees with them. A value the legacy type refuses fails the write without the value in
  the error.

  ## Failure

  A vault error is added to the changeset: the write fails rather than leaving only the
  legacy copy current.

  ## Atomic path

  A literal value (the atomic form of `set_attribute/2` or an accepted input) is
  encrypted in the BEAM and written beside it. An expression — `atomic_update/2` on the
  legacy attribute — cannot be encrypted without reading the row, so the action is
  reported `:not_atomic`; `AshVault.Verifiers.VerifyVault` rejects such declarations at
  compile time.
  """

  use Ash.Resource.Change

  alias AshVault.Context.Builder

  @doc false
  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    if requires_atomic?(changeset) do
      mirror_if_changing(changeset, opts, context)
    else
      Ash.Changeset.before_action(changeset, &mirror_if_changing(&1, opts, context))
    end
  end

  # An action that must run atomically cannot carry a `before_action` hook — Ash refuses
  # the whole action — and cannot have one that changes the attribute either, so its
  # value is final by now: mirror it straight away, or leave the action untouched.
  defp requires_atomic?(%{action_type: :update, action: %{require_atomic?: true}}), do: true
  defp requires_atomic?(_changeset), do: false

  defp mirror_if_changing(changeset, opts, context) do
    field = opts[:field]

    if Ash.Changeset.changing_attribute?(changeset, field) do
      mirror(changeset, opts, Ash.Changeset.get_attribute(changeset, field), context)
    else
      changeset
    end
  end

  @doc false
  @impl Ash.Resource.Change
  def atomic(changeset, opts, context) do
    field = opts[:field]

    case atomic_value(changeset, field) do
      :unchanged ->
        {:ok, changeset}

      {:expression, _expr} ->
        {:not_atomic,
         "#{inspect(field)} is written by an expression, so its AshVault copy cannot be " <>
           "encrypted atomically"}

      {:literal, value} ->
        with {:ok, plaintext} <- legacy_round_trip(changeset.resource, field, value),
             {:ok, attributes} <-
               AshVault.write_attributes(
                 changeset.resource,
                 opts[:vault_field],
                 plaintext,
                 build_context(changeset, opts[:vault_field], context)
               ) do
          {:atomic, changeset, attributes}
        end
    end
  end

  defp atomic_value(changeset, field) do
    cond do
      Keyword.has_key?(changeset.atomics, field) ->
        value = Keyword.fetch!(changeset.atomics, field)
        if Ash.Expr.expr?(value), do: {:expression, value}, else: {:literal, value}

      Map.has_key?(changeset.attributes, field) ->
        {:literal, Map.fetch!(changeset.attributes, field)}

      true ->
        :unchanged
    end
  end

  defp mirror(changeset, opts, value, context) do
    vault_field = opts[:vault_field]

    case legacy_round_trip(changeset.resource, opts[:field], value) do
      {:ok, plaintext} ->
        AshVault.encrypt_and_set(
          changeset,
          vault_field,
          plaintext,
          build_context(changeset, vault_field, context)
        )

      {:error, error} ->
        Ash.Changeset.add_error(changeset, error)
    end
  end

  @doc false
  @spec legacy_round_trip(module(), atom(), term()) :: {:ok, term()} | {:error, Exception.t()}
  def legacy_round_trip(_resource, _field, nil), do: {:ok, nil}

  def legacy_round_trip(resource, field, value) do
    %{type: type, constraints: constraints} = Ash.Resource.Info.attribute(resource, field)

    with {:ok, dumped} <- Ash.Type.dump_to_native(type, value, constraints),
         {:ok, cast} <- Ash.Type.cast_stored(type, dumped, constraints) do
      {:ok, cast}
    else
      _ ->
        {:error,
         Ash.Error.Changes.InvalidAttribute.exception(
           field: field,
           message: "could not be stored by its legacy type"
         )}
    end
  rescue
    _ ->
      {:error,
       Ash.Error.Changes.InvalidAttribute.exception(
         field: field,
         message: "could not be stored by its legacy type"
       )}
  end

  defp build_context(changeset, vault_field, context) do
    Builder.from_changeset(changeset, vault_field, %{context | source_context: changeset.context})
  end
end
