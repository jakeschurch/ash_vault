defmodule AshVault.Changes.Encrypt do
  @moduledoc """
  Encrypts the action argument for one field into its `encrypted_<field>` attribute.

  Encryption happens in a `before_action` hook, not at `change/3` time, and reads the
  **argument** the transformer created — never an attribute, because there is no plaintext
  attribute any more. When the argument is absent the changeset is left alone, so a partial
  update never clobbers existing ciphertext.

  `source_context` is refreshed from `changeset.context` at hook-run time: the callback
  context's copy was snapshotted during `for_create`/`for_update`, before a caller had a
  chance to `Ash.Changeset.set_context/2`.

  ## Atomic path

  `atomic/3` returns `{:atomic, changeset, %{encrypted_field => blob}}` — the three-element
  form, which lets it hand back a changeset with the plaintext scrubbed from `:arguments`
  and `:params`. ash_cloak's atomic path uses the two-element form and skips scrubbing
  entirely, leaving plaintext in `changeset.arguments`. The crypto runs in the BEAM either
  way and the ciphertext is embedded as a literal, so there is nothing to lose by scrubbing.
  """

  use Ash.Resource.Change

  @doc false
  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      field = opts[:field]

      case Ash.Changeset.fetch_argument(changeset, field) do
        {:ok, value} ->
          AshVault.encrypt_and_set(
            changeset,
            field,
            value,
            build_context(changeset, field, context)
          )

        :error ->
          changeset
      end
    end)
  end

  @doc false
  @impl Ash.Resource.Change
  def atomic(changeset, opts, context) do
    field = opts[:field]

    case Ash.Changeset.fetch_argument(changeset, field) do
      {:ok, value} ->
        ctx = build_context(changeset, field, context)

        case AshVault.encrypt_value(changeset.resource, field, value, ctx) do
          {:ok, blob} ->
            {:atomic, AshVault.scrub_plaintext(changeset, field),
             %{AshVault.encrypted_field_name(field) => blob}}

          {:error, error} ->
            {:error, error}
        end

      :error ->
        {:ok, changeset}
    end
  end

  defp build_context(changeset, field, context) do
    AshVault.Context.Builder.from_changeset(changeset, field, %{
      context
      | source_context: changeset.context
    })
  end
end
