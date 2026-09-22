defmodule AshVault.Encrypted do
  @moduledoc """
  One encrypted field of a resource — the target struct of the `encrypt` DSL entity.

      ash_vault do
        vault MyApp.Vault
        encrypt :email
        encrypt :ssn, encrypt_nil?: false
      end

  `:encrypt_nil?` is `nil` here when the field does not override the section-level
  setting; `AshVault.Info.encrypt_nil?/2` resolves the effective value.

  `:searchable?` and `:unique?` are specified but not implemented in v1 — the verifier
  rejects them with an explicit message rather than silently ignoring them.
  """

  defstruct [
    :name,
    :encrypt_nil?,
    :backfill_from,
    searchable?: false,
    unique?: false,
    __spark_metadata__: nil
  ]

  @type t :: %__MODULE__{
          name: atom(),
          encrypt_nil?: boolean() | nil,
          backfill_from: atom() | nil,
          searchable?: boolean(),
          unique?: boolean()
        }
end
