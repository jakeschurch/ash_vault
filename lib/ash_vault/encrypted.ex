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

  `:searchable?` adds a deterministic `<name>_lookup` token column; `:unique?` puts a
  unique identity on it; `:normalize` decides what "equal" means for both. See
  `AshVault.Lookup`.

  `:pre_check_with` is the domain to check that identity against in a `before_action`
  hook, for a data layer that cannot enforce uniqueness itself. Required there, refused
  nowhere, and off by default everywhere — it costs a read on every write.
  """

  defstruct [
    :name,
    :encrypt_nil?,
    :backfill_from,
    :pre_check_with,
    searchable?: false,
    unique?: false,
    normalize: :none,
    __spark_metadata__: nil
  ]

  @type t :: %__MODULE__{
          name: atom(),
          encrypt_nil?: boolean() | nil,
          backfill_from: atom() | nil,
          pre_check_with: module() | nil,
          searchable?: boolean(),
          unique?: boolean(),
          normalize: AshVault.Lookup.normalize()
        }
end
