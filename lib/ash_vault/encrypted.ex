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

  `:legacy`, `:stored_as` and `:decrypt_for` describe expand mode; see `AshVault.Dsl`.
  `AshVault.Info.encrypted_fields/1` presents a `legacy:` entity as the field that is
  actually encrypted — named `stored_as`, with `backfill_from` the legacy attribute and
  `:legacy_of` naming it — so the write path, the backfill and the key tooling treat it
  like any other encrypted field.
  """

  defstruct [
    :name,
    :encrypt_nil?,
    :backfill_from,
    :pre_check_with,
    :legacy,
    :stored_as,
    :decrypt_for,
    :legacy_of,
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
          legacy: module() | {module(), keyword()} | nil,
          stored_as: atom() | nil,
          decrypt_for: [term()] | nil,
          legacy_of: atom() | nil,
          searchable?: boolean(),
          unique?: boolean(),
          normalize: AshVault.Lookup.normalize()
        }
end
