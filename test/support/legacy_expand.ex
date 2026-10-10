defmodule AshVault.Test.LegacyBinary do
  @moduledoc """
  Stands in for an application's pre-AshVault encrypted type: stores `"L1:" <> base64`.
  """
  use Ash.Type

  @impl true
  def storage_type(_), do: :binary

  @impl true
  def cast_input(nil, _), do: {:ok, nil}
  def cast_input(value, _) when is_binary(value), do: {:ok, value}
  def cast_input(_, _), do: :error

  @impl true
  def cast_stored(nil, _), do: {:ok, nil}
  def cast_stored("L1:" <> encoded, _), do: Base.decode64(encoded)
  def cast_stored(_, _), do: :error

  @impl true
  def dump_to_native(nil, _), do: {:ok, nil}
  def dump_to_native(value, _) when is_binary(value), do: {:ok, "L1:" <> Base.encode64(value)}
  def dump_to_native(_, _), do: :error

  @doc "What the legacy column holds for `value`."
  def stored(value), do: "L1:" <> Base.encode64(value)
end

defmodule AshVault.Test.LegacyJsonMap do
  @moduledoc "A pre-AshVault map type that stores JSON, so keys read back as strings."
  use Ash.Type

  @impl true
  def storage_type(_), do: :binary

  @impl true
  def cast_input(nil, _), do: {:ok, nil}
  def cast_input(value, _) when is_map(value), do: {:ok, value}
  def cast_input(_, _), do: :error

  @impl true
  def cast_stored(nil, _), do: {:ok, nil}
  def cast_stored(json, _) when is_binary(json), do: Jason.decode(json)
  def cast_stored(_, _), do: :error

  @impl true
  def dump_to_native(nil, _), do: {:ok, nil}
  def dump_to_native(value, _) when is_map(value), do: Jason.encode(value)
  def dump_to_native(_, _), do: :error
end

defmodule AshVault.Test.Admin do
  @moduledoc "A test actor."
  defstruct [:id, role: :admin]

  @doc "A remote-function `decrypt_for` predicate."
  def admin?(%__MODULE__{role: :admin}), do: true
  def admin?(_actor), do: false
end

defmodule AshVault.Test.Checks.IsAdmin do
  @moduledoc "Matches `%AshVault.Test.Admin{role: :admin}`."
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_), do: "actor is an admin"

  @impl true
  def match?(%AshVault.Test.Admin{role: :admin}, _context, _opts), do: true
  def match?(_actor, _context, _opts), do: false
end

defmodule AshVault.Test.Checks.IsSystem do
  @moduledoc "Matches `%AshVault.Test.Admin{role: :system}`."
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_), do: "actor is the system"

  @impl true
  def match?(%AshVault.Test.Admin{role: :system}, _context, _opts), do: true
  def match?(_actor, _context, _opts), do: false
end

defmodule AshVault.Test.EtsLegacyAccount do
  @moduledoc """
  Expand mode (`encrypt ..., legacy: ...`) over an ETS table: a binary credential, a
  JSON-backed map, and the action shapes that used to need a hand-placed dual-write.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:token,
      legacy: AshVault.Test.LegacyBinary,
      encrypt_nil?: false,
      decrypt_for: [
        AshVault.Test.Checks.IsAdmin,
        {AshVault.Test.Checks.IsSystem, only: [:with_secrets]}
      ]
    )

    encrypt(:settings,
      legacy: AshVault.Test.LegacyJsonMap,
      stored_as: :sealed_settings,
      encrypt_nil?: false,
      decrypt_for: [&AshVault.Test.Admin.admin?/1]
    )
  end

  ets do
    private?(true)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :string, allow_nil?: false, public?: true)
    attribute(:name, :string, allow_nil?: false, public?: true)
    attribute(:token, :binary, public?: true, sensitive?: true)
    attribute(:settings, :map, public?: true, sensitive?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy])

    create :create do
      primary?(true)
    end

    update :update do
      primary?(true)
      require_atomic?(false)
    end

    update :rename do
      accept([:name])
    end

    update :clear_token do
      accept([])
      change(set_attribute(:token, nil))
    end

    update :replace_token do
      accept([:token])
    end

    update :rotate_in_hook do
      accept([])
      require_atomic?(false)

      change(fn changeset, _context ->
        Ash.Changeset.before_action(changeset, fn changeset ->
          Ash.Changeset.force_change_attribute(changeset, :token, "rotated-in-hook")
        end)
      end)
    end

    update :vault_backfill do
      accept([])
      require_atomic?(false)
    end

    read :with_secrets
  end
end

defmodule AshVault.Test.EtsLegacyUpsert do
  @moduledoc "Expand mode under an upsert whose `upsert_fields` lists only the legacy column."

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:token,
      legacy: AshVault.Test.LegacyBinary,
      decrypt_for: [AshVault.Test.Checks.IsAdmin]
    )
  end

  ets do
    private?(true)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :string, allow_nil?: false, public?: true)
    attribute(:name, :string, allow_nil?: false, public?: true)
    attribute(:token, :binary, allow_nil?: false, public?: true, sensitive?: true)
  end

  identities do
    identity(:unique_name, [:name], pre_check_with: AshVault.Test.Domain)
  end

  actions do
    default_accept(:*)
    defaults([:read])

    create :upsert do
      upsert?(true)
      upsert_identity(:unique_name)
      upsert_fields([:token])
    end
  end
end

defmodule AshVault.Test.PgLegacyAccount do
  @moduledoc "The PostgreSQL twin of `AshVault.Test.EtsLegacyAccount`, for the atomic paths."

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:token,
      legacy: AshVault.Test.LegacyBinary,
      encrypt_nil?: false,
      decrypt_for: [AshVault.Test.Checks.IsAdmin]
    )
  end

  postgres do
    table("legacy_accounts")
    repo(AshVault.Test.Repo)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :uuid, allow_nil?: false, public?: true)
    attribute(:name, :string, allow_nil?: false, public?: true)
    attribute(:token, :binary, public?: true, sensitive?: true)
  end

  identities do
    identity(:unique_name, [:name])
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy])

    create :create do
      primary?(true)
    end

    create :upsert do
      upsert?(true)
      upsert_identity(:unique_name)
      upsert_fields([:token])
    end

    update :rename do
      accept([:name])
    end

    update :replace_token do
      accept([:token])
    end

    update :clear_token do
      accept([])
      change(set_attribute(:token, nil))
    end
  end
end

defmodule AshVault.Test.EtsDecryptForDoc do
  @moduledoc "An end-state field (no `legacy:`) restricted with `decrypt_for:`."

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.GlobalVault)
    scope(:global)
    encrypt(:token, decrypt_for: [AshVault.Test.Checks.IsAdmin])
  end

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:token, :string, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, create: :*])
  end
end
