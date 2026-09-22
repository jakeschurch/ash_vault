defmodule AshVault.Test.DeadKeyProvider do
  @moduledoc """
  A key provider that is always unreachable.

  It exists so `test/mix/` can simulate a provider that disappears mid-run without
  stopping the shared `AshVault.KeyProviders.Memory` process (which ExUnit would
  restart, silently re-minting keys).
  """

  @behaviour AshVault.KeyProvider

  @error {:error, :econnrefused}

  @doc false
  @impl AshVault.KeyProvider
  def current_key(_scope), do: @error

  @doc false
  @impl AshVault.KeyProvider
  def get_key(_scope, _version), do: @error

  @doc false
  @impl AshVault.KeyProvider
  def rotate(_scope), do: @error

  @doc false
  @impl AshVault.KeyProvider
  def destroy(_scope), do: @error
end

defmodule AshVault.Test.DeadVault do
  @moduledoc "A vault whose provider is always unreachable."

  use AshVault.Vault, key_provider: AshVault.Test.DeadKeyProvider
end

defmodule AshVault.Test.LegacyVault do
  @moduledoc """
  `AshVault.Test.LegacyUser`'s vault resolver.

  Normally `AshVault.Test.Vault`. Setting the `:ash_vault_test_legacy_vault_broken`
  process/global flag swaps in `AshVault.Test.DeadVault`, which lets a backfill test
  make the provider "go away" at a precise batch boundary.
  """

  @counter {__MODULE__, :calls}
  @break_after {__MODULE__, :break_after}

  @doc "Resolve the vault for `AshVault.Test.LegacyUser`."
  @spec resolve(module(), term()) :: module()
  def resolve(_resource, _context) do
    calls = :counters.add(counter(), 1, 1)
    _ = calls

    if broken?(), do: AshVault.Test.DeadVault, else: AshVault.Test.Vault
  end

  @doc "How many times the resolver has been called since `reset!/0`."
  @spec calls() :: non_neg_integer()
  def calls, do: :counters.get(counter(), 1)

  @doc "Whether the resolver is currently handing back the dead vault."
  @spec broken?() :: boolean()
  def broken? do
    case :persistent_term.get(@break_after, nil) do
      nil -> false
      n -> calls() > n
    end
  end

  @doc """
  Hand back `AshVault.Test.DeadVault` once the resolver has been called more than `n`
  times, simulating a key provider that disappears part way through a run.
  """
  @spec break_after!(non_neg_integer()) :: :ok
  def break_after!(n), do: :persistent_term.put(@break_after, n)

  @doc "Forget any scheduled breakage and zero the call counter."
  @spec reset!() :: :ok
  def reset! do
    :persistent_term.put(@break_after, nil)
    :counters.put(counter(), 1, 0)
    :ok
  end

  defp counter do
    case :persistent_term.get(@counter, nil) do
      nil ->
        ref = :counters.new(1, [:atomics])
        :persistent_term.put(@counter, ref)
        ref

      ref ->
        ref
    end
  end
end

defmodule AshVault.Test.LegacyUser do
  @moduledoc """
  A resource mid-migration: `legacy_email` still holds plaintext, `encrypted_email` is
  the freshly-expanded ciphertext column, and `mix ash_vault.backfill` is what moves one
  into the other.

  This is the "expand" state of EXTENSION_SPEC §20: the encrypted field is already under
  `ash_vault` (so the transformer has created `encrypted_email` and the decrypt
  calculation), while the plaintext column survives until the contract migration.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault &AshVault.Test.LegacyVault.resolve/2
    scope :tenant

    encrypt :email, backfill_from: :legacy_email
    encrypt :ssn, encrypt_nil?: false, backfill_from: :legacy_ssn
  end

  postgres do
    table "legacy_users"
    repo AshVault.Test.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :legacy_email, :string, public?: true
    attribute :legacy_ssn, :string, public?: true
    attribute :email, :string, public?: true
    attribute :ssn, :string, public?: true, allow_nil?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*]

    update :update do
      primary? true
      require_atomic? false
    end

    update :update_atomic do
      require_atomic? true
    end
  end
end

defmodule AshVault.Test.LegacySearchDomain do
  @moduledoc """
  A domain of its own for the searchable-backfill fixtures.

  They are ETS-backed and self-contained, so keeping them out of
  `AshVault.Test.Domain` keeps the `:postgres`-tagged fixtures and this pair independent.
  """

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(AshVault.Test.LegacySearchUser)
    resource(AshVault.Test.LegacyPlainSearchUser)
  end
end

defmodule AshVault.Test.LegacySearchUser do
  @moduledoc """
  A resource mid-migration whose encrypted field is also `searchable?: true`, with a
  lossy `normalize:`.

  This is the combination `backfill_from:` + `searchable?: true` — the one that used to
  write half a row: ciphertext holding the *un-normalized* legacy value and a NULL
  `email_lookup`, which `verify` then confirmed as correct.

  ETS rather than PostgreSQL, so the fixture needs no migration and no shared table to
  truncate.
  """

  use Ash.Resource,
    domain: AshVault.Test.LegacySearchDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email,
      searchable?: true,
      normalize: :downcase_trim,
      backfill_from: :legacy_email
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :legacy_email, :string, public?: true
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*]

    update :update do
      primary? true
      require_atomic? false
    end
  end
end

defmodule AshVault.Test.LegacyPlainSearchUser do
  @moduledoc """
  `AshVault.Test.LegacySearchUser` with `normalize: :none`.

  The token is still mandatory here — a NULL one is just as unfindable — but nothing
  about the ciphertext changes, which is what isolates "the token was never written" from
  "the value was normalized".
  """

  use Ash.Resource,
    domain: AshVault.Test.LegacySearchDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email,
      searchable?: true,
      normalize: :none,
      backfill_from: :legacy_email
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :legacy_email, :string, public?: true
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*]

    update :update do
      primary? true
      require_atomic? false
    end
  end
end
