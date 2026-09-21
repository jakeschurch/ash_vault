defmodule AshVault.Test.Support.Resources do
  @moduledoc """
  Plain module names standing in for Ash resources in crypto-core tests.

  The crypto core only ever puts the resource module into the AAD via `inspect/1`, so
  these need no behaviour of their own.
  """

  defmodule User do
    @moduledoc "Stand-in resource used in AshVault crypto-core tests."
  end

  defmodule Invoice do
    @moduledoc "Second stand-in resource, for cross-resource AAD tests."
  end
end

defmodule AshVault.Test.Support.TenantVault do
  @moduledoc """
  Tenant-scoped test vault backed by the default-named in-memory key provider.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Memory
end

defmodule AshVault.Test.Support.GlobalVault do
  @moduledoc """
  Globally-scoped test vault backed by the default-named in-memory key provider.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Scopes.Global
end

defmodule AshVault.Test.Support.Helpers do
  @moduledoc """
  Helpers shared by the AshVault crypto-core test suites.
  """

  alias AshVault.Test.Support.Resources

  @doc """
  Build an `AshVault.Context` with sensible test defaults.
  """
  @spec context(keyword()) :: AshVault.Context.t()
  def context(opts \\ []) do
    %AshVault.Context{
      resource: Keyword.get(opts, :resource, Resources.User),
      field: Keyword.get(opts, :field, :ssn),
      ash_context: Keyword.get(opts, :ash_context, %{tenant: "acme", actor: nil, context: %{}})
    }
  end

  @doc """
  Build an `AshVault.Context` for a given tenant.
  """
  @spec context_for(term(), keyword()) :: AshVault.Context.t()
  def context_for(tenant, opts \\ []) do
    opts
    |> Keyword.put(:ash_context, %{tenant: tenant, actor: nil, context: %{}})
    |> context()
  end
end

defmodule AshVault.Test.Support.RotateOnWritePolicy do
  @moduledoc """
  A rotation policy that rotates on every write once the key is a moment old.
  """

  @behaviour AshVault.RotationPolicy

  alias AshVault.RotationPolicy

  @policy %RotationPolicy{
    strategy: :age,
    max_age: Duration.new!(second: 0),
    rotate_on_write?: true
  }

  @doc "Always returns an age-based, rotate-on-write policy."
  @impl AshVault.RotationPolicy
  @spec policy(term(), AshVault.Context.t()) :: RotationPolicy.t()
  def policy(_scope, _context), do: @policy
end

defmodule AshVault.Test.Support.FailingRotateProvider do
  @moduledoc """
  A key provider with a fixed key whose `rotate/1` always fails.

  Used to prove that a failed opportunistic rotation never fails a write.
  """

  @behaviour AshVault.KeyProvider

  @key <<7::256>>

  @doc false
  @impl AshVault.KeyProvider
  def current_key(_scope) do
    {:ok, %{version: 1, key: @key, created_at: ~U[2000-01-01 00:00:00Z]}}
  end

  @doc false
  @impl AshVault.KeyProvider
  def get_key(_scope, 1), do: {:ok, @key}
  def get_key(_scope, _version), do: {:error, :not_found}

  @doc false
  @impl AshVault.KeyProvider
  def rotate(_scope), do: {:error, :boom}

  @doc false
  @impl AshVault.KeyProvider
  def destroy(_scope), do: {:error, :boom}
end

defmodule AshVault.Test.Support.UnavailableProvider do
  @moduledoc """
  A key provider that is always down, for provider-error mapping tests.
  """

  @behaviour AshVault.KeyProvider

  @doc false
  @impl AshVault.KeyProvider
  def current_key(_scope), do: {:error, :timeout}

  @doc false
  @impl AshVault.KeyProvider
  def get_key(_scope, _version), do: {:error, :timeout}

  @doc false
  @impl AshVault.KeyProvider
  def rotate(_scope), do: {:error, :timeout}

  @doc false
  @impl AshVault.KeyProvider
  def destroy(_scope), do: {:error, :timeout}
end

defmodule AshVault.Test.Support.FailingRotateVault do
  @moduledoc "Vault whose provider always fails to rotate, with rotate-on-write enabled."

  use AshVault.Vault,
    key_provider: AshVault.Test.Support.FailingRotateProvider,
    rotation_policy: AshVault.Test.Support.RotateOnWritePolicy
end

defmodule AshVault.Test.Support.UnavailableVault do
  @moduledoc "Vault backed by a permanently unavailable provider."

  use AshVault.Vault, key_provider: AshVault.Test.Support.UnavailableProvider
end

defmodule AshVault.Test.Support.RotatingVault do
  @moduledoc "Tenant-scoped vault with rotate-on-write enabled, over the memory provider."

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    rotation_policy: AshVault.Test.Support.RotateOnWritePolicy
end
