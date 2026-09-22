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

defmodule AshVault.Test.Support.ShortKeyProvider do
  @moduledoc """
  A provider that *claims* 32-byte keys but serves 16-byte ones.

  This is what a truncated `v1.key` on disk, or a provider whose runtime configuration
  drifted from its compile-time answer, looks like from the cipher's side. The
  compile-time check in `AshVault.Vault.verify_key_sizes!/2` cannot catch it, which is
  exactly why the runtime branches have to.
  """

  @behaviour AshVault.KeyProvider

  @key <<7::128>>

  @doc false
  @impl AshVault.KeyProvider
  def key_bytes, do: 32

  @doc false
  @impl AshVault.KeyProvider
  def current_key(_scope),
    do: {:ok, %{version: 1, key: @key, created_at: ~U[2000-01-01 00:00:00Z]}}

  @doc false
  @impl AshVault.KeyProvider
  def get_key(_scope, _version), do: {:ok, @key}

  @doc false
  @impl AshVault.KeyProvider
  def rotate(_scope), do: {:ok, 1}

  @doc false
  @impl AshVault.KeyProvider
  def destroy(_scope), do: :ok
end

defmodule AshVault.Test.Support.ShortKeyVault do
  @moduledoc "Vault whose provider serves keys of the wrong size."

  use AshVault.Vault, key_provider: AshVault.Test.Support.ShortKeyProvider
end

defmodule AshVault.Test.Support.DestroyedRotateProvider do
  @moduledoc """
  A fixed-key provider whose `rotate/1` reports `{:error, :destroyed}`.

  Models a write racing a `destroy!`: `rotate_best_effort` used to swallow this, log a
  warning, and encrypt under the pre-destroy key — a "successful" write storing
  ciphertext nobody can ever read.
  """

  @behaviour AshVault.KeyProvider

  @key <<9::256>>

  @doc false
  @impl AshVault.KeyProvider
  def current_key(_scope),
    do: {:ok, %{version: 1, key: @key, created_at: ~U[2000-01-01 00:00:00Z]}}

  @doc false
  @impl AshVault.KeyProvider
  def get_key(_scope, 1), do: {:ok, @key}
  def get_key(_scope, _version), do: {:error, :not_found}

  @doc false
  @impl AshVault.KeyProvider
  def rotate(_scope), do: {:error, :destroyed}

  @doc false
  @impl AshVault.KeyProvider
  def destroy(_scope), do: :ok
end

defmodule AshVault.Test.Support.DestroyedRotateVault do
  @moduledoc "Rotate-on-write vault whose provider reports the scope as destroyed."

  use AshVault.Vault,
    key_provider: AshVault.Test.Support.DestroyedRotateProvider,
    rotation_policy: AshVault.Test.Support.RotateOnWritePolicy
end

defmodule AshVault.Test.Support.NonBinaryScope do
  @moduledoc "A scope implementation that returns a term rather than a binary."

  @behaviour AshVault.Scope

  @doc false
  @impl AshVault.Scope
  def resolve!(_context), do: {:tenant, "acme"}
end

defmodule AshVault.Test.Support.NonBinaryScopeVault do
  @moduledoc "Vault with a custom scope that violates the binary-scope invariant."

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Test.Support.NonBinaryScope
end

defmodule AshVault.Test.Support.PiiTenant do
  @moduledoc """
  A tenant-shaped struct carrying PII, for proving that errors describe it rather than
  print it. A real tenant record looks exactly like this.
  """

  defstruct [:id, :name, :billing_email]
end

defmodule AshVault.Test.Support.StructScope do
  @moduledoc "A scope implementation that returns a loaded tenant record, not a binary."

  @behaviour AshVault.Scope

  @doc false
  @impl AshVault.Scope
  def resolve!(_context) do
    %AshVault.Test.Support.PiiTenant{
      id: "org_1a2b3c",
      name: "Acme Holdings",
      billing_email: "cfo@acme.example"
    }
  end
end

defmodule AshVault.Test.Support.StructScopeVault do
  @moduledoc "Vault whose custom scope returns a PII-bearing struct instead of a binary."

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Test.Support.StructScope
end

defmodule AshVault.Test.Support.FixedKeyVault do
  @moduledoc """
  A vault whose provider hands out the SAME key for every scope, with manual rotation.

  This is what makes a cross-scope decrypt test prove what it claims: with per-scope
  keys, the failure could come from the key differing rather than from the AAD binding
  the scope. Here only the AAD differs.
  """

  use AshVault.Vault, key_provider: AshVault.Test.Support.FailingRotateProvider
end

defmodule AshVault.Test.Support.LocalVaultForTests do
  @moduledoc """
  A vault over the filesystem provider, for end-to-end tests that need key material to
  survive a provider restart. Talks to the default-named `AshVault.KeyProviders.Local`.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end
