defmodule AshVaultRustler.CachedProviders do
  @moduledoc """
  The two wrapped providers the contract suite runs against, defined once so both test
  modules use the identical configuration and differ only in backend.
  """

  defmodule CachedWithRust do
    @moduledoc false
    use AshVault.KeyProviders.Cached,
      provider: AshVault.KeyProviders.Memory,
      backend: AshVaultRustler.KeyCache,
      ttl: 60_000
  end

  defmodule CachedWithETS do
    @moduledoc false
    use AshVault.KeyProviders.Cached,
      provider: AshVault.KeyProviders.Memory,
      backend: AshVault.KeyCaches.ETS,
      ttl: 60_000
  end
end

defmodule AshVaultRustler.CachedProviderRustContractTest do
  @moduledoc """
  The parent's own `AshVault.KeyProvider` contract suite, run against
  `AshVault.KeyProviders.Cached` backed by the Rust cache.

  This is the same file the parent runs (`../test/support/key_provider_cases.ex`,
  compiled in via `elixirc_paths`), not a copy. A wrapper that changes any answer the
  contract specifies has broken the provider, and running the original is what keeps this
  from drifting away from what every other provider is held to.

  `async: false` because `AshVault.KeyProviders.Memory`'s callbacks take no server name,
  so the wrapped instance has to be the default-named one.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory
  alias AshVaultRustler.CachedProviders.CachedWithRust

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_provider/1

  @doc false
  def start_provider(_context) do
    start_supervised!({Memory, name: Memory})
    start_supervised!(CachedWithRust)

    %{
      provider: CachedWithRust,
      scope: fn -> "scope_#{System.unique_integer([:positive])}" end
    }
  end
end

defmodule AshVaultRustler.CachedProviderETSContractTest do
  @moduledoc """
  The same contract suite against the pure-Elixir cache backend, so that `cache: true`
  without the NIF is held to exactly the same standard.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory
  alias AshVaultRustler.CachedProviders.CachedWithETS

  use AshVault.Test.Support.KeyProviderCases, setup: &__MODULE__.start_provider/1

  @doc false
  def start_provider(_context) do
    start_supervised!({Memory, name: Memory})
    start_supervised!(CachedWithETS)

    %{
      provider: CachedWithETS,
      scope: fn -> "scope_#{System.unique_integer([:positive])}" end
    }
  end
end
