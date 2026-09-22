defmodule AshVault.Test.Vault do
  @moduledoc """
  The vault the extension-layer test resources encrypt with.

  Backed by the default-named `AshVault.KeyProviders.Memory`, which every test that
  touches encryption starts with `start_supervised!({Memory, name: Memory})`.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Memory
end

defmodule AshVault.Test.GlobalVault do
  @moduledoc """
  A globally-scoped vault.

  The *effective* encryption scope is the vault's, so a resource declaring
  `scope :global` must be paired with a vault whose scope module is
  `AshVault.Scopes.Global`. `AshVault.Verifiers.VerifyVault` enforces that agreement.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Scopes.Global
end

defmodule AshVault.Test.DynamicVault do
  @moduledoc """
  A `fun/2` vault resolver, used to prove that the dynamic `vault` forms receive the
  normalized `ash_context` map on every path.
  """

  @doc "Record the context shape we were handed, then return the ordinary test vault."
  @spec resolve(module(), term()) :: module()
  def resolve(_resource, context) do
    if pid = Process.whereis(:ash_vault_dynamic_vault_probe) do
      send(pid, {:dynamic_vault_context, context})
    end

    AshVault.Test.Vault
  end
end

defmodule AshVault.Test.NotAVault do
  @moduledoc "A module that is emphatically not an AshVault vault, for verifier tests."
end
