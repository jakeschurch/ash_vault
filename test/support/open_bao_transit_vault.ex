defmodule AshVault.Test.Support.TransitVault do
  @moduledoc """
  A tenant-scoped vault pairing `AshVault.KeyProviders.OpenBaoTransit` with
  `AshVault.Ciphers.OpenBaoTransit` — the non-exporting combination, where the AEAD runs
  inside OpenBao and no key material ever enters the BEAM.

  Used by the `:openbao`-tagged suites. Defining it here rather than inside a test file
  keeps it available to every suite regardless of load order, and proves the pairing
  survives `AshVault.Vault.verify_key_sizes!/2` at compile time.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.OpenBaoTransit,
    cipher: AshVault.Ciphers.OpenBaoTransit
end

defmodule AshVault.Test.Support.TransitWithLocalCipherVault do
  @moduledoc """
  A deliberately wrong pairing: the non-exporting provider under a local cipher that can
  only work on raw key bytes.

  Exists to prove the failure is named — `AshVault.Errors.OpaqueKeyUnsupported`, pointing
  at both modules — rather than silently unwrapped or reported as tampering.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.OpenBaoTransit,
    cipher: AshVault.Ciphers.AES.GCM
end
