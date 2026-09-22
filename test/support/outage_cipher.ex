defmodule AshVault.Test.Support.OutageCipher do
  @moduledoc """
  A cipher that encrypts normally but whose `decrypt/3` always reports an infrastructure
  outage, as `AshVault.Ciphers.OpenBaoTransit` does for a 403 or an unreachable server.

  `AshVault.Vault.Runtime.decrypt!/3` turns any unrecognised cipher error into
  `AshVault.Errors.CiphertextIntegrityFailed` — "your data was tampered with". For a
  cipher that reaches over the network that is a lie, so the runtime re-raises a
  `AshVault.Errors.ProviderUnavailable` unchanged. This module is how that is asserted
  without a live server.
  """

  @behaviour AshVault.Cipher

  alias AshVault.Errors.ProviderUnavailable

  @doc false
  @impl AshVault.Cipher
  def id, do: :test_outage_v1

  @doc false
  @impl AshVault.Cipher
  def key_bytes, do: 32

  @doc false
  @impl AshVault.Cipher
  defdelegate encrypt(plaintext, key, aad), to: AshVault.Ciphers.AES.GCM

  @doc false
  @impl AshVault.Cipher
  def decrypt(_payload, _key, _aad) do
    {:error, ProviderUnavailable.exception(provider: __MODULE__, reason: :simulated_outage)}
  end
end

defmodule AshVault.Test.Support.OutageCipherVault do
  @moduledoc """
  A vault pairing the in-memory key provider with `AshVault.Test.Support.OutageCipher`.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    cipher: AshVault.Test.Support.OutageCipher
end
