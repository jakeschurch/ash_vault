import Config

if config_env() == :test do
  # `AshVaultRustler.Cipher` shares the id `:aes_256_gcm_v1` with the built-in cipher,
  # which is what makes the two interchangeable on stored bytes. The consequence is that
  # a vault's `:cipher` option governs ENCRYPTION only — `AshVault.Vault.Runtime.decrypt!/3`
  # resolves the cipher from the envelope through `AshVault.Cipher.registry/0`, so without
  # this line every value would be decrypted by the pure-Elixir implementation. That is
  # harmless for a binary key and impossible for an opaque one, which is why the README
  # says to set both.
  config :ash_vault, :ciphers, %{"aes_256_gcm_v1" => AshVaultRustler.Cipher}
end
