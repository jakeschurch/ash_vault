defmodule AshVault.Vault do
  @moduledoc """
  Defines a vault: the bundle of key provider, cipher, envelope, scope and rotation
  policy that an application encrypts with.

      defmodule MyApp.Vault do
        use AshVault.Vault, key_provider: MyApp.KeyProvider
      end

      MyApp.Vault.encrypt!("secret", %AshVault.Context{
        resource: MyApp.User,
        field: :ssn,
        ash_context: %{tenant: "acme"}
      })

  ## Options

    * `:key_provider` — **required**, an `AshVault.KeyProvider`
    * `:cipher` — an `AshVault.Cipher`, defaults to `AshVault.Ciphers.AES.GCM`
    * `:envelope` — an `AshVault.Envelope`, defaults to `AshVault.Envelope.V1`
    * `:scope` — an `AshVault.Scope`, defaults to `AshVault.Scopes.AshTenant`
    * `:rotation_policy` — an `AshVault.RotationPolicy`, defaults to
      `AshVault.RotationPolicies.Manual`

  The generated module is a thin set of delegations to `AshVault.Vault.Runtime`.
  """

  @doc "Encrypt a plaintext for a context, returning an encoded envelope."
  @callback encrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Decrypt an encoded envelope for a context, returning the plaintext."
  @callback decrypt!(binary(), AshVault.Context.t()) :: binary()

  @doc "Rotate the key for a scope."
  @callback rotate!(scope :: term()) :: {:ok, non_neg_integer()}

  @doc "Crypto-erase every key for a scope."
  @callback destroy!(scope :: term()) :: :ok

  @doc "Introspect the vault's compile-time configuration."
  @callback __ash_vault__(:key_provider | :cipher | :envelope | :scope | :rotation_policy) ::
              module()

  @doc """
  Compile-time guard: the key provider's key size must match the cipher's.

  Called from the `use AshVault.Vault` macro. `AshVault.KeyProvider.key_bytes/1` had
  zero callers, so a `key_bytes: 16` in config, an OpenBao `key_type: "aes128-gcm96"`,
  or a truncated key file on disk all reached the cipher unchecked — and were then
  reported as two different lies: `AshVault.Errors.AuthenticationFailed` on decrypt
  ("your data was tampered with", for a config typo) and a retryable
  `AshVault.Errors.ProviderUnavailable` naming the *cipher* as the provider on encrypt.

  The check is deliberately conservative. It fires only when it can positively
  determine a mismatch: both modules must already be compiled and both must export
  `key_bytes/0`. A provider whose size depends on runtime configuration —
  `AshVault.KeyProviders.OpenBao` reads `:key_type` from `Application.get_env/3`, which
  operators set in `runtime.exs` — cannot be settled at compile time, and a provider
  module may not even be compiled yet when the vault macro expands. Anything
  unresolvable passes here; `AshVault.Vault.Runtime` raises
  `AshVault.Errors.KeySizeMismatch` at the point of use, which is what actually carries
  the guarantee.
  """
  @spec verify_key_sizes!(module(), map()) :: :ok
  def verify_key_sizes!(vault, %{key_provider: provider, cipher: cipher}) do
    with {:module, _} <- Code.ensure_compiled(provider),
         {:module, _} <- Code.ensure_compiled(cipher),
         true <- function_exported?(provider, :key_bytes, 0),
         true <- function_exported?(cipher, :key_bytes, 0),
         provider_bytes when is_integer(provider_bytes) <- safe_key_bytes(provider),
         cipher_bytes when is_integer(cipher_bytes) <- safe_key_bytes(cipher),
         true <- provider_bytes != cipher_bytes do
      raise ArgumentError, """
      #{inspect(vault)} is misconfigured: its key provider and cipher disagree on key size.

        #{inspect(provider)}.key_bytes() == #{provider_bytes}
        #{inspect(cipher)}.key_bytes()   == #{cipher_bytes}

      Every encryption would fail with AshVault.Errors.KeySizeMismatch. Either configure
      the provider to mint #{cipher_bytes}-byte keys, or choose a cipher that takes
      #{provider_bytes}-byte keys.
      """
    end

    :ok
  end

  defp safe_key_bytes(module) do
    module.key_bytes()
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour AshVault.Vault

      key_provider =
        opts[:key_provider] ||
          raise ArgumentError, """
          `use AshVault.Vault` requires a `:key_provider`.

              defmodule #{inspect(__MODULE__)} do
                use AshVault.Vault, key_provider: MyApp.KeyProvider
              end

          AshVault ships `AshVault.KeyProviders.Memory` for development and test.
          """

      @ash_vault_opts %{
        key_provider: key_provider,
        cipher: opts[:cipher] || AshVault.Ciphers.AES.GCM,
        envelope: opts[:envelope] || AshVault.Envelope.V1,
        scope: opts[:scope] || AshVault.Scopes.AshTenant,
        rotation_policy: opts[:rotation_policy] || AshVault.RotationPolicies.Manual
      }

      AshVault.Vault.verify_key_sizes!(__MODULE__, @ash_vault_opts)

      @doc "Encrypt a plaintext for a context, returning an encoded envelope."
      @impl AshVault.Vault
      @spec encrypt!(binary(), AshVault.Context.t()) :: binary()
      def encrypt!(plaintext, ctx),
        do: AshVault.Vault.Runtime.encrypt!(plaintext, ctx, @ash_vault_opts)

      @doc "Decrypt an encoded envelope for a context, returning the plaintext."
      @impl AshVault.Vault
      @spec decrypt!(binary(), AshVault.Context.t()) :: binary()
      def decrypt!(blob, ctx), do: AshVault.Vault.Runtime.decrypt!(blob, ctx, @ash_vault_opts)

      @doc "Rotate the key for a scope."
      @impl AshVault.Vault
      @spec rotate!(term()) :: {:ok, non_neg_integer()}
      def rotate!(scope), do: AshVault.Vault.Runtime.rotate!(scope, @ash_vault_opts)

      @doc "Crypto-erase every key for a scope."
      @impl AshVault.Vault
      @spec destroy!(term()) :: :ok
      def destroy!(scope), do: AshVault.Vault.Runtime.destroy!(scope, @ash_vault_opts)

      @doc "Introspect this vault's compile-time configuration."
      @impl AshVault.Vault
      @spec __ash_vault__(:key_provider | :cipher | :envelope | :scope | :rotation_policy) ::
              module()
      def __ash_vault__(key)
          when key in [:key_provider, :cipher, :envelope, :scope, :rotation_policy],
          do: Map.fetch!(@ash_vault_opts, key)
    end
  end
end
