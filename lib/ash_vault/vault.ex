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
