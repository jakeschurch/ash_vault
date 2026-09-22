defmodule AshVault.KeyProviderTest do
  @moduledoc """
  The provider lifecycle and configuration surfaces a host application uses:
  `AshVault.KeyProvider.children/1`, `setup/1` and `config/1`.

  These exist because a host had to write one `case` over provider modules in its
  `Application` and a second one in its setup task — `AshVault.KeyProviders.Local` needs
  a supervised child *and* an initialised root, `AshVault.KeyProviders.OpenBao` needs no
  child and a mounted KV engine, `AshVault.KeyProviders.Memory` needs a child and no
  setup.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProvider
  alias AshVault.KeyProviders.Local
  alias AshVault.KeyProviders.Memory
  alias AshVault.KeyProviders.OpenBao

  defmodule MemoryVault do
    @moduledoc false
    use AshVault.Vault, key_provider: Memory
  end

  defmodule BaoVault do
    @moduledoc false
    use AshVault.Vault, key_provider: OpenBao
  end

  defmodule CachedBaoVault do
    @moduledoc false
    use AshVault.Vault, key_provider: OpenBao, cache: [ttl: 10]
  end

  defmodule NoCallbacksProvider do
    @moduledoc "A third-party provider defining neither optional callback."
    @behaviour AshVault.KeyProvider

    @impl true
    def current_key(_scope), do: {:error, :not_found}
    @impl true
    def get_key(_scope, _version), do: {:error, :not_found}
    @impl true
    def rotate(_scope), do: {:error, :not_found}
    @impl true
    def destroy(_scope), do: :ok
  end

  defmodule ThirdPartyVault do
    @moduledoc false
    use AshVault.Vault, key_provider: NoCallbacksProvider
  end

  describe "children/1" do
    test "a supervised provider contributes itself" do
      assert KeyProvider.children(MemoryVault) == [Memory]
      assert KeyProvider.children(Memory) == [Memory]
    end

    test "a provider that owns no process contributes nothing" do
      assert KeyProvider.children(BaoVault) == []
      assert KeyProvider.children(OpenBao) == []
    end

    test "a third-party provider defining no child_spec/1 keeps working" do
      assert KeyProvider.children(ThirdPartyVault) == []
    end

    test "a cached vault supervises the wrapper, not the provider it wraps" do
      # OpenBao owns no process; the generated wrapper owns the cache and must be
      # started. Asking the *provider* would have missed it entirely.
      assert KeyProvider.children(CachedBaoVault) == [CachedBaoVault.CachedKeyProvider]
    end
  end

  describe "setup/1" do
    test "is :ok for a provider with no setup step" do
      assert KeyProvider.setup(MemoryVault) == :ok
      assert KeyProvider.setup(Memory) == :ok
    end

    test "is :ok for a third-party provider defining no setup/0" do
      assert KeyProvider.setup(ThirdPartyVault) == :ok
    end

    test "a vault exposes the same two answers as one-liners" do
      assert MemoryVault.child_specs() == [Memory]
      assert MemoryVault.setup() == :ok
    end
  end

  describe "config/1" do
    setup do
      previous_ash_vault = Application.get_env(:ash_vault, Local)
      previous_pointer = Application.get_env(:ash_vault, :otp_app)

      on_exit(fn ->
        restore(:ash_vault, Local, previous_ash_vault)
        restore(:ash_vault, :otp_app, previous_pointer)
        Application.delete_env(:fake_host_app, Local)
      end)

      :ok
    end

    test "the :ash_vault OTP key still works on its own" do
      Application.put_env(:ash_vault, Local, root: "/from/ash_vault", key_bytes: 32)
      Application.delete_env(:ash_vault, :otp_app)

      assert KeyProvider.config(Local)[:root] == "/from/ash_vault"
    end

    test "a host application's own OTP key is consulted, and wins key by key" do
      Application.put_env(:ash_vault, Local, root: "/from/ash_vault", key_bytes: 32)
      Application.put_env(:fake_host_app, Local, root: "/from/host")
      Application.put_env(:ash_vault, :otp_app, :fake_host_app)

      config = KeyProvider.config(Local)

      # The host's value wins where both set it...
      assert config[:root] == "/from/host"
      # ...and the :ash_vault value survives where the host is silent, so an existing
      # configuration does not have to be moved wholesale.
      assert config[:key_bytes] == 32
    end

    test "a host application's OTP key works with no :ash_vault config at all" do
      Application.delete_env(:ash_vault, Local)
      Application.put_env(:fake_host_app, Local, root: "/only/host")
      Application.put_env(:ash_vault, :otp_app, :fake_host_app)

      assert KeyProvider.config(Local)[:root] == "/only/host"
    end
  end

  describe "otp_apps/0" do
    test "a vault registers the application it was compiled into" do
      # These vaults are compiled into :ash_vault itself, which is already `config/1`'s
      # base, so registering it is a no-op rather than a duplicate lookup.
      assert MemoryVault.__ash_vault_register_otp_app__() == :ok
      refute :ash_vault in KeyProvider.otp_apps()
    end

    test "registering nil is a no-op" do
      assert KeyProvider.register_otp_app(nil) == :ok
    end
  end

  defp restore(app, key, nil), do: Application.delete_env(app, key)
  defp restore(app, key, value), do: Application.put_env(app, key, value)
end
