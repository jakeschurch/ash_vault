defmodule Mix.Tasks.AshVault.DestroyKeys do
  @shortdoc "Crypto-erase a scope: destroy every key version. IRREVERSIBLE"

  @moduledoc """
  Cryptographically erase an AshVault scope.

  > #### This is irreversible {: .error}
  >
  > Every value ever encrypted under the scope becomes permanently unrecoverable. There
  > is no undo, no backup of the key, and no support ticket that brings it back. The
  > provider writes a **tombstone**, so the scope can never be re-minted either —
  > silently re-minting would turn crypto-erasure into silent data loss.

  ## Usage

      mix ash_vault.destroy_keys MyApp.Accounts.User --tenant acme

  The task prints the scope, every resource and field that is about to become
  undecryptable, and the current key version. It then asks you to **type the scope name
  back**. `--yes` does not skip that prompt, and there is deliberately no `--force`: a
  deploy script cannot destroy a tenant's data by passing one more flag.

  In `MIX_ENV=prod` it additionally refuses to run unless `MIX_ENV` was passed explicitly
  or `--i-know-what-this-does` is given.

  ## Options

      --tenant TENANT            required when the key scope is `:tenant`
      --domain MODULE            Ash domain (inferred from `:ash_domains` when omitted)
      --i-know-what-this-does    required in production
      --yes                      skips *other* confirmations; never the scope prompt

  ## Idempotence

  Destroying an already-destroyed scope prints `status=already_destroyed` and exits 0. It
  does not prompt, because there is nothing left to lose.

  ## Output

      ash_vault.destroy_keys=target resource=MyApp.Accounts.User tenant=acme scope=acme \\
        vault=MyApp.Vault provider=MyApp.KeyProvider status=active version=3 fields=4
      undecryptable=MyApp.Accounts.User.email
      undecryptable=MyApp.Accounts.User.ssn
      ash_vault.destroy_keys=done scope=acme versions_destroyed=3 tombstone=confirmed
      DESTROYED MyApp.Vault scope acme: 3 key version(s), 4 field(s) across 2 resource(s).

  The tombstone is re-read from the provider before success is reported: if the provider
  does not answer `{:error, :destroyed}` afterwards, the task exits non-zero rather than
  claiming an erasure that did not happen.
  """

  use Mix.Task

  alias AshVault.Mix.Shared

  @switches [
    tenant: :string,
    domain: :string,
    yes: :boolean,
    i_know_what_this_does: :boolean
  ]

  @requirements ["app.start"]

  @doc false
  @impl Mix.Task
  def run(argv) do
    Shared.start_app!(argv)

    {opts, args} = OptionParser.parse!(argv, strict: @switches)

    resource =
      case args do
        [resource] -> Shared.resource!(resource)
        _ -> Shared.abort!("usage: mix ash_vault.destroy_keys RESOURCE --tenant TENANT")
      end

    check_env!(opts)

    %{vault: vault, scope: scope, provider: provider} =
      Shared.resolve!(resource, opts[:tenant])

    fields = Shared.encrypted_fields_for_vault(Shared.domains(opts), vault, opts[:tenant])

    case Shared.key_state(provider, scope) do
      :destroyed ->
        Shared.kv(
          "ash_vault.destroy_keys": "target",
          resource: resource,
          tenant: opts[:tenant],
          scope: scope,
          vault: vault,
          provider: provider,
          status: "already_destroyed"
        )

        Shared.say(
          "#{inspect(vault)} scope #{Shared.format(scope)} was already destroyed. Nothing to do."
        )

      :not_minted ->
        Shared.abort!(
          "#{inspect(vault)} scope #{Shared.format(scope)} has no key to destroy. " <>
            "Nothing has ever been encrypted under it."
        )

      {:error, reason} ->
        Shared.abort!(
          Exception.message(
            AshVault.Errors.ProviderUnavailable.exception(provider: provider, reason: reason)
          )
        )

      {:active, info} ->
        destroy!(resource, opts, vault, scope, provider, fields, info)
    end
  end

  defp destroy!(resource, opts, vault, scope, provider, fields, info) do
    Shared.kv(
      "ash_vault.destroy_keys": "target",
      resource: resource,
      tenant: opts[:tenant],
      scope: scope,
      vault: vault,
      provider: provider,
      status: "active",
      version: info.version,
      versions: info.versions,
      fields: length(fields)
    )

    Enum.each(fields, fn {field_resource, field} ->
      Shared.kv(undecryptable: "#{inspect(field_resource)}.#{field}")
    end)

    Shared.say("""

    #{banner()}
    About to destroy every key version (#{Enum.join(info.versions, ", ")}) for scope \
    #{Shared.format(scope)} in #{inspect(vault)}.

    #{length(fields)} field(s) across #{fields |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length()} \
    resource(s) will become permanently undecryptable. This cannot be undone.
    """)

    confirm_scope!(scope)

    AshVault.destroy_keys!(vault, scope)

    confirm_tombstone!(provider, scope)

    Shared.kv(
      "ash_vault.destroy_keys": "done",
      scope: scope,
      versions_destroyed: length(info.versions),
      tombstone: "confirmed"
    )

    Shared.say(
      "DESTROYED #{inspect(vault)} scope #{Shared.format(scope)}: " <>
        "#{length(info.versions)} key version(s), #{length(fields)} field(s) across " <>
        "#{fields |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length()} resource(s)."
    )
  end

  defp banner do
    "!! IRREVERSIBLE CRYPTOGRAPHIC ERASURE !!"
  end

  defp confirm_scope!(scope) do
    expected = Shared.format(scope)
    typed = Mix.shell().prompt("Type the scope back to confirm (#{expected}): ")

    if is_binary(typed) and String.trim(typed) == expected do
      :ok
    else
      Shared.abort!("scope confirmation did not match; nothing was destroyed.")
    end
  end

  defp confirm_tombstone!(provider, scope) do
    with {:error, :destroyed} <- provider.current_key(scope),
         {:error, :destroyed} <- provider.get_key(scope, 1) do
      :ok
    else
      other ->
        Shared.abort!("""
        The provider did not confirm a tombstone for scope #{Shared.format(scope)}.

        It answered #{inspect(other)} where `{:error, :destroyed}` was expected, so the
        erasure cannot be reported as complete. Investigate #{inspect(provider)} before
        assuming this scope is erased.
        """)
    end
  end

  defp check_env!(opts) do
    if Mix.env() == :prod and is_nil(System.get_env("MIX_ENV")) and
         !opts[:i_know_what_this_does] do
      Shared.abort!("""
      Refusing to run in production without an explicit environment.

      Re-run as `MIX_ENV=prod mix ash_vault.destroy_keys ...`, or pass
      `--i-know-what-this-does`.
      """)
    end
  end
end
