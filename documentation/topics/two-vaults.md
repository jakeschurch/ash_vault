# Two vaults in one application

A vault is resolved at **compile time**. `use AshVault.Vault` bakes the key provider,
cipher, envelope, scope and rotation policy into the module, and every call site is a
plain module call into `AshVault.Vault.Runtime`. There is no runtime provider switch, and
there is not going to be one.

That is a deliberate trade, and it buys two things:

* **The key-size check.** `AshVault.Vault.verify_key_sizes!/2` compares the provider's
  `key_bytes/0` against the cipher's while the vault module is being compiled. A
  `key_type: "aes128-gcm96"` under a 256-bit cipher is an `ArgumentError` at compile time
  rather than an `AshVault.Errors.CiphertextIntegrityFailed` in production — an error that
  tells an operator their data was tampered with, over a config typo. A vault assembled at
  runtime from a config value cannot be checked this way.
* **A provider call that is a module call.** The four provider call sites in
  `AshVault.Vault.Runtime` stay direct dispatch, with no resolution step on the path of
  every encrypt and every decrypt.

One vault per application is the normal case, and it is the case this library is shaped
for. If that is you, stop reading: name one vault module, point your resources at it, and
nothing below applies.

## When you actually need two

Two situations, both real:

* **Migrating between key providers** — moving from `AshVault.KeyProviders.Local` to
  `AshVault.KeyProviders.OpenBao`, where both have to be live at once while keys move.
* **Demonstrating or testing several providers** against one set of resources — which is
  what AshVault's own acceptance suite does, and what the `example/` application does.

The supported answer is: **two vault modules and a `fun/2` resolver.** The vault DSL entry
already accepts a `fun/2`, and it is called with the resource and the normalized
`ash_context` on the write path, the read path and the key-lifecycle actions alike.

## The pattern

```elixir
defmodule MyApp.Vault.Local do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end

defmodule MyApp.Vault.Bao do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.OpenBao
end

defmodule MyApp.Vault do
  @moduledoc "Which vault the application is currently encrypting with."

  @spec current() :: module()
  def current do
    case Application.get_env(:my_app, :key_provider, "openbao") do
      "local" -> MyApp.Vault.Local
      _ -> MyApp.Vault.Bao
    end
  end

  @doc "The `fun/2` vault form the resources declare."
  @spec resolve(module() | Spark.Dsl.t(), term()) :: module()
  def resolve(_resource, _context), do: current()
end
```

and in each resource:

```elixir
ash_vault do
  vault &MyApp.Vault.resolve/2
  scope :tenant

  encrypt :email
end
```

Supervision and setup go through whichever vault is current, so they stay one line each —
`MyApp.Vault.current()` answers for its own provider:

```elixir
# lib/my_app/application.ex
children = [MyApp.Repo] ++ MyApp.Vault.current().child_specs()

# a deploy step
:ok = MyApp.Vault.current().setup()
```

## The hazard

**The resolver must be stable for the lifetime of a row.** A value written through one
vault and read through another is decrypted with the wrong provider's key material, and
what surfaces is `AshVault.Errors.CiphertextIntegrityFailed` — "the stored bytes were
modified". It is the correct error for what the crypto layer observed and a completely
misleading one for what happened, and it is indistinguishable from a real tampering
finding.

It is worse than misleading in one specific place: it looks like a **passing**
crypto-erasure assertion. A test that erases a tenant and then asserts the read fails will
pass just as happily when the read failed because the resolver flipped between the write
and the read. AshVault's own acceptance suite therefore asserts, before doing anything
else, that the resolver hands back the vault the test thinks it is testing:

```elixir
setup do
  MyApp.VaultResolver.put(MyApp.Vault.Bao)
  assert MyApp.VaultResolver.resolve(MyApp.Accounts.User, %{}) == MyApp.Vault.Bao
  :ok
end
```

Do the same. A resolver keyed on anything request-scoped — an actor, a header, a process
dictionary entry — will eventually read a row it did not write, so key it on something
deployment-scoped (application config, a node name, an environment variable read at boot)
and change it only with a migration that re-encrypts.

## What a migration between providers looks like

1. Add the second vault module alongside the first; leave the resolver returning the old
   one. Nothing has changed yet.
2. Start the new provider (`child_specs/0`) and run its setup (`setup/0`).
3. Flip the resolver. New writes go to the new provider; **old rows do not move**, and
   they now fail to decrypt, so this step alone is not a migration.
4. Re-encrypt: read every row through the old vault and write it through the new one. Use
   `AshVault.Backfill` with the old vault as the source, or a one-off task that calls
   `encrypt!/2` and `decrypt!/2` on the two vault modules explicitly — both vaults are
   ordinary modules and you can call either directly.
5. Once no row remains under the old provider, delete the old vault module and the
   resolver, and point the resources at the new vault by name.

Step 4 is the whole job; steps 1 to 3 are five minutes. Budget accordingly.
