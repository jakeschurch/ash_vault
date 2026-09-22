# ADR 0002 — AshVault distinguishes its crypto failures instead of returning a generic error

Status: accepted
Date: 2026-09-21

## Context

[`ash_cloak`'s security considerations][ash_cloak] recommend that a decryption failure be
reported generically — "decryption failed" — so that the error itself discloses nothing
about *why* it failed. That is sound advice in general: a detailed cryptographic error is a
free oracle, and an attacker who can provoke errors learns from each one.

AshVault does the opposite, deliberately. `AshVault.Errors.KeyDestroyed`,
`AshVault.Errors.AuthenticationFailed`, `AshVault.Errors.ProviderUnavailable`,
`AshVault.Errors.KeyNotFound` and `AshVault.Errors.KeySizeMismatch` are five distinct
`Ash.Error` structs with five distinct messages, and the crypto core goes out of its way to
keep them apart — it checks the tombstone *before* attempting decryption specifically so a
destroyed key can never be reported as a tag mismatch.

Plan §23 and [the threat model](../../documentation/topics/threat-model.md) state the
requirement this serves:

> A provider outage never looks like erasure; erasure never looks like an outage or like
> tampering; a configuration typo is never reported as either.

The divergence from ash_cloak's advice has been real since v1 and has never been written
down. This ADR writes it down.

## What the distinguishable errors actually disclose

Treat it as an oracle and ask what a question to it returns.

To ask the oracle anything at all, an attacker must get AshVault to attempt a decryption of
bytes they control or care about. There are two ways in, and both are expensive:

1. **Read a row through the application.** This requires an authenticated, authorized
   session: AshVault performs no authorization of its own and sits *behind*
   `Ash.Policy.Authorizer`, so the request was already allowed to read that field.
2. **Write bytes into the database and then read them back.** This requires database write
   access.

Given access, the oracle answers:

| Error | What the attacker learns |
|---|---|
| `KeyDestroyed` | this scope has been crypto-erased |
| `KeyNotFound` | the envelope names a key version the provider does not have |
| `ProviderUnavailable` | the key provider is currently unreachable |
| `AuthenticationFailed` | the AEAD tag did not verify under this scope/resource/field |
| `KeySizeMismatch` | the deployment's key size disagrees with its cipher |

Two observations decide the trade:

**The attacker who can reach the oracle already holds the ciphertext.** Both routes in
imply database or authorized-read access. At that point they have the envelope bytes
themselves — magic, cipher id, key version, nonce, tag, ciphertext — which already tell
them the key version and the cipher. `KeyNotFound` versus `KeyDestroyed` is a distinction
they could largely make by reading the column. The oracle is not the cheapest source of any
of this.

**`AuthenticationFailed` is not a padding oracle.** The classic reason to collapse crypto
errors is that a distinguishable "bad padding" versus "bad MAC" leaks a bit per query and
composes into plaintext recovery. AES-256-GCM has no padding, and AshVault returns exactly
one undifferentiated authentication failure for a wrong key, a wrong scope, a wrong
resource, a wrong field, a flipped ciphertext byte and a forged tag alike — it does not
say *which*. `AshVault.Ciphers.AES.GCM.decrypt/3` additionally requires a full 16-byte tag
and 12-byte nonce before the key reaches `:crypto`, closing the truncated-tag forgery that
*would* have made repeated queries productive (threat model §6). There is no iterative
attack for the finer-grained errors to feed.

What remains is a genuine, small disclosure: **erasure is observable**. Someone who can
read a scope's rows can tell that the scope was crypto-erased rather than merely broken.
We accept that. Under the regimes that motivate crypto-erasure in the first place, "this
subject's data was destroyed" is a fact the operator is generally obliged to be able to
demonstrate, not to conceal.

## Why the operational requirement wins

The cost of a generic error is paid every day by the people running the system, and it is
paid at the worst possible moment.

`ProviderUnavailable` and `KeyDestroyed` demand opposite responses. The first is an
outage: page someone, the data is fine, it will come back. The second is expected: the
data is gone on purpose, close the ticket. Collapsing them into "decryption failed" means
that during an OpenBao outage every affected tenant's reads look exactly like erasure —
and the operator's only way to tell is to go and check the key store by hand, under
pressure, on the assumption that they think to doubt the error at all. The failure mode of
getting it wrong in that direction is an incident report that says customer data was
destroyed when it was not; in the other direction, a real erasure is dismissed as a blip.

`KeySizeMismatch` exists for the same reason one layer down. Before it did, a `key_bytes:`
that disagreed with the cipher surfaced on the read path as `AuthenticationFailed` — a
configuration typo reported to the operator as *your data has been tampered with* — and on
the write path as `ProviderUnavailable`, telling them to retry a permanent
misconfiguration forever. A generic error does not remove that confusion; it makes it
total.

There is no configuration that buys back a distinction that was never drawn. The
information has to exist internally for AshVault to behave correctly at all — the
tombstone check gates decryption — so the only question is whether it is allowed out to
the operator. We let it out.

## Mitigation

**These errors are operator-facing.** They are `Ash.Error` structs with `class: :invalid`,
intended for logs, exception reporters, runbooks and the mix tasks. Nothing about their
existence obliges you to render them to an end user, and you should not.

**A public API should map them to a generic failure at its boundary.** An
`AshJsonApi`/`AshGraphql`/Phoenix layer that surfaces raw AshVault errors to unauthenticated
or low-privilege callers hands out the oracle for free — which is the situation ash_cloak's
advice is actually about. Collapse them there, where you know who is asking:

```elixir
defp to_public_error(%module{})
     when module in [
            AshVault.Errors.KeyDestroyed,
            AshVault.Errors.KeyNotFound,
            AshVault.Errors.AuthenticationFailed,
            AshVault.Errors.ProviderUnavailable,
            AshVault.Errors.KeySizeMismatch,
            AshVault.Errors.InvalidCiphertext,
            AshVault.Errors.UnsupportedCipher,
            AshVault.Errors.UnsupportedEnvelope
          ] do
  # Log the real one. Return the generic one.
  %{status: 422, code: "unprocessable", message: "This field could not be read."}
end
```

`KeyDestroyed` is the one worth a deliberate exception: a user-facing "this data was
deleted at your request" is usually better product behaviour than a blank error, and
telling a subject that their own data was erased discloses nothing to them they did not
ask for. That is a decision for your API, made once, with the actor in hand — which is
exactly the context AshVault does not have.

**The error messages themselves are held to the no-plaintext rule regardless.**
`AshVault.Errors.SerializationFailed` redacts the type-controlled value out of its
`:reason`, and `AshVault.Scopes.AshTenant.describe_tenant/1` puts a shape rather than a
tenant into `AshVault.Errors.MissingScope`. Being more specific about *which* failure
occurred is not a licence to be specific about *what the data was*.

## Consequences

* An operator can tell an outage from an erasure from a typo without inspecting the key
  store. This is the property being bought.
* Erasure is observable to anyone who can already read the ciphertext. Accepted.
* Every public API built on AshVault carries a boundary responsibility: map these errors
  to a generic failure before returning them to an end user. That is documented here, in
  [Operations](../../documentation/topics/operations.md) and in the threat model, and it
  is not enforced by code.
* If a future cipher without GCM's properties is added, the "no padding oracle" half of
  this reasoning must be re-derived for it. The `AshVault.Cipher` behaviour does not
  enforce it.

## Related

* [Threat model §8 — Operational distinguishability](../../documentation/topics/threat-model.md)
* [Operations — the error taxonomy](../../documentation/topics/operations.md)
* `AshVault.Errors`
* [ash_cloak security considerations][ash_cloak]

[ash_cloak]: https://deepwiki.com/ash-project/ash_cloak/6.2-security-considerations
