# Macaroon rotation

A long-lived bearer token placed in a consumer's configuration (a CI secret, a
Kubernetes Secret) is the token nobody rotates. A `rotation` on a `macaroon` rotates
them for you: it mints a successor before the current credential is due, delivers it,
keeps both valid through an overlap, and revokes the predecessor only once consumers
have demonstrably stopped using it.

This is *credential* rotation: a new record and token per cycle. It is unrelated to
[key rotation](rotation.md), which rotates the `:mac` key the tokens are signed under.

## Declaring it

```elixir
defmodule MyApp.ServiceCredential do
  use Ash.Resource, extensions: [AshVault, AshOban], ...

  ash_vault do
    vault MyApp.Vault
    scope :global

    macaroon :svc do
      prefix "myapp"
      identity :id
      default_ttl 86_400
      max_ttl 7_776_000
      revoked_when expr(not is_nil(revoked_at) or expires_at <= now())

      rotation do
        source MyApp.Credentials.RotationSource
        delivery AshVault.Macaroon.Rotation.OpenBaoKV
        issue_action :issue_rotated
        revoke_action :revoke
        rotate_action :rotate
      end
    end
  end

  oban do
    scheduled_actions do
      schedule :rotate, "* * * * *" do
        action :rotate
        default_actor %MyApp.Operator{}
        max_attempts 1
      end
    end
  end

  attributes do
    uuid_primary_key :id
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false
    attribute :revoked_at, :utc_datetime_usec
    attribute :last_used_at, :utc_datetime_usec
    # ... whatever the credential grants
  end

  actions do
    create :issue_rotated do
      accept [:expires_at, ...]
    end

    update :revoke do
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end
  end
end
```

The DSL holds wiring only. What each credential grants, its lifetime, its quiet period
and its consumers come from the **source** at runtime, as an
`AshVault.Macaroon.Rotation.Spec`, because they are per credential: one service may
rotate a dozen credentials with different consumers.

- `source` — an `AshVault.Macaroon.Rotation.Source`: lists the credentials to rotate and
  stores each one's `AshVault.Macaroon.Rotation.State` (ids and times only). A
  Kubernetes custom resource's status is a good home.
- `delivery` — an `AshVault.Macaroon.Rotation.Delivery`: stages each new token, then
  hands it to every consumer.
- `issue_action` — a create action that only writes the row. Rotation sets the expiry
  attribute and mints the token itself, through the macaroon's mint action, with the
  spec's caveats.
- `revoke_action` — an update after which `revoked_when` holds.
- `expires_at_attribute` (`:expires_at`) and `last_used_at_attribute`
  (`:last_used_at`) — the expiry, and when the credential was last used. **Your
  application keeps `last_used_at` current** when it verifies a token (off the request
  path and at most once per verification-cache turnover is plenty); it is the only
  evidence rotation trusts that consumers moved on.
- `quiet_period` (3600) — the default; a spec may set its own.

AshVault does not depend on AshOban. The generated rotate action is an ordinary generic
action; schedule it with AshOban as above or with any scheduler, one node at a time.
Policies apply: the scheduler's actor must be allowed to run it, and rotation runs
issue, mint, read and revoke as that same actor.

## The cycle

Every reconcile, for each credential:

1. **Mint** when there is no current credential, the current one is at two thirds of
   its lifetime (a constant: the alerts below assume it), or it is no longer valid
   (revoked, expired, deleted), and nothing is pending. The token is staged; the row
   becomes `pending`.
2. **Distribute** the pending token to every consumer not yet holding it. Once all
   have it, pending becomes current and current becomes `previous`. A consumer added
   later is handed the current token.
3. **Retire** the previous credential once its `last_used_at` has been quiet for the
   quiet period since it was superseded. One still in use is kept (`in_use`) and
   simply expires at the end of its lifetime: the overlap is the last third.

| Failure | Effect |
|---|---|
| issue or mint fails | nothing changes; the current credential stays (`Mint`) |
| staging fails | the new row is revoked at once: nobody holds it (`Staging`) |
| a delivery fails | retried next reconcile, for that consumer only (`Distribution`) |
| staging lost the token | the pending row is revoked and minted again (`StagingLost`) |
| the state cannot be saved | reported (`Status`); the next reconcile starts from the last saved state |
| the spec is invalid | reported (`InvalidSpec`), never acted on |

A predecessor still in use is never revoked early, whatever else fails.

## Delivering through OpenBao and External Secrets

`AshVault.Macaroon.Rotation.OpenBaoKV` writes each token to OpenBao KV v2, reusing an
already-configured OpenBao key provider's connection:

```elixir
config :my_app, AshVault.Macaroon.Rotation.OpenBaoKV,
  provider: AshVault.KeyProviders.OpenBaoTransit,
  mount: "my-app-credentials"
```

A consumer is `%{name: "ns/secret", path: "consumers/ns/secret"}`. Staging lives at
`staging/<ref>` and must be readable by the minting service only. Each consumer
namespace declares an `ExternalSecret` (`property: token`) through its own
`SecretStore`, whose OpenBao policy reads only its path. The minting service never
touches consumer Secrets and needs no Kubernetes RBAC in their namespaces.

Two timing rules:

- keep the `ExternalSecret`'s `refreshInterval` well under the quiet period (5 minutes
  against an hour). Otherwise an idle consumer can have its old token revoked before
  its Secret changes.
- a consumer that reads the token only at start needs a restart when its Secret
  changes. Annotate it for Stakater Reloader
  (`secret.reloader.stakater.com/reload: <secret>`). Rotation does not restart
  workloads: the restart must follow the Secret change, which only the syncer sees.

## Metrics and alerts

The telemetry events are listed in `AshVault.Macaroon.Rotation`. With
`Telemetry.Metrics` (tag `:rotation` is the source's ref):

```elixir
last_value("my_app.rotation.expires_in.seconds",
  event_name: [:ash_vault, :macaroon, :rotation, :status],
  measurement: :expires_in, tags: [:rotation]),
last_value("my_app.rotation.rotate_in.seconds",
  event_name: [:ash_vault, :macaroon, :rotation, :status],
  measurement: :rotate_in, tags: [:rotation]),
last_value("my_app.rotation.pending", event_name: [:ash_vault, :macaroon, :rotation, :status],
  measurement: :pending, tags: [:rotation]),
last_value("my_app.rotation.predecessor_in_use",
  event_name: [:ash_vault, :macaroon, :rotation, :status],
  measurement: :predecessor_in_use, tags: [:rotation]),
last_value("my_app.rotation.healthy", event_name: [:ash_vault, :macaroon, :rotation, :status],
  measurement: :healthy, tags: [:rotation]),
counter("my_app.rotation.failure.total",
  event_name: [:ash_vault, :macaroon, :rotation, :failure], tags: [:rotation, :reason]),
last_value("my_app.rotation.reconciled.timestamp.seconds",
  event_name: [:ash_vault, :macaroon, :rotation, :reconciled], measurement: :timestamp)
```

Alerts worth having (PromQL against the names above):

| Alert | Expression |
|---|---|
| reconcile stalled | `time() - max(my_app_rotation_reconciled_timestamp_seconds) > 900` |
| rotation overdue | `min by (rotation) (my_app_rotation_rotate_in_seconds) < -3600` |
| expiring with no successor | `min by (rotation) (my_app_rotation_expires_in_seconds) < 259200` |
| repeated failures | `sum by (rotation, reason) (increase(my_app_rotation_failure_total[30m])) > 5` |
| predecessor still used | `max by (rotation) (my_app_rotation_predecessor_in_use) == 1` for 3d |

## What never leaves the library

Tokens travel only inside `AshVault.Macaroon.Rotation.Secret`, which inspects as
`<redacted>` and has no JSON encoder; a delivery calls `Secret.reveal/1` at the moment
it writes. No log line, telemetry event, stored state or failure message carries a
token, and failure messages never inspect errors (a source or delivery may describe its
own errors with `describe_error/1`).
