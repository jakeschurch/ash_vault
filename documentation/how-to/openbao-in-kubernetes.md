# Running against OpenBao in Kubernetes

This guide configures the OpenBao providers for an application running as a pod. The pod
logs in with its service account (no long-lived token in a Secret), and it trusts an
OpenBao server certificate signed by a private CA.

Both settings live in the provider's configuration block. They apply to every request the
provider makes: `AshVault.KeyProviders.OpenBao`, `AshVault.KeyProviders.OpenBaoTransit`,
and `AshVault.Ciphers.OpenBaoTransit` and `AshVault.Macs.OpenBaoTransit` too, because
those two read the `OpenBaoTransit` block.

## Configuration

```elixir
# config/runtime.exs
config :my_app, AshVault.KeyProviders.OpenBaoTransit,
  address: "https://openbao-active.openbao.svc:8200",
  cacertfile: "/etc/openbao-ca/ca.crt",
  auth: {:kubernetes, role: "ashvault-foundry"}
```

### Address the active node

With HA (`server.ha.enabled`), point `:address` at the chart's `<release>-active` Service,
not the `<release>` Service that spans every pod. OpenBao standbys answer reads and run
policy checks against their own copy of the data, which lags the active node slightly.
AshVault creates a scope's key explicitly and then encrypts with it straight away; a
standby that has not yet seen the new key treats that encrypt as a request to create the
key, and a policy that withholds `create` on `transit/encrypt/*` (as recommended) refuses
it with `403`. Verified against openbao 2.6.3 in a three-node Raft cluster: through the
all-pods Service, encrypt immediately after create was refused every time on a standby,
and succeeded a few hundred milliseconds later; through the active Service it never failed.
A standby can equally serve a tombstone read from before a `destroy/1` landed.

The `-active` Service only routes *new* connections. A pooled keep-alive connection opened
while a node was active stays on that node after a leader change demotes it, and Finch has
no maximum connection lifetime, so under steady traffic it never goes idle and never
reconnects. That is why `reuse_connections` defaults to `false`: every request carries
`connection: close`, opens a new connection, and lands on whichever node is active at that
moment. Leave it off against HA. Turning it on is safe only for a single, non-HA node or
servers run with `disable_standby_reads = true`, which makes standbys forward every
request to the active node. That server setting is the defence for every client, not
just AshVault.

`AshVault.KeyProviders.OpenBaoTransit.node_status/0` reports the HA role
(`:active`, `:standby`, `:sealed`, `:uninitialized`) of the node a request lands on, from
the unauthenticated `sys/health`. Log it at boot and export it as a gauge: `:standby` means
`:address` does not reach the active node, and fresh-scope keys will fail.

The server certificate must name the address you configure (see below).

Use `auth:` **or** `token:`, never both. AshVault raises `ArgumentError` if both are set
rather than guess which one you meant. The static `token:` forms (a binary,
`{:system, "VAR"}` or a zero-arity function) work as before.

## Kubernetes auth

`auth: {:kubernetes, opts}` takes:

| Option | Default | Meaning |
|---|---|---|
| `:role` | required | The role under `auth/<mount>/role/` to log in as |
| `:mount` | `"kubernetes"` | The auth method's mount path |
| `:jwt_path` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | The projected service-account token |
| `:refresh_fraction` | `2/3` | Log in again after this fraction of the lease |
| `:backoff_min` / `:backoff_max` | `1_000` / `30_000` | Milliseconds between failed logins, doubling |
| `:login_timeout` | `15_000` | How long a caller waits for a login in flight |

How it behaves, in short. See `AshVault.KeyProviders.OpenBao.KubernetesAuth` for the
details.

- **One token holder per provider.** It starts on first use under AshVault's own
  supervisor, so there is nothing to add to your supervision tree. The `:ash_vault`
  application must be running. A `mix` task or release command that has not started it
  gets `ProviderUnavailable` with reason `{:not_started, :ash_vault}`.
- **The login.** The holder posts the service-account JWT to
  `/v1/auth/<mount>/login` and caches the client token.
- **Refreshing.** Once two thirds of the lease has passed, it logs in again from
  scratch. It re-reads the JWT file each time, because the kubelet rotates projected
  tokens. A fresh login is also not limited by the role's `token_max_ttl`, which
  `renew-self` would be.
- **Requests never wait on a refresh.** A request that arrives while a refresh is
  running uses the current token. When there is no valid token, concurrent requests
  share a single login.
- **Failures.** A failed refresh keeps the old token in use until it expires, and
  retries with backoff. With no valid token, a request inside the backoff window fails
  at once instead of starting another login. Every failure is
  `AshVault.Errors.ProviderUnavailable` with reason `{:kubernetes_auth, reason}`, which
  is retryable. Some example reasons are `:forbidden`, `{:http_status, 400}`,
  `{:jwt_unreadable, path, :enoent}` and `{:transport, :econnrefused}`. A failure is
  never reported as `KeyDestroyed`.
- **Secrets stay out of logs.** Neither the JWT nor the client token is logged or
  placed in an error. The holder's `:sys.get_status/1` and crash reports show the token
  as `:redacted`.

A token revoked out of band (for example with `bao token revoke`) is not noticed
until the next scheduled login. Until then, requests fail with
`AshVault.Errors.ProviderForbidden`.

### OpenBao side

```sh
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao write auth/kubernetes/role/ashvault-foundry \
    bound_service_account_names=foundry \
    bound_service_account_namespaces=foundry \
    token_policies=ashvault-foundry \
    token_ttl=1h token_max_ttl=4h
```

Grant the policy only what the provider needs. The `OpenBaoTransit` moduledoc lists the
paths. Do not grant `transit/export/*`: `AshVault.Macs.OpenBaoTransit` computes MACs
with `transit/hmac` and `transit/verify`, so the MAC key never leaves OpenBao either.

## Server-enforced retirement

Stock Transit is the default (`server_retirement: false`). Its client-side tombstone
recheck cannot clean up a delayed create when that client dies. For permanent
no-recreation at the server, install the optional plugin from the repository's
`openbao_plugin/` directory and set `server_retirement: true` on either provider.

The plugin uses OpenBao SDK 2.7.1 transactions, tested against OpenBao 2.6.2 with Raft
storage. A backend without transactional storage fails with HTTP 503. Every key
operation, including export, rotation, AEAD and HMAC, checks the retirement marker
in the same transaction as its key access. Retirement deletes policy and archive
entries for all three key purposes and permanently marks their names. Concurrent
creators cannot commit across that retirement transaction. A lost commit response
remains an outage; repeat destruction until confirmed.

This is a restricted Transit backend for AshVault keys, not a general Transit
replacement. It supports the AES-GCM and ChaCha20-Poly1305 profiles used by AshVault,
versioned exports, rotation, AEAD with associated data and SHA-256 HMAC. Derived,
convergent, imported, soft-deleted, auto-rotating or plaintext-backup-enabled keys
are refused. Import/restore, implicit creation, retirement deletion and other Transit
operations are unavailable. Unsupported request options are rejected. Use a dedicated
AshVault mount; inventory existing key profiles before upgrading one.

### Build and install

Build from a reviewed repository checkout with Go 1.27.3 or newer. The root Nix shell
includes Go and OpenBao; the plugin adds no runtime dependency to an Elixir release.

```sh
cd openbao_plugin
go build -trimpath -o ashvault-transit ./cmd/ashvault-transit
sha256sum ashvault-transit
```

Copy the binary to each OpenBao node's configured `plugin_directory`, with execute
permission for the OpenBao user. Register its SHA-256 using an operator token:

```sh
bao plugin register -sha256=SHA256 -command=ashvault-transit -version=v0.1.0 secret ashvault-transit
bao secrets enable -path=ashvault-transit -plugin-version=v0.1.0 ashvault-transit
bao secrets enable -path=ashvault -version=2 kv
```

Configure `transit_mount: "ashvault-transit"` and the existing `kv_mount`. Do not
point an existing installation at a new empty mount: it would lose access to its keys.
The mount refuses key operations until initialized. Grant the application these
additional paths (replace the Transit mount prefix as configured):

```hcl
path "ashvault-transit/ashvault/protocol" { capabilities = ["read"] }
path "ashvault-transit/ashvault/retired/*" { capabilities = ["read"] }
path "ashvault-transit/ashvault/retire/*" { capabilities = ["update"] }
```

Retain the provider's ordinary key/crypto and KV permissions. The plugin does not
need `delete` on key paths; use its retirement endpoint. Keep `sudo` on initialization,
KV metadata deletion and mount/catalog administration out of application policies.

### Upgrade an existing stock Transit mount

Stop writers and drain requests once for this maintenance migration. Keep the same
Transit and KV mounts. Register the binary under the existing plugin name `transit`
with a custom version, tune the mount and reload it; **do not disable the mount**:

```sh
bao plugin register -sha256=SHA256 -command=ashvault-transit -version=v0.1.0 secret transit
bao secrets tune -plugin-version=v0.1.0 transit/
bao plugin reload -plugin=transit
```

This preserves stock Transit storage, including keys, versions and archives. Reloading
by plugin name affects all mounts using it; use dedicated mounts and schedule accordingly.
After installing or upgrading, import all previous KV tombstones before activation:

```sh
mix ash_vault.openbao.init_retirement AshVault.KeyProviders.OpenBao
# Or the OpenBaoTransit provider, using its configured mounts.
```

Run with an operator token configured for that provider: `read` on `sys/mounts` to
verify the configured store is KV-v2, `read`/`list` on
`<kv_mount>/metadata/tombstones`, `read` on `<kv_mount>/data/tombstones/*`, `update`
on `<transit_mount>/ashvault/retire/*`, and `update` plus `sudo` on
`<transit_mount>/ashvault/initialize`, as well as protocol read access. Create the
KV-v2 mount explicitly before a fresh installation's initialization. The task loads
application configuration and starts only AshVault and its HTTP dependencies, not the
consumer application. It imports soft-deleted tombstones too and stops on any unreadable
or ambiguous entry. Interrupted imports are safe to repeat. Never initialize a migrated
mount directly with `bao write`: skipping the tombstone import would lose old erasures.

Set `server_retirement: true`, verify `provider.setup()` succeeds, then resume writers.
No re-encryption or lookup-token rebuild is needed. Subsequent scope retirement needs
no per-scope writer drain. Route requests to the active node as described above.

The library retains KV tombstones as well as server markers. Reverting the application
flag keeps recognizing scopes erased through the provider, but does not switch the
server backend: stock-mode key deletion is unsupported by the plugin and fails closed.
Reverting the mount implementation is a separate operator change: retain
its storage and KV tombstones, stop writers, and reconcile every server retirement into
KV first if operators used the raw plugin endpoint. Never remove or restore retirement
metadata to reactivate a scope. No mode can revoke already-exported keys, recall
in-flight responses or erase historical OpenBao snapshots/Raft logs.

### Verify the plugin

From `openbao_plugin/`, run `go test -race ./...`. For the real process/upgrade suite,
run `ASHVAULT_BAO_INTEGRATION=1 go test -count=1 -timeout 3m ./...` with `bao`, `curl`,
`go` and `rtk` on PATH (Linux). It starts its own disposable Raft server, upgrades stock
keys in place, kills delayed clients and the plugin process, and restarts the server.
The Elixir suite additionally accepts `ASHVAULT_RETIREMENT_MOUNT` naming an initialized
plugin mount alongside the ordinary stock Transit test mount.

## A private CA

`:cacertfile` is a path to a PEM bundle, typically a ConfigMap mounted as a file:

```yaml
volumes:
  - name: openbao-ca
    configMap:
      name: openbao-ca
containers:
  - name: app
    volumeMounts:
      - name: openbao-ca
        mountPath: /etc/openbao-ca
        readOnly: true
```

AshVault passes it to Req as
`connect_options: [transport_opts: [cacertfile: path, verify: :verify_peer]]`. Mint keeps
its hostname check and SNI on top of that. Things to know:

- **The host in `:address` must match a name in the server certificate.**
  `openbao.foundry.svc` and `openbao.foundry.svc.cluster.local` are different names to
  the check. Issue the certificate for the name you configure.
- **A missing or unreadable file fails before any connection is attempted.** The error
  is `ProviderUnavailable` with reason `{:cacertfile_unreadable, path}`, so it cannot be
  mistaken for a network outage.
- **The CA file is read once per path and cached for the life of the VM.** Mint does
  the caching. After you rotate the CA, restart the pods.
- **Other TLS settings go in `:connect_options`.** Pass it for anything else (timeouts,
  `transport_opts` such as `versions`). Its `transport_opts` are merged with
  `:cacertfile`. `verify: :verify_none` is refused with `ArgumentError`.

Without `:cacertfile`, Mint verifies against the OS trust store, or CAStore, the way it
always has. Adding the CA to the image's trust store also works. `:cacertfile` keeps the
trust scoped to OpenBao.

## Other Req options

`:req_options` is a keyword list merged into every request before AshVault's own
options. AshVault's options win wherever both set the same key. Tests use it to route
requests to a `Req.Test` stub (`req_options: [plug: {Req.Test, MyStub}]`). Use it for
anything Req supports that has no dedicated setting here.
