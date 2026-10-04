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
  address: "https://openbao.foundry.svc:8200",
  cacertfile: "/etc/openbao-ca/ca.crt",
  auth: {:kubernetes, role: "ashvault-foundry"}
```

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
until the next scheduled login. Until then, requests fail with `ProviderUnavailable` and
reason `:forbidden`.

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
