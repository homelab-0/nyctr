# Deployment

## Application image

The root Dockerfile builds the TypeScript frontend and copies only compiled web
assets into a Python runtime. Python dependencies install from a hash-locked
requirements file. The application runs as UID/GID 10001 and serves both the UI
and `/api` on port 8080. It needs no Docker socket or privileged mode.

```sh
docker build -t nyctr:dev .
```

The Dockerfile supports local builds; CI builds and smoke-tests the packaged
application against PostgreSQL on AMD64 and ARM64. The [release workflow](../docs/releases.md)
publishes versioned multi-platform images with SBOM/provenance metadata after
its release checks pass. Use a digest from a completed publication; the presence
of the workflow does not imply that a public release image already exists.

## Local demo

Run `docker compose up --build -d` from the repository root. PostgreSQL must be
healthy before the application starts. The application has a read-only root
filesystem, a small temporary filesystem, dropped Linux capabilities and no
new privileges. PostgreSQL is available only on the Compose network.

The known demo accounts and data are explicitly enabled by `NYCTR_MODE=demo` in
the local Compose file. The app port binds only to `127.0.0.1`. Do not make that
demo service public or attach real provider secrets to it.

## Live Compose configuration

Use `.env.production.example` and the production override shown in the README.
The override uses a separate named database volume. The app also records its
database mode and rejects cross-mode reuse. Keep the PostgreSQL password
URL-safe, because it is interpolated into the connection URI; hexadecimal
random output is suitable. Do not change a database volume's initial password
by editing environment variables alone; rotate the existing database user's
password explicitly and then update the application configuration.

Terminate HTTPS at an ingress/reverse proxy and set `NYCTR_PUBLIC_URL` to the
external origin. Keep `NYCTR_COOKIE_SECURE=true`. The production override keeps
the application localhost binding so a host reverse proxy can reach it. Adapt
that binding deliberately if the reverse proxy runs in another container.

The first deployment either bootstraps a local administrator from environment
or uses configured OIDC. Remove local bootstrap credential environment values
after provisioning. They are not an account password-rotation interface.

For a private console CA, prepare a PEM bundle containing **both the private
console CA certificates and public CA roots**, mount it as read-only, and set
`NYCTR_CONNECTOR_CA_BUNDLE` to its container path in a local Compose override.
This bundle replaces the default CA trust for all connector clients, including
NextDNS; a private-only bundle prevents verification of public provider
certificates. Keep the combined bundle's certificates updated. Leave this setting
unset when all connector certificates are already publicly trusted. The server
must also explicitly allow the console's hostname through
`NYCTR_CONNECTOR_HOSTS`. NextDNS uses its fixed official HTTPS origin.

### Trusted reverse proxies and login limits

Set `FORWARDED_ALLOW_IPS` to the comma-separated **actual proxy peer IP addresses
seen by the application**. The production Compose override requires this value.
It is a Uvicorn setting, so it has no `NYCTR_` prefix. For example, use
`FORWARDED_ALLOW_IPS=10.42.0.10,10.42.0.11` only if those are your trusted proxies.
Do not use `*`, a client network, or a shared container/cluster subnet. (The Helm
chart accepts a bounded range only together with its NetworkPolicy, and only
when you have made sure that nothing but your proxies can reach the pod; Compose
has no such control.) Docker
port forwarding or ingress networking can change the peer address the container
sees; confirm it from connection/access logs before configuring trust. Trust a
NAT/bridge address only when network controls ensure that every connection from
it must pass through your trusted proxy.

Uvicorn uses `X-Forwarded-For` and `X-Forwarded-Proto` only from trusted peers to
set the request's client address and scheme. Nyctr's login limiter uses that
resolved client address, with a separate per-account quota. If the proxy is not
trusted or does not forward the client address, all its users share the same
60-attempt peer quota. See the official [Uvicorn proxy settings](https://uvicorn.dev/settings/#http)
and [proxy deployment guidance](https://uvicorn.dev/deployment/#proxies-and-forwarded-headers).

The public-facing proxy must **replace client-supplied forwarding headers** with
values derived from its incoming connection. For a single Nginx proxy terminating
HTTPS, the relevant directives are:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

For multiple proxies, the public edge must first normalize untrusted headers;
subsequent trusted hops may append their verified peer address. List each trusted
hop explicitly. Keep direct application access restricted to those proxies using
the loopback binding, firewall rules, or Kubernetes NetworkPolicy. Forwarding
headers from other peers are ignored; permitting untrusted traffic to arrive
under a trusted proxy/NAT address would defeat that protection. Retain the exact
external `NYCTR_PUBLIC_URL` and secure cookies independently of this setting.

## Kubernetes / GitOps

The same image can run behind your existing ingress or Gateway API service.
Initial requirements:

- One replica, container port 8080, UID/GID 10001 and read-only root filesystem.
- A writable temporary mount and PostgreSQL accessible through a secret-backed
  `NYCTR_DATABASE_URL`.
- `NYCTR_MODE=live`, HTTPS public URL, secure cookies and local bootstrap or OIDC.
- `FORWARDED_ALLOW_IPS` set to the trusted ingress peer addresses, with forwarded
  headers normalized and direct application access restricted as described above.
- Provider credentials injected from Kubernetes Secrets/External Secrets; never
  bake tokens or API keys into the image.
- Readiness/liveness probes on `/api/health` and network policy permitting only
  the intended database, identity provider and configured provider endpoints.

Use the [Helm chart](../charts/nyctr/README.md) for the supported templates, values,
and Secret-reference contracts. The chart uses an existing PostgreSQL database;
database provisioning, backups, and identity-provider administration remain with
the operator. It supports optional Ingress or Gateway API HTTPRoute resources,
one application replica, and explicit proxy/network settings.

Chart rendering and isolated kind installation are automated checks. They do not
establish compatibility with a particular private cluster, ingress controller,
or identity provider. Independent acceptance testing uses local Docker fixtures
only; see [the test handoff](../docs/testing/cloudex.md). No homelab deployment is
performed by the release or test workflows.

## Operations and limits

Back up PostgreSQL and validate recovery before relying on collected history.
The initial schema migrates during startup. Keep one application replica during
alpha; concurrent migration and worker orchestration are not production-ready.
The current collectors run on demand. There is no schedule worker or event
receiver yet. Inbox expiry hides old requestable events but is not a retention
purge job; request/audit evidence persists until later retention tooling.

Logs and backups may contain sensitive network identifiers. Apply appropriate
access controls and retention to both. Never expose a development server or
demo credentials through a public ingress.
