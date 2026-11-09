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
application against PostgreSQL. A public, signed image release is not claimed;
registry publishing and release version policy are separate roadmap items.

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

For a private console CA, mount the CA bundle read only and set
`NYCTR_CONNECTOR_CA_BUNDLE` in a local Compose override. The server must also
explicitly allow the console's hostname through `NYCTR_CONNECTOR_HOSTS`.
NextDNS uses its fixed official HTTPS origin.

## Kubernetes / GitOps

The same image can run behind your existing ingress or Gateway API service.
Initial requirements:

- One replica, container port 8080, UID/GID 10001 and read-only root filesystem.
- A writable temporary mount and PostgreSQL accessible through a secret-backed
  `NYCTR_DATABASE_URL`.
- `NYCTR_MODE=live`, HTTPS public URL, secure cookies and local bootstrap or OIDC.
- Provider credentials injected from Kubernetes Secrets/External Secrets; never
  bake tokens or API keys into the image.
- Readiness/liveness probes on `/api/health` and network policy permitting only
  the intended database, identity provider and configured provider endpoints.

A Helm chart and a cluster deployment are not included in this first change.
Deployment to the lab remains separate from authoring the application.

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
