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

## Offline model credential keys

The image includes an offline helper for encrypting model credential bytes with
Fernet. This storage helper does not enable API-key entry in the Model card;
the card still takes server secret references. Reference-only installations need
no key file or extra volume.

To provision a new encryption key, build the image and initialize an explicitly
named volume once. The command runs as UID/GID 10001 and prints no key:

```sh
docker build -t nyctr:dev .
docker volume create nyctr-model-keys
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount type=volume,src=nyctr-model-keys,dst=/var/lib/nyctr/model-keys \
  --entrypoint python nyctr:dev -m nyctr.model_secrets init /var/lib/nyctr/model-keys/keyring
```

Initialization requires an existing private directory, creates a 0600 file and
syncs the file and directory. It refuses every existing path, including a damaged
or partial file. Startup never creates, replaces or repairs this key. Restore a
lost key from backup instead of initializing over an existing installation.

For later runtime use, mount that same volume read-only and set
`NYCTR_MODEL_KEY_FILE=/var/lib/nyctr/model-keys/keyring`. The setting is an optional
absolute path; startup does not read it. Do not put the key in the image, database,
container writable layer or `/tmp`. A standalone `docker run` needs the same
explicit volume as Compose would. Container removal preserves a named volume;
removing the volume destroys its contents. A bind directory must already belong
to UID/GID 10001 with mode 0700; mounting it hides the image's owned directory.

Key files contain one to three distinct generated Fernet keys, one per line,
with an optional final newline. The first encrypts; all can decrypt. Reads are
fresh on each operation and require a regular file owned by the process or root,
without world access or group/other write permission. Group read requires the
process to belong to that group. Operator-controlled projected symlinks work;
keep their directory protected from untrusted writers. POSIX file permissions
are required; mounts that do not preserve them have not been validated.

Back up the key volume separately from the database, with separate access
controls. Lost encryption keys cannot decrypt existing ciphertext. To rotate
while credential writers exist, stop new credential writes and wait for all
in-flight writers to finish before installing the new primary key. Keep writers
stopped while installing the new key first in the ring with old keys retained,
reencrypting retained ciphertext, verifying it, and removing old keys from the
live file. Resume writers only after rotation is complete. Keep the old keys
for older backups.
Replace keyring files atomically; do not edit a live file in place. There is no
API rotation operation in this storage helper. Anyone controlling the host or
API process can read these keys; encryption protects against database-only theft.

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

To give members their own address, set `NYCTR_PORTAL_URL` to a second HTTPS
origin on a different host, serve both names from the reverse proxy to the same
application, and add `<portal>/api/auth/oidc/callback` to the identity
provider's allowed redirects. The reverse proxy must pass the original `Host`
header through for both names, including any port: Nyctr tells the addresses
apart by it, and a proxy that replaces it with the upstream's name makes every
request look like the console's. What each address allows is described under
"Two addresses" in the [security model](../docs/security-model.md).

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

Set `NYCTR_TRUSTED_PROXIES` to the comma-separated **actual proxy peer IP addresses
seen by the application**. The production Compose override requires this value.
It accepts only addresses and ranges. For example, use
`NYCTR_TRUSTED_PROXIES=10.42.0.10,10.42.0.11` only if those are your trusted proxies.

The list used to be called `FORWARDED_ALLOW_IPS`, the web server's own name for
it. That name is still read for this release when `NYCTR_TRUSTED_PROXIES` is
unset or empty; Nyctr then writes a warning at start and shows one in Setup. If
both are set, `NYCTR_TRUSTED_PROXIES` wins. Move to the new name: under its own
name the list is unknown to the web server.

Always start the web server with `--no-proxy-headers`. The image, the chart,
Compose and the commands in this repository do. A server started by hand
without that flag runs the web server's own forwarded-header handling, which
believes `127.0.0.1` by default and rewrites the peer before Nyctr sees it.
Nyctr's own name for the list keeps that harmless only when no proxy runs on
the server's own host. It is not safe in two cases: with a proxy on the same
host, where a passed-on `X-Forwarded-For: 192.0.2.99, 127.0.0.1` makes Nyctr
take the forged `192.0.2.99`; and while the old name is set, where the web
server believes the whole list.

The list must be exact addresses or bounded ranges. A list that covers every
address, such as `0.0.0.0/0` or `::/0`, is refused at start like `*`.

Do not use `*`, a client network, or a shared container/cluster subnet. (The Helm
chart accepts a bounded range only together with its NetworkPolicy, and only
when you have made sure that nothing but your proxies can reach the pod; Compose
has no such control.) Docker
port forwarding or ingress networking can change the peer address the container
sees; confirm it from connection/access logs before configuring trust. Trust a
NAT/bridge address only when network controls ensure that every connection from
it must pass through your trusted proxy.

Nyctr works out the client's address itself, and the image starts the web server
with its own forwarded-header handling off (`--no-proxy-headers`) and with only
itself on the web server's own list. A peer that is
not listed is the client and its headers are ignored. For a listed peer, Nyctr
reads `X-Forwarded-For` from the right and takes the entry at position
`NYCTR_PROXY_HOPS` (default 1), the one your own proxy wrote; entries to its left
came from the client and are never read. A missing or malformed entry gives no
address, and so does an entry to its right that is not a listed proxy. The
sign-in limit counts by that address, with a separate per-account
quota. If the proxy is not listed, all its users share one 60-attempt quota, and
so do all requests that have no address.

Your proxy must **write the address it saw** as the last entry, by appending it
or by replacing the header. What is in front of the proxy must **keep the
client's address**: a load balancer or NAT that replaces it leaves the proxy
nothing else to write. For a single Nginx proxy terminating HTTPS, either
`$remote_addr` or `$proxy_add_x_forwarded_for` does it:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

With more than one proxy, set `NYCTR_PROXY_HOPS` to their number and **list every
one of them** in `NYCTR_TRUSTED_PROXIES`. The edge writes the client's address and
the inner proxy appends the edge's. Nyctr checks that each entry to the right of
the one it reads is a listed proxy, so a client that reaches the inner proxy
without passing the edge gets no address, and so does everyone while the edge is
not listed. One limit remains: a client whose own address is inside a listed
range, and which can reach an inner proxy directly, passes for a proxy and can
name any address. Keep direct application access restricted to your
proxies using the loopback binding, firewall rules, or Kubernetes NetworkPolicy;
a peer that arrives under a listed address is believed. If your edge's
addresses cannot be listed (a large public network), leave `NYCTR_PROXY_HOPS=1`:
everyone behind that edge then appears at the edge's address, which is wrong for
them but cannot be forged. With a higher count and the edge unlisted, nobody
gets an address.

Nyctr does not read `X-Forwarded-Proto`. Cookies and sign-in follow the exact
external `NYCTR_PUBLIC_URL` and the secure-cookie setting, whatever a proxy
reports; setting the header is harmless and not needed.

To check the path, sign in as an administrator and open Setup, This
installation, "The address Nyctr sees for you".

## Kubernetes / GitOps

The same image can run behind your existing ingress or Gateway API service.
Initial requirements:

- One replica, container port 8080, UID/GID 10001 and read-only root filesystem.
- A writable temporary mount and PostgreSQL accessible through a secret-backed
  `NYCTR_DATABASE_URL`.
- `NYCTR_MODE=live`, HTTPS public URL, secure cookies and local bootstrap or OIDC.
- `NYCTR_TRUSTED_PROXIES` set to the trusted ingress peer addresses and
  `NYCTR_PROXY_HOPS` to the number of your proxies, the server started with
  `--no-proxy-headers` as the image does, and direct application access
  restricted as described above.
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
