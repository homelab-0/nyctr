# Isolated Docker acceptance environment

This test pack runs the **current production Dockerfile** against fabricated
UniFi and NextDNS services. It requires no homelab access, real provider account,
production database, or production credentials. Use it on the tester's own
computer or an isolated CI runner. The containers remain running for browser
testing after the checks finish.

The application runs in **live mode** to exercise ordinary connector setup,
authorization, TLS validation, diagnostics, and collection. All provider data is
synthetic; this does not establish compatibility with a real controller or DNS
account. OIDC-provider acceptance testing is outside this pack.

## Start the application

From the repository root, with Docker, the Compose plugin, and Python 3.11+ installed:

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml up --build --wait -d
python3 tests/acceptance/check.py
```

Open **http://localhost:8091** and sign in with the disposable test account:

| Field | Synthetic value |
| --- | --- |
| Email | `tester@nyctr.test` |
| Password | `nyctr-acceptance-only` |

The script uses only Python's standard library. It rejects non-loopback URLs,
uses only this fixed account, does not follow redirects, and ignores environment
proxy settings. It never prints session tokens, provider responses, or credentials
on failure.

For a different local port, set both the Compose port and checker URL:

```sh
export NYCTR_ACCEPTANCE_PORT=19091
export NYCTR_ACCEPTANCE_URL=http://localhost:19091
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml up --build --wait -d
python3 tests/acceptance/check.py
```

`check.py --url http://localhost:19091` overrides `NYCTR_ACCEPTANCE_URL`. To run
under another Compose project name, use that same `-p` value for every command;
the service names and checks stay the same.

## What the checks cover

The first run creates these saved connections through Nyctr's normal
administrator API. Subsequent runs reuse matching test connections; the script
refuses to overwrite an unexpected configuration.

| Connection | Synthetic behavior | Expected result |
| --- | --- | --- |
| Acceptance - UniFi Network | One site, gateway, network, client, and configured policy | Supported reads verified; firewall-event and reachability gaps remain |
| Acceptance - NextDNS | Full profile configuration and one block for `photos.example.test` | Supported reads verified; user attribution remains unverified |
| Acceptance - rejected credential | Ordinary provider HTTP 401 | Authentication check fails; a valid TLS exchange remains distinct |
| Acceptance - invalid TLS hostname | Allowed host absent from the certificate SANs | TLS verification fails before authentication is established |
| Acceptance - logging disabled | Profile `bbbbbb` explicitly disables logging | Partial result with unavailable log coverage, not an empty clean inbox |
| Acceptance - malformed response | Profile `cccccc` returns invalid JSON | Provider-contract failure; no reflected body or invented verification |

For every diagnostic, the script compares inventory, graph, observations, and
collection health before and after the request. Diagnostics must not import data
or mark a connection collected. It also checks unauthenticated access, missing
CSRF rejection, and sanitized diagnostic audit events.

Only after these checks does it explicitly collect the two positive fixtures.
The expected saved result is **13 resources, 14 relationships, and one fresh DNS
block**. Both provider-reported clients stay unassigned. The DNS observation has
no trusted device ID and no score, because the fixture's block reason is one the
scorer does not recognise. No source writes or exceptions are created.

The isolated HTTPS fixture routes are:

```text
https://fixture/proxy/network/integration/v1/sites
https://fixture/proxy/network/integration/v1/sites/site-one/devices
https://fixture/proxy/network/integration/v1/sites/site-one/networks
https://fixture/proxy/network/integration/v1/sites/site-one/clients
https://fixture/proxy/network/integration/v1/sites/site-one/firewall/policies
https://api.nextdns.io/profiles/aaaaaa
https://api.nextdns.io/profiles/aaaaaa/logs
https://api.nextdns.io/profiles/bbbbbb
https://api.nextdns.io/profiles/cccccc
```

These names resolve to the fixture **inside the Docker network only**. The pack
does not edit the host's resolver or hosts file and does not call NextDNS's real
API. Good requests use the fixed server-side `fake-readonly` key; the rejected
credential is `fake-rejected`. These values are disposable test inputs.

## Verify persistence and leave the UI available

Restart only the application, then run the read-only verification mode:

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml restart nyctr
python3 tests/acceptance/check.py --verify-persistence
```

Persistence verification signs in and reads the previously saved connections,
inventory, graph, collection health, and block. It does not create connections,
run diagnostics, or recollect evidence. PostgreSQL remains in a separate named
volume. The UI stays available for inspection of the explorer, integrations,
partial reports, failed checks, and the administrator block inbox.

If you recreate the application container instead of restarting it, restart
`ingress` after the application is healthy so nginx resolves its new container IP.

The fixture emits one stable event timestamp per process. It expires from the
inbox after 24 hours, as real observations do. For a fresh event, restart the
fixture and rerun the regular checker to collect again; for a completely clean
acceptance run, reset this project's volumes as shown below. Running the checker
after unrelated manual imports or device assignments may fail its expected
synthetic counts; use a fresh project for a repeatable run.

## Isolation and TLS

- Application, fixture, database, and certificate initialization containers join
  only the `isolated` network (`internal: true`) and have no external route.
  Image build/pull operations still need the normal package registries before
  the runtime starts.
- Only the small `ingress` nginx service joins both a normal bridge and the
  isolated network. It alone publishes the UI port, bound to `127.0.0.1`, and
  forwards requests to the fixed `http://nyctr:8080` upstream. The application,
  PostgreSQL, and fixture have no published ports. The ingress is a reverse proxy,
  not a configurable destination or CONNECT tunnel.
- This separate ingress supplies the default-gateway network Docker uses for
  published ports while keeping the application isolated. Internal-only
  containers can appear healthy even when their requested host port is not
  published. See Docker's [networking documentation](https://docs.docker.com/compose/how-tos/networking/)
  and the [Moby maintainer explanation](https://github.com/moby/moby/discussions/53256).
- The proxy preserves the original Host header including the port, passes normal
  cookies and CSRF headers, and allows 120 seconds for upstream responses so
  bounded diagnostics can complete. Its health check reaches the application
  through that same proxy path. It runs as a non-root user with a read-only
  filesystem, no capabilities, and temporary files in a small `/tmp` tmpfs;
  the image's configuration-modifying entrypoint scripts are bypassed.
- A short-lived CA and leaf are generated in a named test volume. The leaf SANs
  are exactly `fixture` and `api.nextdns.io`; `untrusted-fixture` is deliberately
  absent so the negative TLS case follows the production verification path.
- The connector receives a read-only CA bundle combining public roots with this
  test CA. No insecure TLS switch or application test backdoor is used.
- Certificate initialization uses the production image's existing
  `cryptography`/`certifi` dependencies. Its one-shot container runs as root to
  initialize the volume. The fixture uses the normal non-root application user
  with only `NET_BIND_SERVICE` added for HTTPS on port 443.
- The disposable fixture leaf key is mode `0644` so that user can read it. The
  CA signing key is never stored. These files and known credentials must never be
  reused for deployment. Complete certificates are reused on restart and expire
  after 30 days; reset the test volumes to rotate them.
- `NYCTR_COOKIE_SECURE=false` and the HTTP public URL apply solely to this
  loopback acceptance UI. Production deployments retain HTTPS and secure cookies.

## Logs, shutdown, and reset

Inspect this project's containers without accessing another environment:

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml ps
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml logs --tail=100 ingress nyctr fixture certificates
```

Stop while retaining synthetic PostgreSQL state and test certificates:

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml down
```

Reset **only this disposable project**, deleting its synthetic database and CA:

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml down -v
```

## Focused helper tests

With the API development dependencies installed, the helper tests exercise real
loopback TLS handshakes, valid and invalid certificate names, credential
rejection, GET-only fixture behavior, normal production-parser compatibility,
and rejection of remote checker URLs:

```sh
python3 -m unittest discover -s tests/acceptance -p 'test_*.py' -v
```

Those helper checks supplement the Docker run; they do not validate container
startup, PostgreSQL persistence, or a real provider deployment.
