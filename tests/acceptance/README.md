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

The checker is for a fresh default start. It prints the mode it found (`PASS
mode: changes disabled for access; changes disabled for guests`) and fails if
Nyctr says anything else. After any restart of the fixture, use a fresh project:
the fixture stamps its lookups when it starts, so collecting again stores a
second copy of the one block and the check fails on that count.

Volumes made before the scenario sources were added hold a certificate that
lacks a name the fixture now needs. The start then stops at the certificate step
with "Test certificates expired or changed; reset the acceptance volumes"; reset
them as shown under Logs, shutdown, and reset.

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
| Acceptance - UniFi Network | One site; a gateway listed with switching only, a switch and an access point; three networks with address ranges; three clients; one configured policy | Supported reads verified; firewall-event and reachability gaps remain |
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
The expected saved result is **19 resources, 28 relationships, and one fresh DNS
block**. Four of those relationships are worked out when the graph is read and
are labelled inferred: the laptop and the camera are each placed on the one
network whose range holds their address, and the two gateway-managed networks
are linked to the only gateway. The visitor reports no address and is placed
nowhere. The gateway is listed with the switching feature only and reports an
address outside every network range, as a real one can. It is filed as the
gateway because it is the only equipment outside every range, has nothing
above it and has the switch attached to it, and is marked as worked out by
Nyctr. All provider-reported clients stay unassigned. The DNS observation has
no trusted device ID and no score, because the fixture's block reason is one the
scorer does not recognise. No source writes or exceptions are created
on the default start.

Both fixtures serve every read their adapter makes, the optional ones included.
Each collection must therefore record nothing it could not read: a gap count of
zero in its answer, none listed on the source and none in its audit record.

The isolated HTTPS fixture routes are:

```text
https://fixture/proxy/network/integration/v1/sites
https://fixture/proxy/network/integration/v1/sites/site-one/devices
https://fixture/proxy/network/integration/v1/sites/site-one/devices/{device}
https://fixture/proxy/network/integration/v1/sites/site-one/networks
https://fixture/proxy/network/integration/v1/sites/site-one/networks/{network}
https://fixture/proxy/network/integration/v1/sites/site-one/clients
https://fixture/proxy/network/integration/v1/sites/site-one/clients/{client}
https://fixture/proxy/network/integration/v1/sites/site-one/firewall/policies
https://fixture/proxy/network/integration/v1/sites/site-one/hotspot/vouchers
https://fixture/proxy/network/integration/v1/sites/site-one/wifi/broadcasts
https://api.nextdns.io/profiles/aaaaaa
https://api.nextdns.io/profiles/aaaaaa/logs
https://api.nextdns.io/profiles/aaaaaa/allowlist
https://api.nextdns.io/profiles/bbbbbb
https://api.nextdns.io/profiles/cccccc
https://api.nextdns.io/profiles/dddddd
```

`site-large` has the same routes as `site-one`, and every gateway route is also
served under `https://api.ui.com/v1/connector/consoles/{console}`. Profile
`dddddd` has the same routes as `aaaaaa`. The gateway lists give 25 rows unless
asked for more and at most 200. With changes allowed the fixture also takes the
changes Nyctr makes: a name added to or removed from an allowlist, a pass issued
or ended under `hotspot/vouchers`, and a guest let on or cut off at
`clients/{client}/actions`. `/control` reads and sets the switches below.

These names resolve to the fixture **inside the Docker network only**. The pack
does not edit the host's resolver or hosts file and does not call NextDNS's real
API. Good requests use the fixed server-side `fake-readonly` key; the rejected
credential is `fake-rejected`. These values are disposable test inputs.

The check then saves three more sources, collects each, checks what it records
and shows, and removes it again, so the saved result above does not move: the
site at real size (321 items, nothing unread, its rules read in two pages), a key that may not read the Wi-Fi
names (one gap, in the answer, on the source with its cause, and in the audit
record) and a DNS profile holding more than one collection reads (stored and
shown as partial with 4000 rows kept). They are described under Scenarios.

Nyctr collects every saved source on its own schedule, first 30 seconds after it
starts. That would add the failing sources' data to the counts above, so the
check **turns scheduled collection off** before it saves anything. Turn it back
on under Setup, Scheduled collection, when a scenario needs it; rerun the check
only on a fresh project after that. Nyctr accepts ten sign-ins per account in 15
minutes, and every run of the checker is one.

## Verify persistence and leave the UI available

Do this before adding the scenario sources below. They are kept for the browser,
so the saved counts would no longer match; `--verify-persistence` then stops and
says that scenario sources are saved, not that anything was lost.

Restart only the application, then run the read-only verification mode, which
also requires scheduled collection to still be off:

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
inbox after 24 hours, as real observations do. For a fresh event, reset this
project's volumes as shown below and start again; restarting the fixture and
collecting again within 24 hours stores a second copy. Running the checker
after unrelated manual imports or device assignments may fail its expected
synthetic counts; use a fresh project for a repeatable run.

## Scenarios

Everything here is fabricated and runs on the stack started above, after the
regular check and the persistence check. Add the three scenario sources and
leave them in place for the browser with:

```sh
python3 tests/acceptance/check.py --scenarios
```

To add one by hand instead, use Sources, Add connection. The secret name is
`NYCTR_CONNECTOR_SECRET_ACCEPTANCE` unless the table says otherwise, and the
gateway address is `https://fixture/proxy/network/integration`.

| Source | Settings | What the console should show |
| --- | --- | --- |
| Scenario - site at real size | UniFi Network, site `site-large` | 10 networks with address ranges; 13 pieces of equipment with uplinks, the gateway listed with switching only at an address outside every range and filed as the gateway by Nyctr; 67 devices, 63 placed on a network and 4 not (two report no address, two an address outside every range); 230 rules, more than the 200 one page of a list holds, so a collection that stopped at the first page would show 200. On Guests: `Example Guest Wi-Fi` uses a sign-in page, with five guests on it, one still waiting |
| Scenario - key that may not read Wi-Fi names | UniFi Network, site `site-one`, secret name `NYCTR_CONNECTOR_SECRET_LIMITED` | Connected, with gaps: the Wi-Fi names could not be read because the source refused the read |
| Scenario - more lookups than one collection reads | NextDNS, profile `dddddd` | Partial: only the most recent blocked lookups were read. 4000 log rows are kept; each lookup is on ten rows, so Blocks gains 400 |
| The cloud form of the address (by hand only) | UniFi Network, address `https://api.ui.com/v1/connector/consoles/example-console/proxy/network/integration`, site `site-large` | The same site, read the way a cloud console is. `api.ui.com` is the fixture inside the Docker network only |

### Switches that make a source misbehave

A switch applies to every source the fixture serves, until it is changed or the
fixture restarts. Set one while the stack runs, from the repository root:

```sh
alias fixture-set='docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml exec fixture python /acceptance/fixture.py --set'
fixture-set                          # print every switch
fixture-set refuse=wifi/broadcasts   # set one
fixture-set refuse= fail=limit:2     # clear one, set another
```

`FIXTURE_REFUSE`, `FIXTURE_ERROR`, `FIXTURE_FAIL`, `FIXTURE_RETRY_AFTER` and
`FIXTURE_SLOW`, set where `docker compose up` is run, give the same switches a
value from the start. The switch route is not published: no other machine can
reach it. On Linux the host itself can, at the fixture's address on the Docker
network.

| Switch | What the source does | What the console should show |
| --- | --- | --- |
| `refuse=<part of a path>` | Refuses every request whose path contains it, changes included. Reads a collection can do without: `wifi/broadcasts`, `hotspot/vouchers`, `networks/` (address ranges), `devices/` (uplinks), `clients/` (guest details) | After Collect snapshot the source is Connected, with gaps; the gap is named and says the source refused the read |
| `error=<part of a path>` | Answers those requests, changes included, with a server error | The same gap, saying the source had an error of its own and the next collection may read it. Without the range of a network the gateway runs, a second gap says no device could be shown to be the gateway |
| either, on a read every collection needs, such as `firewall/policies` | | The collection fails with its reason on the source and nothing is stored |
| `fail=drop:N`, `fail=timeout:N`, `fail=limit:N` | The next N requests get no answer, no answer after 25 seconds, or a rate limit asking to wait `retry_after` seconds (90 unless set). One failed request fails one collection | Collect snapshot fails with the reason. A scheduled collection (set the schedule to 5 minutes under Setup) keeps the source's status, shows the reason, and tries again after 1, 2 and 4 minutes, or after the wait asked for if longer; Activity lists each attempt. It passes once N is used up, or ends as Error after the third retry |
| `slow=<seconds>` | Holds every answer that long | A long collection. The site at real size takes nearly 40 requests, so `slow=1` is about 40 seconds; over 90 seconds in all it fails |

### Changes at the fake sources

The default start is read only: the fixture refuses every change. To allow
them, reset the project (`down -v`, under Logs, shutdown, and reset) and start
it fresh with the kinds of source Nyctr may change. The checker reads the same
variable and then requires Nyctr to say changes are enabled:

```sh
export NYCTR_ACCEPTANCE_WRITES=unifi_network,nextdns
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml up --build --wait -d
python3 tests/acceptance/check.py
python3 tests/acceptance/check.py --scenarios
```

A fresh project is needed because setting the variable on a running one
restarts the fixture (see Start the application). The fixture then accepts and
remembers each change until it restarts, and reports it on the next read.

**An exception.** Only a member can ask for one in the console, and this stack
has no member account. So with changes allowed, `--scenarios` also asks, as the
administrator, for `lookup-00.example.test` to be opened for 15 minutes, and
prints `PASS request`. In the console: Requests shows it waiting; Approve opens
it; Open now lists the name with the time left and "Changed at the provider and
checked."; End now ends it. The name is on the DNS profile's allowed list while
the exception is open and leaves it when it is ended or runs out. One project
has one request: once it is decided, `--scenarios` prints that it found it so.

**Guests.** On Guests, let the waiting guest on (`Example speaker 62`) and cut
one off; What this stack cannot show says what a cut-off looks like here.

**A pass, by API until the console can choose the source.** The pass form names
no source, so Nyctr takes the first by name, here one that never collects, and
refuses. This issues one at the site at real size (one more sign-in) and prints
it; End on its row on Guests ends it:

```sh
PYTHONPATH=tests/acceptance python3 - <<'EOF'
import check; client = check.Client("http://localhost:8091"); client.login()
source = next(row["id"] for row in client.json("/api/guests")["sources"] if row["name"] == "Scenario - site at real size")
print(client.json("/api/guests/passes", method="POST", expected=201, body={"name": "Example pass", "minutes": 60, "integration_id": source}))
EOF
```

Three more switch values act on changes only:

| Switch | What the source does | Use it to see |
| --- | --- | --- |
| `writes=fail` | Fails every change | A change recorded as failed, with nothing shown as applied |
| `writes=pause:<seconds>` | Holds each change that long, then makes it | A change in flight: remove the source, or end the exception or pass, while it waits. Set `writes=fail` during the wait to make the undo fail |
| `writes=on` | Accepts changes again | |

For an exception that runs out while a collection is under way, set `slow=2`,
open a 15 minute exception and collect the site at real size as it ends.

### What this stack cannot show

- The member side. The stack has one account, the administrator, and no way to
  add a member with local sign-in. What a member sees and does (their own
  blocks, asking for an exception, their requests) is seen in Demo mode.
- Scores, the High, Medium and Low filters, and the automatic access rule: every
  block here has a reason the scorer does not know, so nothing is ever scored.
- Real lookup volume. A real profile at the bound has a different time on every
  row, so the 4000 rows kept are about 4000 blocks, ten times what this one
  stores. The fixture repeats each lookup on ten rows because 4000 different
  ones make an answer larger than the checker accepts and a Blocks screen that
  draws every row.
- The lookback setting: the fake log read ignores the time window it is asked
  for, so changing it shows nothing.
- Paging of any gateway list but the rules; the others fit in one page.
- A second kind of DNS source, or a third kind of source: only the gateway and
  one DNS service are fabricated.
- A request limit that counts: the cloud address is served without one, so
  pacing is seen as a longer collection, and a rate limit only when switched on.
- Issuing a pass from the console: its form cannot choose the source (see above).
- A verified cut-off or a working "Let it back on". A guest who is cut off is
  gone for good here, where a real device normally rejoins and is listed again.
  So Nyctr cannot read the result back, the row stays Cut off after the next
  collection (320 items), and Let it back on fails with the source's answer.
- A guest signing in on the Wi-Fi's own page, using up a pass, moving between
  access points, or making lookups that are tied to it.
- Firewall events, single sign-on, and anything that depends on how a real
  source behaves. What the fixture remembers is lost when it restarts, while
  Nyctr's database keeps its own record; reset the volumes to start level.

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
  are exactly `fixture`, `api.nextdns.io` and `api.ui.com`; `untrusted-fixture` is deliberately
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

Reset **only this disposable project**, deleting its synthetic database and CA
(add `--rmi local` to remove the image it built as well):

```sh
docker compose -p nyctr-acceptance -f tests/acceptance/compose.yaml down -v
```

## Focused helper tests

With the API development dependencies installed, the helper tests exercise real
loopback TLS handshakes, valid and invalid certificate names, credential
rejection, the read-only default (on the wire and in the compose file), the site at real size, each switch, every
change Nyctr can make, normal production-parser compatibility, and rejection of
remote checker URLs:

```sh
python3 -m unittest discover -s tests/acceptance -p 'test_*.py' -v
```

Those helper checks supplement the Docker run; they do not validate container
startup, PostgreSQL persistence, or a real provider deployment.
