# Integrations

Nyctr's core is vendor neutral. Each integration below is one module that
declares what it reads and which capabilities it adds; the
[integration contract](integration-contract.md) describes how to write one. The
Sources page in the console shows the same information for a running server.

Collection is always read only. What Nyctr may change at a provider is a separate
server setting, described under [Provider changes](#provider-changes).

## Read-only collection

Live integration setup requires administrator access. Demo mode cannot configure
or synchronize live providers. Store each API credential in the server environment
and use its name in the integration form:

```text
NYCTR_CONNECTOR_SECRET_UNIFI=<set through your secret manager>
NYCTR_CONNECTOR_SECRET_NEXTDNS=<set through your secret manager>
NYCTR_CONNECTOR_SECRET_PROXMOX=<API token: user@realm!name=value>
NYCTR_CONNECTOR_SECRET_PIHOLE=<an application password made for Nyctr>
```

Only names starting with `NYCTR_CONNECTOR_SECRET_` are accepted. Credential values
are not stored in integration configuration or returned to the browser. In
Kubernetes, inject these using your secret management system rather than storing
them in Git. Secret rotation takes effect when the running process receives the
updated environment; restart the deployment after environment-secret changes.

## Changing a saved source

**Edit** on a source's card opens the connection form filled in. The kind of
source cannot be changed, and only the secret's name is shown. Its name and
numeric settings, such as the hours of lookups to read, can change at any time
and keep its status. Where it reads (its address, every other setting such as a
profile or site, and the secret name) can change only until it first stores a
collection, partial ones included, so a mistake can be corrected; the source then
needs a test again. After that the form shows these as read only and the server
refuses with 409: to read from somewhere else, add a new source, which starts
with nothing from the old one.

The other side of that rule: Nyctr changes nothing at a source until it has
collected from it once. Opening an exception (by approval, by the access rule or
as a permanent one), issuing a guest pass, and letting a guest on, cutting one
off or locking one out are refused in plain words before anything is sent. So a
source can never move while Nyctr is changing something there.

A change is checked as a new source is, by the integration's own validation and
the `NYCTR_CONNECTOR_HOSTS` allow-list. A refused change leaves the source and
the audit history as they were. The refusal names the field by its label on the
form and says what to change. It never names a setting key or a variable, and
never repeats an address. Where only whoever runs the server can put it right,
it says so: "names a server Nyctr is not yet allowed to connect to" means the
address's host name is missing from `NYCTR_CONNECTOR_HOSTS`. Saving a new source
is refused in the same words. An edit is refused while a collection or
diagnostic of that source is running, and in demo mode. Overlapping edits are
applied one after the other. The audit history records who changed which fields
of which source, never the values.

## What a collection could not read

A gap is something a collection could not read or could not work out: a read the
key may not make, detail reads stopped at a limit, a setting the source did not
return. Every collection records the gaps it hit, whether the schedule, a person
or a nudge started it, with the same codes and texts the connection test shows.
The codes go into the collection's entry in Activity's record; nothing from the
source's answer, no address and no secret name is kept with them.

A source whose last stored collection had gaps is shown as "Connected, with
gaps". Its card says what could not be read and what that means, and the
Briefing lists it under "Needs you" until a later collection reads everything. A
collection that fails stores nothing, so the gaps of the last stored collection
stay on the card beside the error. A partly collected source is listed there
too, with a link to its Edit form, where a shorter time window is the cure.

Where the source's answer says why, the card says it: the source refused the
read (this key may not read it), or the source had an error of its own (the next
collection may read it). Neither fails the collection. A rate limit, a timeout
or a broken connection still does.

## Removing a source

**Remove** on a source's card shows, with counts, what goes and what stays, and
asks for the source's name to be typed. Removal sends nothing to the source and
changes nothing there; it cannot be undone.

What goes: everything collected from the source (devices and other inventory,
networks, rules, relationships, blocked lookups, sightings, guest history and
passes read from it that are still live), findings that rest only on its items,
each of its devices' assignments to people, and links between its items and DNS
labels. Another source's lookups that were tied to one of its devices stay, no
longer tied to that device. What stays: requests, exceptions and guest passes
Nyctr recorded (any still open but not Nyctr's at the source are ended), and the
whole activity history. The removal's own record keeps the source's name and kind
and the counts removed, so requests still name it.

Removal is refused while Nyctr still has something of its own at the source: an
open exception it applied, a guest pass it issued that is still live, or a guest
it cut off or locked out. The refusal says how many and where to end them. A
guest Nyctr let on does not hold removal back, because that grant ends by itself
at the source; the confirmation says, with a count, that those guests stay let on
until their time ends and that Nyctr can no longer cut them off. It is
also refused while a collection or diagnostic of the source is running, and in
demo mode. Adding a source again, for the same place or another, starts from
nothing: no device, assignment, label link, guest state or finding comes back.

If a source is removed while Nyctr is opening an exception or issuing a guest
pass there, Nyctr takes back what it just added, at the place the call used, and
says so. If that fails, the exception stays under Open now with what to remove
by hand; Nyctr cannot reach it any more, so it is not retried, and **I removed
it by hand** ends it once that is done. A guest let on, cut off or locked out
during the removal is not undone: the activity history records what was done
at which source.

## Connection diagnostics

On a saved live-mode integration, **Run diagnostics** performs the same bounded
GET-only reads used by collection and reports configuration, credential,
transport/TLS, response-contract and capability evidence. It does not import
resources or observations, refresh the collection timestamp, or change the
previous collection-health outcome. An audit entry records the sanitized check
result. A collection or another diagnostic already in progress returns a busy
response rather than starting overlapping work.

The capability table separates what an adapter implements from what this check
actually verified. For example, no visible UniFi sites leaves per-site reads
unverified, and a NextDNS profile with logging disabled cannot provide a verified
blocked-query stream. A passed check is not an end-to-end traffic test or a
destination safety decision. Use **Collect snapshot** separately to import data.

For independent acceptance testing, use [local HTTPS fixtures](../tests/acceptance/README.md).
They exercise the real connector transport with synthetic endpoints and retain
certificate verification. They require no access to actual provider accounts or
the maintainer's network.

## UniFi Network

The adapter targets the supplied **UniFi Network API 11.0.97** contract: sites,
networks, devices, clients, configured firewall policies, guest access state and
hotspot vouchers. Guest authorisation details (time, expiry, data use) are read
per guest client, for at most 40 guests per collection across all sites. If the
voucher list is not available to the key, collection continues and reports the
gap. A rate limit, a broken connection or a spent request budget during one of
these optional reads fails the collection instead, so an incomplete snapshot is
never stored under the wrong explanation.

Each network's address range and each device's uplink come from one detail read
per network and per device. These are optional reads too: a read the key may not
make, or an answer that is malformed or about a different record, keeps nothing
from that read and reports the gap. They stop once the collection has made 96
requests, after setting aside the guest and closing reads. With several sites,
every site's lists are read first and the detail reads that fit are shared: each
site gets what it needs up to the same level, so a small site is read in full
and large ones are cut short alike. The gap is reported once, and each site that
was cut short carries `detail_reads_skipped` with how many network and equipment
reads were left out. A site with 10 networks, 13 pieces of equipment and 67
devices costs 30 requests, plus one for each guest device up to 40.

### Through the cloud address

The adapter accepts two addresses: the console's own (below) and the vendor's
cloud pass-through, `https://api.ui.com/v1/connector/consoles/<console id>/proxy/network/integration`,
with `api.ui.com` in `NYCTR_CONNECTOR_HOSTS`. The vendor's Site Manager API
description limits the pass-through to 100 requests a minute for each console,
25 seconds for a request and 10 MB for a response (Nyctr refuses an answer over
2 MB from any source).

Through the cloud address one copy of Nyctr sends at most 96 requests to one
console in any 60 seconds. Scheduled and manual collections, connection tests
and a collection started by the console's webhook share that count, as do two
saved sources that point at the same console. A request that does not fit waits
for its turn instead of being sent and refused. A request is counted from when
its answer arrived. The console's own address is not paced.

A collection through the cloud address, with the `proxy` segment in the path as
above, succeeded against a real console on 2026-11-13: one installation, read
only. Everything else here, including the pacing, the error answers and the
sharing between sites, is tested with fabricated answers only.

- A collection whose lists each fit one page makes at most 96 requests and does
  not wait. One that needs more (a guest pass or Wi-Fi list long enough to page)
  finishes about a minute later.
- Reading is limited to 60 seconds for every source; time spent waiting for a
  turn is not counted in it. A collection waits at most 120 seconds in total,
  which is two full minutes of the limit and happens only when something else
  used the console just before. If it would have to wait longer it ends as a
  rate limit and the scheduled retry comes back after the wait. So a collection
  ends within 180 seconds, a backstop stops it at 210, and its lease on the
  source lasts 300.
- A connection test waits at most 20 seconds in total for a turn. Past that it
  reports that the request limit is in use and to try again shortly.
- While a scheduled collection waits, the console and the API are served as
  usual. The collection pass it belongs to does not move on: the other sources
  in that pass, and a run or retry that comes due meanwhile, wait for it. Any
  source may hold the pass for its 60 seconds of reading; a paced source may
  hold it for up to the 180 seconds above. The ending of expired exceptions
  does not wait: the upkeep loop starts it on every tick, whether or not a
  collection pass is still going.

What pacing does not cover:

- The count is kept in the running process. Two copies of Nyctr on one database
  each keep their own, so together they can send up to twice the pace to one
  console; so can a restart inside the same minute. The scheduled run is claimed
  by one copy only, so this needs a test or manual collection on one copy while
  another collects. The source then answers with its rate-limit error and the
  collection fails and is retried, as for any rate limit.
- Changes Nyctr makes at the console (issuing or ending a guest pass, letting a
  guest on or cutting one off) are not paced or counted. The four requests a
  minute between the pace and the vendor's limit are left for them.
- Anything else that uses the same console through the cloud address counts
  against the same limit at the vendor.

The cloud's own error answers are read by their status only; nothing in their
body is shown or stored. A rate limit fails the collection as a rate limit and
keeps the wait the cloud asked for, when it gives one in seconds. A device
timeout (408) or a bad gateway (502) on a read the collection needs fails it as
a fault that may pass, so a scheduled collection is retried; on an optional read
it is reported as that read's gap, as any server error is. "Unauthorized" (401) and "forbidden or not the
owner of the host" (403) are refusals: nothing is retried until the key or its
access is put right.

What the adapter states and what Nyctr works out are kept apart:

| Fact | Where it comes from | Shown as |
| --- | --- | --- |
| A network's address range and gateway address | The network's detail read | Configured |
| The switch that runs a switch-managed network | The network's `deviceId` | Configured |
| The equipment above a piece of equipment | The device's detail read (`uplink.deviceId`) | Observed |
| Which device is the gateway | The device's feature list. Failing that, Nyctr's deduction from the collected addresses and ranges (below) | Observed device. A deduced gateway carries `kind_basis`, and its panel says Nyctr worked it out and from what |
| Which network a client is on | Not reported by this API. Worked out when the graph is read, from the client's address and the collected ranges. Nothing in a site is placed while a network there that a gateway or switch manages has no collected range | Inferred, never stored |
| Which gateway runs a gateway-managed network | Worked out when the graph is read, when the site has exactly one gateway | Inferred, never stored |

A console can list its gateway with the switching feature only. Nyctr files a
device as the gateway on the first of these that names one:

1. The source lists the device with the gateway feature. This is the source's
   own statement and carries no `kind_basis`.
2. Exactly one device's own address is the gateway address of a network the
   source says its gateway manages (`kind_basis: gateway_address`).
3. No device holds a gateway address, as when the gateway reports its
   internet-side address. Then, if the range of every gateway-managed network
   was collected, every piece of equipment reports an IPv4 address (the family
   the ranges are read in), exactly one of them is outside every collected
   range of the site, that device's detail read reports nothing above it, and
   at least one other piece of equipment reports it as its uplink, that device
   is the gateway (`kind_basis: outside_network_ranges`). Client devices
   attached to it do not count: a lone access point has clients too.

The second and third are Nyctr's deduction, not the source naming a gateway, and
the device's panel on the Map says so. If none holds, nothing is filed as a
gateway and the connection test reports that gap.

The third rule can be wrong in one shape, and this source's data cannot tell it
apart from a real gateway: the site's router is another vendor's, the source
still holds a gateway-managed network, and the core switch has equipment below
it and a management address outside every collected range. That switch would be
filed as the gateway. The same holds, behind another vendor's router, for an
old switch with an out-of-range address that still has one old access point
naming it as its uplink: this source's data cannot tell that pair apart from a
gateway with equipment below it either. It is why this stays a labelled
deduction and is never shown as the source's statement. A device with nothing
attached, a site with a single piece of equipment, and equipment reporting an
IPv6 address are never filed by this rule.

The console's own integration base URL has this shape:

```text
https://console.example.internal/proxy/network/integration
```

Set `NYCTR_CONNECTOR_HOSTS=console.example.internal` on the server. Multiple
explicit hosts may be comma-separated. The UI accepts the base URL, an optional
site ID, and the environment-secret reference. Use a trusted TLS certificate;
the adapter does not offer an insecure skip-verification option.

Inventory/configuration collection is separate from firewall-event collection.
The first adapter does not subscribe to events or open a syslog receiver. Those
will be separate channels under the UniFi Network integration.

Client display names and IPs do not create user assignments. Imported clients
start unassigned. Configured rules do not prove which rule matched a real packet.

Guests sign in on UniFi's own captive portal; Nyctr is never the portal. The
reasons and the UniFi setup steps are in [guest-wifi.md](guest-wifi.md). The
adapter also reads each site's Wi-Fi names and whether a captive portal gates
them, so the console can show that the guest Wi-Fi really is behind one.

The API lists only connected clients, has no event or flow feed, and does not say
which voucher a guest used. Nyctr therefore keeps its own record of which access
point each guest was on at each collection, shows the pass a guest most likely
used as an inferred match on activation time, and cannot see connection attempts
or port scans. Guest activity comes from blocked DNS lookups tied to the device.

## NextDNS

The adapter uses the fixed official `https://api.nextdns.io` endpoint and a
profile ID. It collects profile configuration and recent blocked-query records.
The provider's account API key is resolved from the environment reference.

Optional `lookback_hours` is bounded to 1–72. Collection is bounded, so a busy
profile may require the later incremental collector to establish full coverage.
Logging must be enabled and available at the provider for events to exist.

If your gateway forwards all DNS upstream, the upstream records may lack useful
per-device identity. Nyctr keeps these blocks unattributed and administrator-only.
Even a provider device label is not enough to assign a real user without a trusted
mapping. Member self-service requires that separate attribution layer.

Blocked lookups keep the provider's reason identifiers, which the risk score
reads. An administrator can link a NextDNS device label to an inventory device
under Setup; the link applies only to lookups observed after it is made, so it
never backdates what a member can see.

## Proxmox VE (experimental)

Reads `/cluster/resources`, each node's `/network`, each guest's `/config` and
`/firewall/options`, and `/cluster/firewall/options`, using an API token sent as
`Authorization: PVEAPIToken=...`. Give the token a read-only role such as
`PVEAuditor`. Enter the host address, for example `https://pve.example:8006`,
and add the hostname to `NYCTR_CONNECTOR_HOSTS`. At most 48 guests are read per
collection.

This adapter was written from the documented API and has not been run against a
cluster. Firewall rules are not read, only the on/off switches. A failed firewall
option read leaves the state unknown, never off.

Nyctr joins any source that provides `compute` to any source that provides
`inventory` at read time: a workload's network card and a network client with the
same hardware address, a card's VLAN tag and a network with that VLAN, a host
address and a client with that address. Each is shown as inferred with its
basis, and an ambiguous match produces no link.

## Pi-hole (experimental)

Reads recently blocked lookups from a Pi-hole v6 resolver. Enter its HTTPS
address, for example `https://pihole.example.net`, add the hostname to
`NYCTR_CONNECTOR_HOSTS`, and add its certificate to `NYCTR_CONNECTOR_CA_BUNDLE`
if it is self-signed. The secret is the web password or, better, an application
password created for Nyctr. Optional `lookback_hours` is bounded to 1 to 72, and
at most the newest 2,000 queries in the window are read.

Pi-hole has no API keys, so collection signs in (`POST /api/auth`), reads
`GET /api/queries` with the session id in the `X-FTL-SID` header, and signs out
(`DELETE /api/auth`), even when a read fails. Nothing on the Pi-hole is changed.

What this integration deliberately does not do:

- It does not open blocked addresses. It declares no `dns.exceptions`
  capability, so the access rule never acts on a Pi-hole block and an approved
  request is recorded as not applied for you to carry out in Pi-hole.
- It does not score a block from a subscribed list. Pi-hole does not say whether
  a list is about adverts or threats, so those blocks stay unknown. Blocks from
  the deny list or a deny pattern are scored as an administrator's rule.
- It does not treat a client name as identity. Names come from Pi-hole's own
  network table; a block stays unassigned until an administrator links the label
  to a device under Setup.

Sign-in follows Pi-hole's published authentication contract. The query-log field
names follow the published API description and have not been run against a live
Pi-hole by this project.

## Provider changes

Off unless the integration is listed in `NYCTR_PROVIDER_WRITES` (comma separated).
Only integrations that declare a write capability are accepted there; naming any
other, such as `pihole` or `proxmox`, stops the server at start-up with a clear
message.

| Provider | Call | Used for |
| --- | --- | --- |
| `nextdns` | `GET`, `POST /profiles/{id}/allowlist`, `DELETE /profiles/{id}/allowlist/{domain}` | Opening and closing a lease |
| `unifi_network` | `POST`, `DELETE /v1/sites/{site}/hotspot/vouchers` | Issuing and ending a guest pass |
| `unifi_network` | `POST /v1/sites/{site}/clients/{client}/actions` with `AUTHORIZE_GUEST_ACCESS` or `UNAUTHORIZE_GUEST_ACCESS` | Cutting off, restoring and locking out a guest |

A NextDNS allowlist entry applies to everyone on the profile. An entry that
already existed is never removed. The NextDNS allowlist path follows the API's
documented rule that every nested array has its own endpoint; the documentation
shows the denylist form explicitly. None of these calls has been exercised
against a live service by this project.

## Planned integrations and capability boundaries

| Integration | Planned scope | Boundary |
| --- | --- | --- |
| UniFi Fabric | Site Manager discovery/health, verified shared policy capabilities | Separate API connections and evidence coverage within one product section |
| Proxmox | Firewall rules, SDN zones and virtual networks | The experimental adapter reads only inventory, cards and firewall switches |
| AWS | VPC topology, security groups, NACLs, routes and available observations | Account/region permissions and observation coverage remain explicit |
| Azure | VNets, subnets, NSGs, routes and available observations | Subscription/resource scope remains explicit |
| Additional log sources | Supported event formats for otherwise unsupported sources | Receiver configuration alone does not prove complete logging |

The provided **Carrier / ISP Fabric Subscriber API 1.0.0** is an ISP subscriber
management contract. It does not establish access to organizational Fabric
Blueprint/Canvas policy configuration. The provided **Site Manager 1.0.0**
contract is tracked separately.

## References

- [NextDNS API documentation](https://nextdns.github.io/api/)
- [Pi-hole API authentication](https://docs.pi-hole.net/api/auth/)
- [UniFi developer portal](https://developer.ui.com/)
- User-provided Network 11.0.97, Site Manager 1.0.0 and Carrier/ISP Fabric 1.0.0
  OpenAPI contracts informed the initial implementation. Raw exports and personal
  deployment settings are not bundled in this repository.
