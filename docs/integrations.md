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
from that read and reports the gap. The vendor's Site Manager API description
limits its cloud pass-through to 100 requests a minute for each console (and 25
seconds for a request, 10 MB for a response). These detail reads therefore stop
once the collection has made 96 requests, after setting aside the guest and
closing reads. That is not a ceiling on the whole collection: lists long enough
to need several pages, or many sites, can take a collection past 100, and a
second collection or connection test in the same minute counts against the same
limit. The source then answers with its rate-limit error and the collection
fails, as it does for any rate limit. A site with 10 networks, 13 pieces of
equipment and 67 devices costs 30 requests, plus one for each guest device up
to 40.

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

The local integration base URL has this shape:

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
