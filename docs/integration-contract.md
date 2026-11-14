# Writing an integration

Nyctr is the product. An integration is how one kind of source feeds it. The core
(`services/api/nyctr/*.py`) and the web app never name a vendor: they ask whether
a source offers a capability and call whatever that source's integration declared.
Two tests keep it that way (`tests/test_registry.py`): one fails if a core module
contains a vendor name, the other fails if the web app does.

Adding a source therefore means adding one module under
`services/api/nyctr/integrations/` and listing it in `registry._MODULES`. The
console's source list, connection form, capability table, chips and map views all
come from `GET /api/integrations/catalog`, so the web app needs no change.

## What an integration declares

Each module exposes `PROVIDER`, a `registry.Provider`:

| Field | Purpose |
| --- | --- |
| `id`, `name`, `summary`, `letter`, `tone` | Identity and how the console shows it. `tone` is one of `blue`, `teal`, `orange`, `rose`, `violet`, `grey` |
| `logo` | Optional. The file name of the source's own logo in `integrations/logos/`. See below |
| `status` | `stable` or `experimental`. Say `experimental` until it has run against the real thing |
| `fields`, `secret_hint` | The connection form. Secrets are never fields; the form only takes the name of a server environment variable |
| `validate(config)` | Reject unknown keys, unapproved hosts and unbounded settings before any credential is used. Use `core.validated_host` for every address |
| `collect(integration_id, config, secret)` | Return a `Snapshot`. Read only |
| `reads` | What collection reads, as `(id, label)`. Diagnostics report each one as verified, unavailable or unknown |
| `provides` | The capabilities below |
| `classify(text)` | Optional. Explain one block reason: `(category, base score, sentence)`, or a score of `None` to say the source cannot tell |
| `limitations`, `gaps`, `gap_notes` | What the source cannot support or cannot tell Nyctr, in plain words, shown with every connection test. `gaps` also travel in the catalog as `limits`, and the Briefing lists them under "Keep in mind" for each connected source. `gap_notes` are also shown on the source's card after a collection that recorded their code |
| `not_collected` | Optional. What a source of this kind never collects, each a few plain words ("DNS lookups that were allowed"). It travels in the catalog, and the Briefing lists it under "Not collected" for each connected source. A caution about evidence that is collected belongs in `gaps` |
| `scope(config)` | Optional. The configured scope (a site, for example) that actions apply to |
| `allow_domain`, `disallow_domain`, `issue_pass`, `end_pass`, `guest_access` | Actions, present exactly for the write capabilities declared |

The registry refuses to start if a provider declares a write capability without
its actions, or actions without the capability.

## Logos

A source's chip shows its logo where the integration declares one and its `letter`
on its `tone` where it does not. To declare one, save the vendor's own file in
`services/api/nyctr/integrations/logos/` as a lower-case `.svg` or `.png` name,
unedited, add a row to `SOURCES.md` in that folder saying where it came from, and
set `logo="<file name>"`. Prefer the symbol to the wordmark, a vector file where
the vendor publishes one, and the variant made for dark backgrounds.

The registry reads the file once and puts the picture itself in the catalog as an
image `data:` address, so no route serves logo files. It refuses to start if a
declared file is missing, is larger than 96 KB, is not the type its name says, or
is an SVG containing script, event handlers or embedded pages. The console shows a
logo only through an image element, where a browser runs nothing the file
contains, and ignores any value that is not an embedded PNG or SVG. The chip
falls back to the letter when there is no logo or the picture does not load.
`tone` still colours the source on lines, on the Map and in status, so declare
both.

## Capabilities

| Capability | What it adds to Nyctr | Changes the source |
| --- | --- | --- |
| `inventory` | Devices, networks and rules on the map and in inventory | No |
| `dns.blocks` | Blocked lookups for the Blocks page and the member portal | No |
| `dns.exceptions` | The access rule and approvals can open an address for a while | Yes |
| `guest.devices` | The Guests page: who is on, where, and how they got on | No |
| `guest.passes` | Issuing and ending guest passes | Yes |
| `guest.control` | Letting a waiting guest on, cutting one off, locking one out | Yes |
| `compute` | Hosts and workloads, and inferred links from them to network devices | No |

A feature works when a connected source offers its capability. When none does,
the console says so instead of failing: the access rule reports that no connected
source can open an address, and a request about a block from a source without
`dns.exceptions` waits for a person with that stated as the reason.

| Integration | Provides |
| --- | --- |
| UniFi Network | `inventory`, `guest.devices`, `guest.passes`, `guest.control` |
| NextDNS | `dns.blocks`, `dns.exceptions` |
| Proxmox VE (experimental) | `compute` |
| Pi-hole (experimental) | `dns.blocks` |

## Neutral attributes

An adapter translates vendor fields into the names the core reads. Anything else
it keeps is source detail for people to read and query.

| Resource kind | Attributes the core reads |
| --- | --- |
| `client` | `ip`, `mac`, `uplink` (source id of the device it is attached to), `connected_at` |
| `client` on guest access | `guest: {authorized, method, authorized_at, expires_at, bytes, seconds}` where `method` is `pass`, `console`, `other` or absent |
| `gateway`, `switch`, `access_point` | `ip`, `mac`, `uplink` (source id of the equipment above it) |
| `gateway` filed on evidence other than the source naming it one | `kind_basis` saying which evidence (see below) |
| `network` | `vlan`, `subnets` (the address ranges the source configured, as `["192.0.2.0/24"]`), `gateway_ip`, `managed_by` (`gateway`, `switch` or `unmanaged`) |
| `workload` | `nics: [{bridge, mac, vlan, firewall}]`, `firewall_enabled` |
| `host` | `addresses` |
| `site` | `wifi: [{name, enabled, captive_portal, network_id}]` |
| `dns_profile` | `logs_enabled` |

Guest passes go in `Snapshot.passes` as `{id, code, name, minutes, guest_limit,
data_limit_mb, guest_count, created_at, activated_at, expires_at, expired}`. Leave
`passes` as `None` when the source did not report them this time, so stored passes
are left alone; a list is treated as the complete current set.

Blocks go in `Snapshot.blocks` with `source` set to the integration id, the
provider's own reason text and `reason_codes`, `device_id` left `None`, and
`risk_score` left `None`. Scoring happens in the core and uses your `classify`.

## What the adapter states and what Nyctr works out

An adapter writes only what its source said. A network's `subnets` are
configured evidence. A `connects_to` link from a client or a piece of equipment
to the equipment above it, taken from the source's uplink, is observed. A
`managed_by` link from a network to the device the source names is configured.

When a source reports addresses and ranges but not membership, the adapter does
not write a `member_of` link. `nyctr/links.py` places a client on a network when
the graph is read, if its `ip` falls inside the `subnets` of exactly one network
from the same connection and site, and links a network whose `managed_by` is
`gateway` to that site's gateway when there is exactly one. Both links are
labelled inferred, carry their basis, and are never stored. A client with no
address, or an address in no range or in more than one network's range, gets no
link and the console shows its network as not reported. A network whose
`managed_by` is `gateway` or `switch` has a range; while one such network of a
site has no `subnets`, no client of that site is placed, because its address
could belong there. An `unmanaged` network has no range to miss and does not
block placement.

`kind_basis` is absent when the source itself said what kind a device is. An
adapter that files a device on anything else sets it, and the console then says
on the device's panel that Nyctr worked the kind out and from what:

| `kind_basis` | Meaning |
| --- | --- |
| `gateway_address` | The source does not list the device as a gateway. Its own address is the gateway address of a network the source says its gateway manages, and no other device holds one |
| `outside_network_ranges` | The source names no gateway and no device holds a gateway address. Every gateway-managed range was collected, this is the only equipment whose address is outside every collected range, the source reports nothing above it, and other equipment reports it as its uplink |

A new value needs a row here and a sentence in the console. A value the console
does not know is still shown as worked out by Nyctr, never as the source's
statement.

## Rules every integration follows

- **Collection reads.** Use `ReadClient.get`. The one exception is a source that
  only offers session sign-in: it may sign in and out of its own session (Pi-hole
  does, with one `POST` and one `DELETE` to `/api/auth`) and must say so in its
  module docstring.
- **Changes live in `integrations/actions.py`** and nowhere else. Each takes an
  explicit `allowed` flag, validates its inputs, makes one documented call and
  reads back what it changed. They run only for an integration an operator named
  in `NYCTR_PROVIDER_WRITES`.
- **Never guess.** A reason your source does not explain stays unknown. A device
  name a source was told is a label, not an identity: leave `device_id` empty and
  let an administrator link it.
- **Say what was not verified.** If the adapter has not run against the real
  service, set `status="experimental"` and add a gap saying so.
- **Tests.** Mock the transport, cover a refused credential, malformed data, a
  future timestamp and every configuration the validator must reject. Use
  fabricated data only.

`pihole.py` is the smallest complete example: about 200 lines, one capability,
its own reason classifier, and no core or web change.
