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
| `status` | `stable` or `experimental`. Say `experimental` until it has run against the real thing |
| `fields`, `secret_hint` | The connection form. Secrets are never fields; the form only takes the name of a server environment variable |
| `validate(config)` | Reject unknown keys, unapproved hosts and unbounded settings before any credential is used. Use `core.validated_host` for every address |
| `collect(integration_id, config, secret)` | Return a `Snapshot`. Read only |
| `reads` | What collection reads, as `(id, label)`. Diagnostics report each one as verified, unavailable or unknown |
| `provides` | The capabilities below |
| `classify(text)` | Optional. Explain one block reason: `(category, base score, sentence)`, or a score of `None` to say the source cannot tell |
| `limitations`, `gaps`, `gap_notes` | What the source cannot support or cannot tell Nyctr, in plain words, shown with every connection test |
| `scope(config)` | Optional. The configured scope (a site, for example) that actions apply to |
| `allow_domain`, `disallow_domain`, `issue_pass`, `end_pass`, `guest_access` | Actions, present exactly for the write capabilities declared |

The registry refuses to start if a provider declares a write capability without
its actions, or actions without the capability.

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
| `gateway`, `switch`, `access_point` | `ip`, `mac` |
| `network` | `vlan` |
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
