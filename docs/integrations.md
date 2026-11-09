# Integrations

## Read-only collection

Live integration setup requires administrator access. Demo mode cannot configure
or synchronize live providers. Store each API credential in the server environment
and use its name in the integration form:

```text
NYCTR_CONNECTOR_SECRET_UNIFI=<set through your secret manager>
NYCTR_CONNECTOR_SECRET_NEXTDNS=<set through your secret manager>
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

The initial adapter targets the supplied **UniFi Network API 11.0.97** contract:
sites, networks, devices, clients and configured firewall policies. The local
integration base URL has this shape:

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

No allowlist operation is implemented. A future allowlist exception is generally
profile scoped and needs scope disclosure, owned leases and expiry reconciliation.

## Planned integrations and capability boundaries

| Integration | Planned scope | Boundary |
| --- | --- | --- |
| UniFi Fabric | Site Manager discovery/health, verified shared policy capabilities | Separate API connections and evidence coverage within one product section |
| Proxmox | Nodes, guests, bridges and firewall configuration | Hypervisor policies can add another enforcement layer |
| AWS | VPC topology, security groups, NACLs, routes and available observations | Account/region permissions and observation coverage remain explicit |
| Azure | VNets, subnets, NSGs, routes and available observations | Subscription/resource scope remains explicit |
| Additional log sources | Supported event formats for otherwise unsupported sources | Receiver configuration alone does not prove complete logging |

The provided **Carrier / ISP Fabric Subscriber API 1.0.0** is an ISP subscriber
management contract. It does not establish access to organizational Fabric
Blueprint/Canvas policy configuration. The provided **Site Manager 1.0.0**
contract is tracked separately.

## References

- [NextDNS API documentation](https://nextdns.github.io/api/)
- [UniFi developer portal](https://developer.ui.com/)
- User-provided Network 11.0.97, Site Manager 1.0.0 and Carrier/ISP Fabric 1.0.0
  OpenAPI contracts informed the initial implementation. Raw exports and personal
  deployment settings are not bundled in this repository.
