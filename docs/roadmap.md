# Product roadmap

The full product spans network security, DNS, firewalls, ports, hypervisors and
cloud controls. Member self-service is one workflow within that platform.
This roadmap identifies dependencies and acceptance criteria, not release dates.

## 1. Runnable foundation — this implementation

- Professional repository, branded application and documented architecture.
- Real API, database, authentication and administrator/member authorization.
- Evidence-aware graph and resource inspection.
- Demo fixtures that exercise permitted, stale, unattributed and private events.
- Read-only UniFi Network and NextDNS adapter boundaries.
- Persistent requests, internal review and audit records.
- Docker image, PostgreSQL Compose setup, CI and reproducible checks.

Exit gate: application boots from a fresh database; member isolation and read-only
transport tests pass; packaged frontend and API work together.

### Deployable alpha

- Versioned container publication workflow with exact-source validation,
  multi-platform builds, SBOM metadata and provenance attestation.
- Helm packaging for external PostgreSQL, existing Secrets, OIDC settings,
  explicit proxy trust and optional Ingress/Gateway API routing.
- Guided integration diagnostics that distinguish verified reads from
  implemented capabilities and incomplete evidence.
- Isolated Docker provider fixtures and an independent browser-testing handoff.
- Chart rendering, isolated Kubernetes installation and persistence checks.

Exit gate: clean installation and the isolated acceptance suite pass for the
tested source revision. Publishing an image is a separate release action.
Synthetic fixtures do not establish real-vendor compatibility or homelab reach.

### Console MVP

A first working slice through stages 2 to 4, built before those stages' exit
gates are met. Each item below is marked in its stage as **(first version)**.

- New console and member portal design.
- Rule-based risk score, the access rule, durable leases and suggestions.
- Guest Wi-Fi passes, tracking, cut-off and the counted cut-off rule.
- Provider changes for NextDNS and UniFi, off by default, simulated in demo.
- Experimental Proxmox reader and inferred links between sources.
- Read-only GraphQL endpoint, attention list, assistant and finding insights.

Exit gate: every claimed provider read and write validated against a real
UniFi console, NextDNS profile and Proxmox node, with differences fixed.

## 2. Collection and network posture

- Durable background collection, scheduling, bounded retries and health reporting.
  **(first version: optional in-process interval, no retries)**
- UniFi ports, uplinks, VLANs, zones, rule ordering and configuration snapshots.
- UniFi Fabric's Site Manager discovery/health channel, separately scoped from
  organizational policy capabilities that require verified APIs.
- UniFi firewall/CEF event receiver within the UniFi integration.
- Optional generic log ingestion for sources without dedicated integrations.
- Proxmox cluster/node/guest firewall and virtual-network relationships.
  **(first version: nodes, bridges, guests, cards and firewall switches)**
- Device identity reconciliation, temporal assignments and attribution confidence.
  **(first version: administrator links from DNS labels to devices)**
- Guest Wi-Fi history beyond connected clients, and a UniFi-side block for
  locked-out devices. Guests keep signing in on UniFi's portal
  ([design](guest-wifi.md)); Nyctr does not become an external portal.
- Historical drift, exposure findings and explicit evidence gaps.

Exit gate: real test environments validate each claimed capability; failures and
partial coverage cannot be mistaken for clean posture.

## 3. Investigation and AI

- Evidence-backed policy and reachability analysis, with focused finding graphs.
- Background domain investigation, explainable risk dimensions and source links.
  **(first version: rule-based score from the block reason; no reputation source)**
- Unknown/insufficient-evidence state distinct from low risk.
- BYO model provider with LiteLLM-compatible routing and future Spektr support.
  **(first version: one OpenAI-compatible endpoint from server settings)**
- Scoped, redacted model context; prompt-injection and output validation tests.
  **(first version)**
- Authenticated external MCP tools for scoped posture questions and evidence reads.

Exit gate: explanations are reproducible from retained evidence; models have no
infrastructure credentials or independent execution authority.

## 4. Controlled remediation

- Immutable exact-plan approval binding and separate execution authority.
- Rule/source ownership, before/after diffs, blast-radius and drift checks.
- DNS exceptions **(first version)** and verified provider-specific firewall changes.
- Durable temporary leases, expiration/revocation, overlap handling and recovery.
  **(first version)**
- Administrator-defined limited auto-grant policies, rate limits and audit.
  **(first version)**
- Administrator permanent-allow review after qualifying temporary requests.
  **(first version)**

Exit gate: failure/restart tests prove expiry reconciliation and prevent removal
of pre-existing or independently changed provider configuration.

## 5. Broader platform and operations

- AWS networking (VPCs, routes, security groups, NACLs and observations).
- Azure networking (VNets, subnets, NSGs, routes and observations).
- Multiple sites and organizations with explicit tenancy boundaries.
- Chart upgrade compatibility and broader GitOps deployment workflows.
- Retention policies, audit export, backups, upgrades and release verification.
- Large-graph performance, accessibility review, localization and mobile polish.

## Out of scope without a separate design decision

TLS interception, endpoint certificate deployment, autonomous model-controlled
firewall writes, and unscoped public infrastructure scanning are not assumed
requirements. The self-service portal uses authenticated observation history;
it does not require replacing the browser's HTTPS block/error page.
