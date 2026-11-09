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

## 2. Collection and network posture

- Durable background collection, scheduling, bounded retries and health reporting.
- UniFi ports, uplinks, VLANs, zones, rule ordering and configuration snapshots.
- UniFi Fabric's Site Manager discovery/health channel, separately scoped from
  organizational policy capabilities that require verified APIs.
- UniFi firewall/CEF event receiver within the UniFi integration.
- Optional generic log ingestion for sources without dedicated integrations.
- Proxmox cluster/node/guest firewall and virtual-network relationships.
- Device identity reconciliation, temporal assignments and attribution confidence.
- Historical drift, exposure findings and explicit evidence gaps.

Exit gate: real test environments validate each claimed capability; failures and
partial coverage cannot be mistaken for clean posture.

## 3. Investigation and AI

- Evidence-backed policy and reachability analysis, with focused finding graphs.
- Background domain investigation, explainable risk dimensions and source links.
- Unknown/insufficient-evidence state distinct from low risk.
- BYO model provider with LiteLLM-compatible routing and future Spektr support.
- Scoped, redacted model context; prompt-injection and output validation tests.
- Authenticated external MCP tools for scoped posture questions and evidence reads.

Exit gate: explanations are reproducible from retained evidence; models have no
infrastructure credentials or independent execution authority.

## 4. Controlled remediation

- Immutable exact-plan approval binding and separate execution authority.
- Rule/source ownership, before/after diffs, blast-radius and drift checks.
- DNS exceptions and verified provider-specific firewall changes.
- Durable temporary leases, expiration/revocation, overlap handling and recovery.
- Administrator-defined limited auto-grant policies, rate limits and audit.
- Administrator permanent-allow review after qualifying temporary requests.

Exit gate: failure/restart tests prove expiry reconciliation and prevent removal
of pre-existing or independently changed provider configuration.

## 5. Broader platform and operations

- AWS networking (VPCs, routes, security groups, NACLs and observations).
- Azure networking (VNets, subnets, NSGs, routes and observations).
- Multiple sites and organizations with explicit tenancy boundaries.
- Helm packaging and documented integration with GitOps deployment workflows.
- Retention policies, audit export, backups, upgrades, release signing and SBOMs.
- Large-graph performance, accessibility review, localization and mobile polish.

## Out of scope without a separate design decision

TLS interception, endpoint certificate deployment, autonomous model-controlled
firewall writes, and unscoped public infrastructure scanning are not assumed
requirements. The self-service portal uses authenticated observation history;
it does not require replacing the browser's HTTPS block/error page.
