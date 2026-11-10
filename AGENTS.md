# Working on Nyctr

Read README.md, docs/architecture/overview.md, docs/security-model.md and
docs/roadmap.md before changing architectural behavior. Preserve the Nyctr console
design: near-black ground, layered panels, one blue accent, Geist type. Colour
names the source (UniFi blue, Proxmox orange, NextDNS teal). Line style names the
evidence (solid observed, dashed configured, dotted inferred). Hatching means
unknown or not collected. Tokens live in `apps/web/src/styles/base.css`. Write
interface text in plain words a non-technical member can read.

## Repository workflow

- Use focused branches and pull requests. Preserve unrelated changes.
- Keep README capability claims aligned with running code; distinguish demo,
  implemented, experimentally supported, and planned functionality.
- Do not commit credentials, live telemetry, personal browsing history, .env files,
  generated databases or session tokens. Use fabricated fixtures.
- Changes to authentication, member visibility, expiry or provider requests need
  meaningful tests covering denial paths.
- Run `python -m pytest services/api/tests`, `npm --prefix apps/web test`, and
  `npm --prefix apps/web run build` for relevant changes. Container changes also
  require the Docker smoke workflow. Report any checks you cannot execute.

## Product boundaries

- Connector collection is GET-only. Provider changes exist only in
  `nyctr/integrations/actions.py`, refuse to run unless the provider is named in
  `NYCTR_PROVIDER_WRITES`, and read back what they changed. Do not add a provider
  write anywhere else, and do not add a new kind of write while implementing an
  unrelated feature.
- Nyctr acts on its own only under an administrator-written rule in
  `nyctr/policy.py`. A risk score alone never opens access, and nothing a model
  returns can trigger a change, edit a rule or cut a device off.
- Record what happened at the provider (`simulated`, `applied`, `not_applied`,
  `failed`) separately from the decision. Never display a decision as restored or
  removed connectivity unless it was applied.
- AI has no infrastructure credentials and cannot authorize its own changes. It
  sees only the redacted evidence pack built in `nyctr/assistant.py`; citations
  to anything outside the pack are removed before the answer is returned.
- Unknown risk is unknown, never an invented low score. Missing logs do not
  prove a successful connection.
- Physical topology, configured policy, inferred reachability and observed
  traffic are distinct evidence types.
- Members must pass API authorization against event-time identity and current
  device access. A network address or DNS profile alone is not user identity.
- Expiring an inbox observation must not delete an existing request or its audit
  history. Revalidate freshness before starting a new request or execution.
- Temporary access uses owned durable leases, explicit scope, verification and
  reconciliation after failure or restart. Ending a lease must never remove a
  provider entry Nyctr did not create.
- Links between sources (same hardware address, VLAN tag or address) are computed
  at read time and always labelled inferred. Never store them as provider fact.
- Never describe Site Manager or the Carrier/ISP Fabric API as full coverage of
  organizational Fabric Blueprint/Canvas policies without confirming support.

## Source and dependencies

Use documented provider APIs and pin reproducible dependency inputs. Keep
integrations independent of the database and HTTP app. Consult official docs
when a provider or framework contract is uncertain. Do not bundle upstream API
keys or claim support based only on a UI mockup.
