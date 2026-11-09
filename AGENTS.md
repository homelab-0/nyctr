# Working on Nyctr

Read README.md, docs/architecture/overview.md, docs/security-model.md and
docs/roadmap.md before changing architectural behavior. Preserve the approved
charcoal/blue Nyctr UI.

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

- Connector collection is GET-only in this version. Do not introduce provider
  writes while implementing unrelated features.
- AI has no infrastructure credentials and cannot authorize its own changes.
- Unknown risk is unknown, never an invented low score. Missing logs do not
  prove a successful connection.
- Physical topology, configured policy, inferred reachability and observed
  traffic are distinct evidence types.
- Members must pass API authorization against event-time identity and current
  device access. A network address or DNS profile alone is not user identity.
- Expiring an inbox observation must not delete an existing request or its audit
  history. Revalidate freshness before starting a new request or execution.
- Future temporary access must use owned durable leases, explicit scope,
  verification and reconciliation after failure or restart.
- Never describe Site Manager or the Carrier/ISP Fabric API as full coverage of
  organizational Fabric Blueprint/Canvas policies without confirming support.

## Source and dependencies

Use documented provider APIs and pin reproducible dependency inputs. Keep
integrations independent of the database and HTTP app. Consult official docs
when a provider or framework contract is uncertain. Do not bundle upstream API
keys or claim support based only on a UI mockup.
