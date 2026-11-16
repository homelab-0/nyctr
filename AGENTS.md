# Working on Nyctr

Read README.md, docs/architecture/overview.md, docs/security-model.md and
docs/roadmap.md before changing architectural behavior. Preserve the Nyctr console
design: near-black ground, layered panels, one blue accent, Geist type. Colour
names the source (each integration declares its tone). A source's chip may show
that source's own logo on a neutral tile; colour still names the source on lines
and the Map. Line style names the
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

- Nyctr is vendor neutral. Core modules (`services/api/nyctr/*.py`) and the web
  app never name a vendor or branch on a provider id: a feature asks the registry
  whether a source offers a capability and calls what that integration declared.
  Vendor knowledge lives in `nyctr/integrations/<name>.py` (and the demo seed).
  `tests/test_registry.py` fails if a vendor name appears elsewhere. Read
  docs/integration-contract.md before adding or changing an integration, and
  write adapters to the neutral attribute names listed there.
- Connector collection is read only: GET requests, plus signing in and out of
  its own session where a source offers nothing else (Pi-hole). Provider changes exist only in
  `nyctr/integrations/actions.py`, refuse to run unless the provider is named in
  `NYCTR_PROVIDER_WRITES`, and read back what they changed (voucher create and
  delete do not yet; say so wherever verification is claimed). Do not add a provider
  write anywhere else, and do not add a new kind of write while implementing an
  unrelated feature.
- Nyctr acts on its own only under an administrator-written rule in
  `nyctr/policy.py`. A risk score alone never opens access. A model's Analysis
  may be one condition of the Administrator's Access rule, in the tiers the
  Administrator switched on; by itself it opens nothing. No model output edits
  a rule, cuts a device off, lengthens or widens access, or opens a deliberate
  Block.
- Record what happened at the provider (`simulated`, `applied`, `not_applied`,
  `failed`) separately from the decision. Never display a decision as restored or
  removed connectivity unless it was applied.
- AI has no infrastructure credentials and cannot authorize its own changes. It
  sees only the redacted evidence pack built in `nyctr/assistant.py`; citations
  to anything outside the pack are removed before the answer is returned.
- Every call to a model goes through `model.call` in `nyctr/model.py`. The
  model's key goes only where the operator's host list (`NYCTR_MODEL_HOSTS`) and
  secret names (`NYCTR_MODEL_SECRET_*`) allow. Trace field names live in one
  table in `nyctr/model.py`, and nothing branches on them.
- Unknown risk is unknown, never an invented low score. Missing logs do not
  prove a successful connection.
- Physical topology, configured policy, inferred reachability and observed
  traffic are distinct evidence types.
- Members must pass API authorization against event-time identity and current
  device access. A network address or DNS profile alone is not user identity.
  One stated exception: a sign-in tie (`nyctr/presence.py`) reaches back a set
  time before the first sign-in, two hours unless an administrator sets
  another, and assumes the person signing in was the one using the device in
  that time. It never reaches past the last time an administrator set whose
  the device is, nor, on a device that is not shared, past the end of another
  person's tie on it. Only `nyctr/deps.py` decides which device a member may
  see.
- Only `nyctr/peer.py` says which address a request came from: the peer, or
  behind a listed proxy the `X-Forwarded-For` entry that proxy wrote, counted
  from the right by `NYCTR_PROXY_HOPS`, with every entry to its right a listed
  proxy too. No other module reads the peer or a forwarded header, and a
  caller given no address must not fall back to one.
- Expiring an inbox observation must not delete an existing request or its audit
  history. Revalidate freshness before starting a new request or execution.
- Temporary access uses owned durable leases, explicit scope, verification and
  reconciliation after failure or restart. Ending a lease must never remove a
  provider entry Nyctr did not create.
- Guests sign in on the network source's own captive portal. Nyctr never serves a page to a
  device that has not signed in and must not be made an external portal server;
  see docs/guest-wifi.md. Do not add an unauthenticated API route without
  changing the guard test on purpose.
- Links between sources (same hardware address, VLAN tag or address) are computed
  at read time and always labelled inferred. Never store them as provider fact.
- Never describe Site Manager or the Carrier/ISP Fabric API as full coverage of
  organizational Fabric Blueprint/Canvas policies without confirming support.

## Source and dependencies

Use documented provider APIs and pin reproducible dependency inputs. Keep
integrations independent of the database and HTTP app. Consult official docs
when a provider or framework contract is uncertain. Do not bundle upstream API
keys or claim support based only on a UI mockup.
