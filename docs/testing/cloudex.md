# Independent Docker acceptance testing

This is the test assignment for Cloudex or another independent tester with its
own computer. It requires no access to the maintainer's network. All provider
activity uses synthetic fixtures inside an isolated Docker network. Do not
configure real UniFi, NextDNS, identity-provider, or infrastructure credentials
for this assignment.

## Objective and evidence

Test the packaged application from a fresh checkout of the pull request's exact
commit. Record that SHA before starting and keep it unchanged throughout the
report. A successful build is only one check: inspect the browser behavior,
authorization outcomes, diagnostics, and persistence as well.

Use **PASS**, **FAIL**, **BLOCKED**, or **NOT RUN** for each scenario. If this
computer has no working Docker daemon or browser, record the limitation; do not
substitute a successful unit test for a container or browser result. Return the
report and reproduction steps to the project owner. This assignment does not
include merging, releasing, production deployment, or changes to network rules.

## 1. Prerequisites and checkout

Required: Git, Docker with Compose, Python 3.12+, and a browser. AMD64 and ARM64
are both test targets; record which one this computer actually uses.

```sh
git clone https://github.com/homelab-0/nyctr.git
cd nyctr
git fetch origin feat/deployable-alpha
git switch --detach <exact-PR-commit>
git rev-parse HEAD
docker version
docker compose version
python3 --version
```

Replace `<exact-PR-commit>` with the supplied immutable SHA. After this PR is
merged, the same procedure can target its merged commit or a released version.
Use an isolated checkout; preserve any unrelated work on this computer.

## 2. Fresh demo installation

Use a dedicated Compose project and an unused loopback port:

```sh
export NYCTR_PORT=18080
docker compose -p nyctr-cloudex-demo up --build --wait -d
NYCTR_SMOKE_URL=http://127.0.0.1:18080 \
NYCTR_SMOKE_ORIGIN=http://localhost:18080 \
NYCTR_SMOKE_STATE=/tmp/nyctr-cloudex-demo-state.json \
python3 scripts/smoke.py
```

Open `http://localhost:18080`. Synthetic accounts:

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@nyctr.demo` | `nyctr-demo` |
| Member | `jamie@nyctr.demo` | `nyctr-demo` |

### Browser scenarios

| Scenario | Expected result |
| --- | --- |
| Fresh sign-in | Branded application loads; the role's navigation appears; no blank screen or console exception |
| Administrator overview | Inventory, graph, finding context, integrations, requests, and audit views work with explicitly synthetic data |
| Graph navigation | Pan, zoom, select, drill down, and return; dragging does not select the page's text or lose the selected resource |
| Finding path | The focused graph and resource inspector retain source/evidence context |
| Member isolation | Member sees assigned devices and eligible recent blocks; administrator pages/API calls remain forbidden |
| Request submission | Enter a reason, submit an eligible event, and see one durable pending request |
| Administrator review | Review or deny the request; the UI does not claim network access was granted |
| Demo connectors | Live setup, diagnostics, and collection remain disabled with an explanation |
| Sign-out | The signed-in shell and local session disappear; protected data cannot be loaded without signing in again |
| Narrow viewport | At approximately 390px width, navigation, forms, tables, and dialogs remain usable without hiding the primary controls |

Use separate browser profiles or sign out between identities. Capture screenshots
of failures and the diagnostic report, including enough surrounding UI to identify
the screen. Record reproducible steps, expected behavior, actual behavior, and
relevant console errors. All visible data in this assignment is fabricated.
The smoke script already creates one pending member request. Use another eligible
block for a new browser submission, and review the existing request as an
administrator. An existing request should not be duplicated accidentally.

### Restart persistence

```sh
docker compose -p nyctr-cloudex-demo restart nyctr
NYCTR_SMOKE_URL=http://127.0.0.1:18080 \
NYCTR_SMOKE_ORIGIN=http://localhost:18080 \
NYCTR_SMOKE_STATE=/tmp/nyctr-cloudex-demo-state.json \
python3 scripts/smoke.py --verify-persistence
```

Sign in again and confirm the earlier request and review remain. The restart
must not recreate a database or duplicate the request.

## 3. Isolated provider acceptance stack

This second stack exercises the application's **live-mode code paths against
local fake providers**. The application mode is not a claim of production testing.
The stack has its own database, synthetic bootstrap account, ephemeral test CA,
and internal Docker network. Its HTTPS fixtures model UniFi and NextDNS reads;
certificate verification stays enabled for connector traffic.
The browser reaches the application through a loopback-only proxy with a fixed
Nyctr upstream. Nyctr, PostgreSQL, and the provider fixture remain on the internal
network; the proxy supplies browser access without giving those services an
external route.

```sh
docker compose -p nyctr-cloudex-acceptance \
  -f tests/acceptance/compose.yaml up --build --wait -d
python3 tests/acceptance/check.py
```

Open `http://localhost:8091` and sign in with
`tester@nyctr.test` / `nyctr-acceptance-only`. See the
[fixture README](../../tests/acceptance/README.md) for configurable ports and
synthetic connection details.

Check the Integrations screen after the scripted checks have created the saved
fixture connections:

- Successful diagnostics show which reads were verified, the examined counts,
  and the remaining evidence gaps. They do not import a new snapshot themselves.
- Rejected fixture credentials produce an authentication failure and useful
  guidance, without displaying a credential or raw provider response.
- A hostname that does not match the fixture certificate produces a TLS failure.
  Do not disable verification to make this case pass.
- The disabled-logging NextDNS profile reports logging unavailable. Zero events
  must not become a statement that no blocks happened.
- NextDNS blocks remain unattributed and administrator-only. The fixture's
  device label is not an authenticated user identity.
- Collecting a snapshot is a separate, explicit action that populates the graph
  and inventory with the fixture's fabricated resources.
- Rerun and close the diagnostics dialog during a request; old results must not
  reappear after the dialog closes. Check scrolling and keyboard access on both
  desktop and narrow viewports.

Then verify persistence without rebuilding or collecting again:

```sh
docker compose -p nyctr-cloudex-acceptance \
  -f tests/acceptance/compose.yaml restart nyctr
python3 tests/acceptance/check.py --verify-persistence
```

## 4. Boundaries of this report

The fixture suite validates Nyctr's behavior, transport verification, UI, and
persistence against controlled local inputs. It does not certify compatibility
with every vendor release or configuration. Real Authentik interoperability,
homelab routing, live device attribution, and production network policies are
outside this assignment. OIDC protocol cases have automated backend coverage;
do not report a real identity-provider integration as tested because those unit
tests pass.

No AI risk engine or provider write executor exists in this version. Unknown
risk, internal review decisions, and unassigned observations should stay honest
in the UI. Treat any display suggesting an actual unblock as a failure.

## Report template

```text
Nyctr acceptance report
Commit:
OS / architecture:
Docker / Compose / browser versions:
Test date:

Fresh demo installation: PASS | FAIL | BLOCKED | NOT RUN
Packaged HTTP smoke: ...
Administrator browser workflow: ...
Member isolation and request workflow: ...
Graph navigation and finding context: ...
Desktop / narrow-viewport dialogs: ...
Demo restart persistence: ...
Isolated provider checks: ...
TLS / credential / disabled-logging failures: ...
Fixture restart persistence: ...

For each failure:
- Steps to reproduce:
- Expected / actual:
- Screenshot or sanitized error:
- Whether it reproduces after a fresh login:

Unexecuted scenarios and blockers:
```

## Cleanup

Keep the stacks running while reviewing screenshots or reproducing a finding.
These commands delete only the dedicated test projects and their synthetic data:

```sh
docker compose -p nyctr-cloudex-demo down --volumes
docker compose -p nyctr-cloudex-acceptance \
  -f tests/acceptance/compose.yaml down --volumes
```

Do not use broad Docker cleanup commands or remove unrelated containers/volumes.
