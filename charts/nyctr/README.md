# Nyctr Helm chart

This chart packages the self-hosted alpha as **one application replica** with an
external PostgreSQL database. It creates a hardened Deployment, ClusterIP
Service, ServiceAccount without an API token, and an optional ingress
NetworkPolicy. It can also create either an Ingress or a Gateway API HTTPRoute.
TLS termination, PostgreSQL, identity-provider setup, credentials, and Gateway
infrastructure remain separately managed.

The chart does not install a database operator, separate worker, AI service or
model gateway. A default installation is read-only, collects only on request and
has the assistant off; [three explicit settings](#what-nyctr-may-change-and-do-on-its-own)
change that. Validation covers offline rendering and isolated test fixtures; it
does not establish compatibility with a private homelab, real gateway, or real
IdP.

## Requirements and image selection

- Kubernetes 1.28 or later. Gateway routing additionally needs Gateway API 1.2+
  standard CRDs and a controller supporting HTTPRoute request timeouts.
- Helm. Rendering is tested with Helm 3.22.1 and 4.3.1.
- An image you have actually built or obtained from the project's release
  workflow. `ghcr.io/homelab-0/nyctr` is the default repository, **not a claim that
  a particular tag has been published**. Set exactly one explicit `image.tag` or
  `image.digest`; there is no implicit tag and `latest` is rejected. A digest is
  preferable for a reproducible deployment.
- A dedicated, writable PostgreSQL database for live mode. Read-only describes
  provider access; Nyctr still writes its own sessions, evidence, and audit data.

Default values intentionally fail validation until the image and live deployment
settings are explicit. The alpha stays at one replica and uses `Recreate`, so an
upgrade can interrupt service. Horizontal scaling and zero-downtime migration
are not supported by this chart.

## Existing Secrets

Provision Secrets in the **same namespace** using your existing secret manager,
External Secrets, SOPS workflow, or another appropriate mechanism. This chart
does not create Secret objects, generate passwords, or accept inline credentials.

| Purpose | Values | Expected Secret content |
| --- | --- | --- |
| PostgreSQL | `database.existingSecret`, `database.urlKey` | A complete `postgresql+psycopg://…` connection URL |
| Optional local bootstrap | `auth.local.bootstrap.existingSecret`, `emailKey`, `passwordKey` | Administrator email and a password of at least 12 characters |
| OIDC | `auth.oidc.existingSecret`, `clientSecretKey` | Confidential application client secret |
| Provider credential | Each `connectors.secrets` entry | API key selected by that entry's `key` |
| Private console trust | `connectors.caBundle.existingSecret`, `key` | Combined PEM bundle containing private CA and required public roots |

Configure database authentication and TLS at PostgreSQL and in the connection
URL. Helm cannot inspect Secret contents or establish connectivity. Missing
Secrets/keys prevent the pod from starting; invalid database/authentication
configuration is rejected by the application. Use separate databases for live
and demo mode, and preserve the external database when upgrading or uninstalling.

## Live configuration with Authentik and Envoy Gateway

The following is a **shape to adapt**, with fictional domains, proxy IPs, labels,
and Secret names. Replace the image tag with a built/published tag. Confirm the
actual Envoy peer addresses and pod labels in your cluster; this example does not
discover them.

```yaml
image:
  tag: sha-REPLACE_WITH_PUBLISHED_COMMIT
publicUrl: https://nyctr.example.org
forwardedAllowIps:
  - 10.42.0.10
database:
  existingSecret: nyctr-database
  urlKey: database-url
auth:
  local:
    enabled: false
  oidc:
    enabled: true
    issuer: https://auth.example.org/application/o/nyctr/
    clientId: nyctr
    existingSecret: nyctr-oidc
    adminGroups: [nyctr-admins]
    allowedGroups: [nyctr-members]
httpRoute:
  enabled: true
  parentRefs:
    - name: internal
      namespace: networking
      sectionName: https
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: envoy-gateway-system
      podSelector:
        matchLabels:
          app.kubernetes.io/name: envoy
```

Set the IdP's exact issuer URL, including a trailing slash if it has one. The
redirect URI is `https://nyctr.example.org/api/auth/oidc/callback`. Configure the
IdP to include the trusted groups as a list in the **signed ID token**; a claim
present only in userinfo is not sufficient. `auth.oidc.groupsClaim` defaults to
`groups`. Empty `allowedGroups` permits any valid identity from that issuer, so
use an explicit list for a restricted workspace. Configured administrator groups
are also allowed to sign in.

The Gateway must already have an HTTPS listener and its certificate. Its
`allowedRoutes` must permit routes from Nyctr's namespace. The chart's required
`sectionName` selects a listener but cannot prove that the referenced listener
uses HTTPS. Verify the route's `Accepted`/`ResolvedRefs` conditions and the actual
TLS connection. The HTTPRoute hostname is derived from `publicUrl`; its default
100-second request timeout accommodates the current bounded collection request.
See the [Gateway API HTTPRoute reference](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/).

For a traditional Ingress, disable HTTPRoute and configure:

```yaml
ingress:
  enabled: true
  className: your-ingress-class
  tlsSecretName: nyctr-tls
```

Both routing options are mutually exclusive. The Ingress hostname also comes
from `publicUrl`. Configure HTTPS redirect and a request timeout of at least
100 seconds in your ingress controller. If you already manage routing outside
the chart, leave both disabled and target the ClusterIP Service.

### Proxy identity and network restrictions

Live mode requires `forwardedAllowIps`: exact IPv4/IPv6 addresses of trusted
proxy peers **as seen by the application**. The chart rejects wildcard trust,
CIDRs, and hostnames. The public edge must replace untrusted client-supplied
forwarding headers; subsequent trusted hops must maintain a verified chain.
Uvicorn uses these addresses to determine whether `X-Forwarded-For` and
`X-Forwarded-Proto` are trustworthy. A missing/untrusted proxy collapses users
onto the same peer login quota; overbroad trust enables spoofing. See the
[deployment proxy guidance](../../deploy/README.md#trusted-reverse-proxies-and-login-limits).

IP lists must be updated when proxy peer addresses change. Do not trust a NAT or
bridge address unless network controls guarantee that connections through it
come only from the intended proxies. Use the chart's NetworkPolicy or equivalent
existing controls to restrict direct access. The default policy is ingress-only,
and live mode requires explicit allowed peers when it is enabled. Your CNI must
enforce NetworkPolicy. The chart does **not** restrict egress; configure separate
egress rules for DNS, PostgreSQL, the IdP, and intended providers as appropriate.

### Optional local bootstrap and provider configuration

Instead of OIDC, enable local authentication and reference a bootstrap Secret:

```yaml
auth:
  local:
    enabled: true
    bootstrap:
      existingSecret: nyctr-bootstrap
```

After the administrator exists, remove the bootstrap Secret reference and set
`auth.local.existingAccount: true`. This explicitly acknowledges an already
provisioned database; it does not create an account or rotate its password.
The chart requires an administrator path: local bootstrap/existing account or
nonempty OIDC administrator groups.

Optional provider configuration is injected through Secret references:

```yaml
connectors:
  hosts: [console.example.internal]
  secrets:
    - envName: NYCTR_CONNECTOR_SECRET_UNIFI
      existingSecret: nyctr-unifi
      key: api-key
    - envName: NYCTR_CONNECTOR_SECRET_NEXTDNS
      existingSecret: nyctr-nextdns
      key: api-key
  caBundle:
    existingSecret: nyctr-connector-ca
    key: combined.pem
```

UniFi destinations require the explicit hostname allowlist. NextDNS uses its
fixed official origin. The mounted CA bundle **replaces** default trust roots
for both integration clients: include the required public roots along with the
private console CA. A private-only bundle can break NextDNS TLS verification.
It does not configure OIDC, PostgreSQL, or browser certificate trust. A provider
key alone never lets Nyctr change that provider; see the next section. Proxmox
and Pi-hole destinations also need their hostname in `connectors.hosts` and
their own `NYCTR_CONNECTOR_SECRET_*` entry.

### What Nyctr may change and do on its own

All of this is off by default. Demo mode rejects every setting in this section.

```yaml
# Integrations Nyctr may change. Only integrations that can change their source
# are accepted (today nextdns and unifi_network); the pod refuses to start on
# any other name.
providerWrites: [nextdns]

collection:
  # 60 to 86400. Without an interval the guest cut-off rule and lock-out act
  # only when an administrator presses Collect.
  intervalSeconds: 300
  nudge:
    # Optional. A Secret holding a token of 32 or more characters lets a network
    # console call /api/hooks/collect to ask for a collection now.
    existingSecret: nyctr-nudge

assistant:
  # Any OpenAI-compatible endpoint. Set both or neither.
  baseUrl: http://model-gateway.ai.svc.cluster.local:4000/v1
  model: local/reasoner
  # Optional, when the endpoint needs a key.
  existingSecret: nyctr-model
```

Turn changes on one integration at a time, after a read-only collection from it
looks right. With `providerWrites` set, Nyctr acts only on an administrator's
approval or written rule, and only in the ways listed in the
[security model](../../docs/security-model.md). The assistant receives a bounded,
redacted evidence pack and has no credentials; a plain-HTTP endpoint is accepted
for an in-cluster gateway, so keep that traffic inside the cluster. The chart
adds no egress rules: allow the pod to reach each provider and the model
endpoint yourself.

Environment-backed secret rotations require an application restart; changing
an existing Secret alone does not cause Helm to roll the Deployment. After
updating a Secret through your normal workflow, restart the Deployment or use a
separately managed restart controller. CA contents are mounted read-only; restart
as part of a coordinated trust rotation to avoid inconsistent in-flight requests.

## Helm and Flux usage

From a repository checkout, render your nonsecret values for review first:

```sh
helm lint ./charts/nyctr -f nyctr-values.yaml --strict
helm template nyctr ./charts/nyctr -n nyctr -f nyctr-values.yaml
helm upgrade --install nyctr ./charts/nyctr -n nyctr --create-namespace \
  -f nyctr-values.yaml --wait --timeout 5m
```

For Flux, reference the chart path in an existing Git source and put the same
nonsecret values in the HelmRelease. An outline is:

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: nyctr
  namespace: nyctr
spec:
  interval: 10m
  chart:
    spec:
      chart: ./charts/nyctr
      reconcileStrategy: Revision
      sourceRef:
        kind: GitRepository
        name: nyctr
        namespace: flux-system
  values:
    # Insert the complete reviewed nonsecret configuration from above.
    image:
      tag: sha-REPLACE_WITH_PUBLISHED_COMMIT
```

This outline is intentionally incomplete until actual dependencies and values
are supplied. Ensure the namespace, database, and referenced Secrets exist before
reconciliation. The chart does not change Talos configuration or need privileged
pods, host paths, a container-runtime socket, or Kubernetes API credentials.
See the [Flux HelmRelease reference](https://fluxcd.io/flux/components/helm/helmreleases/).

## Isolated demos and verification

Known synthetic accounts require both `mode: demo` and
`demo.allowKnownCredentials: true`. Demo mode refuses Ingress/HTTPRoute, public
origins, proxy trust, OIDC, and live provider credentials. Use a dedicated
namespace/cluster and loopback-only port forwarding; ClusterIP is not an
authorization boundary against other workloads in the cluster.

`ci/demo-postgres-values.yaml` is for the isolated kind CI workflow. It expects
a locally loaded `nyctr:ci-smoke` image and an independently created **synthetic**
`nyctr-db` Secret with key `database-url`. `ci/demo-ephemeral-values.yaml` selects
a disposable SQLite emptyDir instead. That data disappears when the pod is
replaced; it is never accepted for live mode. Neither file selects a published
image or contains credentials. Keep PostgreSQL persistence validation in the
external-database test, not the disposable demo.

From the repository checkout, using the API development dependencies:

```sh
HELM_BIN=/path/to/verified/helm \
  services/api/.venv/bin/python -m pytest tests/deployment -q
helm lint ./charts/nyctr -f charts/nyctr/ci/live-values.yaml --strict
```

The offline tests render real manifests and reject conflicting routes, missing
secrets/authentication configuration, unsafe forwarding trust, inline credentials,
extra replicas, invalid image selection, and exposed demos. Container/kind tests
exercise synthetic data only. TLS routing, actual proxy identity, real provider
responses, IdP configuration, backup recovery, and upgrades require validation in
the intended environment before relying on the deployment.
