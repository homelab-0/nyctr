"""Render the real chart offline and enforce its deployment/security boundaries."""

import ast
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "nyctr"


def test_chart_app_version_matches_api_runtime_and_web_release():
    """Prevent deployment labels from drifting from the actual application release version."""
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    web = json.loads((ROOT / "apps/web/package.json").read_text())
    module = ast.parse((ROOT / "services/api/nyctr/__init__.py").read_text())
    versions = [node.value.value for node in module.body
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    assert len(versions) == 1 and isinstance(versions[0], str), "API version must be one static string"
    assert chart["appVersion"] == web["version"] == versions[0]


@pytest.fixture(scope="session")
def helm_binary():
    """Require a real Helm executable; absence must not silently skip chart checks."""
    binary = os.environ.get("HELM_BIN") or shutil.which("helm")
    if not binary or not Path(binary).is_file():
        pytest.fail("Install Helm or set HELM_BIN to its verified executable path.")
    return binary


def merge(base, changes):
    """Apply values overrides recursively while replacing lists exactly as Helm does."""
    result = copy.deepcopy(base)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def fixture(name):
    """Load synthetic chart values that reference no real image, cluster or secret."""
    return yaml.safe_load((CHART / "ci" / name).read_text())


def run_helm(helm_binary, tmp_path, values, command="template"):
    """Invoke Helm without cluster access, plugins, or the operator's local configuration."""
    values_path = tmp_path / "values.yaml"
    values_path.write_text(yaml.safe_dump(values))
    env = {**os.environ, "KUBECONFIG": os.devnull, "HELM_PLUGINS": str(tmp_path / "plugins"),
           "HELM_CONFIG_HOME": str(tmp_path / "config"), "HELM_CACHE_HOME": str(tmp_path / "cache"),
           "HELM_DATA_HOME": str(tmp_path / "data")}
    args = [helm_binary, command]
    if command == "template":
        args += ["nyctr", str(CHART), "--namespace", "nyctr-tests", "--kube-version", "1.35.0"]
    else:
        args += [str(CHART), "--strict"]
    return subprocess.run([*args, "-f", str(values_path)], env=env, capture_output=True,
                          text=True, timeout=30, check=False)


def render(helm_binary, tmp_path, values):
    """Parse successful manifests, retaining Helm stderr if rendering fails."""
    result = run_helm(helm_binary, tmp_path, values)
    assert result.returncode == 0, result.stderr + result.stdout
    return {row["kind"]: row for row in yaml.safe_load_all(result.stdout) if row}


def container(manifests):
    """Return the only application container and reject accidental sidecars."""
    containers = manifests["Deployment"]["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    return containers[0]


def environment(manifests):
    """Index actual rendered environment entries and reject duplicate names."""
    items = container(manifests)["env"]
    assert len({row["name"] for row in items}) == len(items)
    return {row["name"]: row for row in items}


@pytest.mark.parametrize("values_file", ["live-values.yaml", "demo-postgres-values.yaml",
                                         "demo-ephemeral-values.yaml"])
def test_supported_profiles_pass_strict_helm_lint(helm_binary, tmp_path, values_file):
    """Lint every shipped example with the same schema and templates used at install."""
    result = run_helm(helm_binary, tmp_path, fixture(values_file), command="lint")
    assert result.returncode == 0, result.stderr + result.stdout


def test_live_workload_is_single_process_and_hardened(helm_binary, tmp_path):
    """Require restricted pod settings, probes, bounded resources, and no ambient API access."""
    manifests = render(helm_binary, tmp_path, fixture("live-values.yaml"))
    assert set(manifests) == {"Deployment", "Service", "ServiceAccount", "NetworkPolicy"}
    deployment = manifests["Deployment"]
    spec = deployment["spec"]
    pod = spec["template"]["spec"]
    app = container(manifests)
    assert deployment["metadata"]["name"] == manifests["Service"]["metadata"]["name"] == "nyctr"
    assert spec["replicas"] == 1 and spec["strategy"] == {"type": "Recreate"}
    assert pod["automountServiceAccountToken"] is False
    assert manifests["ServiceAccount"]["automountServiceAccountToken"] is False
    assert pod["serviceAccountName"] == "nyctr"
    assert pod["securityContext"] == {
        "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
        "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert app["securityContext"] == {
        "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    assert app["readinessProbe"]["httpGet"]["path"] == "/api/health"
    assert app["startupProbe"]["httpGet"]["path"] == "/api/health"
    assert app["livenessProbe"]["httpGet"]["path"] == "/api/auth/config"
    assert app["resources"]["requests"] and app["resources"]["limits"]
    assert app["volumeMounts"] == [{"name": "tmp", "mountPath": "/tmp"}]
    assert not pod.get("hostNetwork") and not pod.get("hostPID") and not pod.get("hostIPC")
    assert manifests["Service"]["spec"]["type"] == "ClusterIP"
    labels = spec["selector"]["matchLabels"]
    assert labels == spec["template"]["metadata"]["labels"] == manifests["Service"]["spec"]["selector"]
    policy = manifests["NetworkPolicy"]["spec"]
    assert policy["podSelector"]["matchLabels"] == labels
    assert policy["policyTypes"] == ["Ingress"] and policy["ingress"][0]["ports"][0]["port"] == 8080


def test_live_secrets_are_references_and_ca_mount_preserves_read_only_boundary(helm_binary, tmp_path):
    """Pass only secret references for credentials and mount the combined CA without a private key."""
    values = merge(fixture("live-values.yaml"), {
        "image": {"tag": "", "digest": "sha256:" + "a" * 64},
        "connectors": {"hosts": ["console.example.test"], "secrets": [
            {"envName": "NYCTR_CONNECTOR_SECRET_UNIFI", "existingSecret": "nyctr-unifi", "key": "api-key"},
            {"envName": "NYCTR_CONNECTOR_SECRET_NEXTDNS", "existingSecret": "nyctr-nextdns", "key": "api-key"},
        ], "caBundle": {"existingSecret": "nyctr-ca", "key": "combined.pem"}},
    })
    manifests = render(helm_binary, tmp_path, values)
    env = environment(manifests)
    assert container(manifests)["image"] == "ghcr.io/homelab-0/nyctr@sha256:" + "a" * 64
    expected = {
        "NYCTR_DATABASE_URL": ("nyctr-db", "database-url"),
        "NYCTR_OIDC_CLIENT_SECRET": ("nyctr-oidc", "client-secret"),
        "NYCTR_CONNECTOR_SECRET_UNIFI": ("nyctr-unifi", "api-key"),
        "NYCTR_CONNECTOR_SECRET_NEXTDNS": ("nyctr-nextdns", "api-key"),
    }
    for variable, (name, key) in expected.items():
        assert env[variable] == {"name": variable, "valueFrom": {"secretKeyRef": {"name": name, "key": key}}}
    assert env["NYCTR_MODE"]["value"] == "live"
    assert env["NYCTR_COOKIE_SECURE"]["value"] == "true"
    assert env["FORWARDED_ALLOW_IPS"]["value"] == "10.42.0.10"
    assert env["NYCTR_CONNECTOR_HOSTS"]["value"] == "console.example.test"
    assert env["NYCTR_CONNECTOR_CA_BUNDLE"]["value"] == "/etc/nyctr/connector-ca/ca-bundle.crt"
    mount = next(row for row in container(manifests)["volumeMounts"] if row["name"] == "connector-ca")
    assert mount["readOnly"] is True
    volume = next(row for row in manifests["Deployment"]["spec"]["template"]["spec"]["volumes"]
                  if row["name"] == "connector-ca")
    assert volume["secret"] == {"secretName": "nyctr-ca", "defaultMode": 0o444,
                                "items": [{"key": "combined.pem", "path": "ca-bundle.crt"}]}
    assert "Secret" not in manifests and "envFrom" not in container(manifests)


def test_a_default_live_installation_is_read_only_with_the_assistant_off(helm_binary, tmp_path):
    """Nothing Nyctr can do on its own is on unless the operator asked for it."""
    env = environment(render(helm_binary, tmp_path, fixture("live-values.yaml")))
    assert env["NYCTR_PROVIDER_WRITES"] == {"name": "NYCTR_PROVIDER_WRITES", "value": ""}
    assert env["NYCTR_COLLECT_INTERVAL_SECONDS"]["value"] == "0"
    assert not any(name.startswith("NYCTR_AI_") or name == "NYCTR_NUDGE_TOKEN" for name in env)


def test_changes_collection_and_the_assistant_are_explicit_and_keep_credentials_in_secrets(helm_binary, tmp_path):
    """Write permission, the schedule and the model are plain values; every credential is a Secret reference."""
    values = merge(fixture("live-values.yaml"), {
        "providerWrites": ["nextdns", "unifi_network"],
        "collection": {"intervalSeconds": 300, "nudge": {"existingSecret": "nyctr-nudge"}},
        "assistant": {"baseUrl": "http://gateway.ai.svc.cluster.local:4000/v1", "model": "local/reasoner",
                      "existingSecret": "nyctr-model", "apiKeyKey": "key"},
    })
    manifests = render(helm_binary, tmp_path, values)
    env = environment(manifests)
    assert env["NYCTR_PROVIDER_WRITES"]["value"] == "nextdns,unifi_network"
    assert env["NYCTR_COLLECT_INTERVAL_SECONDS"]["value"] == "300"
    assert env["NYCTR_AI_BASE_URL"]["value"] == "http://gateway.ai.svc.cluster.local:4000/v1"
    assert env["NYCTR_AI_MODEL"]["value"] == "local/reasoner"
    assert env["NYCTR_NUDGE_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": "nyctr-nudge", "key": "nudge-token"}
    assert env["NYCTR_AI_API_KEY"]["valueFrom"]["secretKeyRef"] == {"name": "nyctr-model", "key": "key"}
    assert "Secret" not in manifests and "envFrom" not in container(manifests)
    # A model gateway that needs no key is supported: the endpoint is set and no key is passed.
    keyless = environment(render(helm_binary, tmp_path, merge(values, {"assistant": {"existingSecret": ""}})))
    assert keyless["NYCTR_AI_MODEL"]["value"] == "local/reasoner" and "NYCTR_AI_API_KEY" not in keyless


@pytest.mark.parametrize("trusted", [["10.42.0.0/16"], ["10.42.7.0/24", "10.42.0.10"], ["2001:db8:42::/56"]])
def test_a_bounded_proxy_range_is_accepted_only_behind_the_network_policy(helm_binary, tmp_path, trusted):
    """A range of proxy peers is trusted only while the chart's policy decides who can connect."""
    manifests = render(helm_binary, tmp_path, merge(fixture("live-values.yaml"), {"forwardedAllowIps": trusted}))
    assert environment(manifests)["FORWARDED_ALLOW_IPS"]["value"] == ",".join(trusted)
    policy = manifests["NetworkPolicy"]["spec"]
    assert policy["policyTypes"] == ["Ingress"] and policy["ingress"][0]["from"]


def test_local_bootstrap_uses_existing_secret_and_can_be_removed_after_provisioning(helm_binary, tmp_path):
    """Support initial local provisioning and an explicit existing-account upgrade without password resets."""
    values = merge(fixture("live-values.yaml"), {"auth": {
        "local": {"enabled": True, "bootstrap": {"existingSecret": "nyctr-bootstrap"}},
        "oidc": {"enabled": False, "issuer": "", "clientId": "", "existingSecret": "", "adminGroups": []},
    }})
    env = environment(render(helm_binary, tmp_path, values))
    for variable, key in [("NYCTR_BOOTSTRAP_ADMIN_EMAIL", "bootstrap-email"),
                          ("NYCTR_BOOTSTRAP_ADMIN_PASSWORD", "bootstrap-password")]:
        assert env[variable]["valueFrom"]["secretKeyRef"] == {"name": "nyctr-bootstrap", "key": key}
    updated = merge(values, {"auth": {"local": {"existingAccount": True, "bootstrap": {"existingSecret": ""}}}})
    env = environment(render(helm_binary, tmp_path, updated))
    assert "NYCTR_BOOTSTRAP_ADMIN_PASSWORD" not in env and "NYCTR_OIDC_CLIENT_SECRET" not in env


@pytest.mark.parametrize("external", [True, False])
def test_demo_keeps_known_credentials_isolated_and_database_choice_explicit(helm_binary, tmp_path, external):
    """Render external PostgreSQL or disposable SQLite without a public route or live secrets."""
    name = "demo-postgres-values.yaml" if external else "demo-ephemeral-values.yaml"
    manifests = render(helm_binary, tmp_path, fixture(name))
    assert set(manifests) == {"Deployment", "Service", "ServiceAccount"}
    env = environment(manifests)
    assert env["NYCTR_MODE"]["value"] == "demo" and env["NYCTR_COOKIE_SECURE"]["value"] == "false"
    assert env["FORWARDED_ALLOW_IPS"]["value"] == ""
    assert not any(key.startswith("NYCTR_CONNECTOR_SECRET_") for key in env)
    if external:
        assert env["NYCTR_DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"] == "nyctr-db"
    else:
        assert env["NYCTR_DATABASE_URL"]["value"] == "sqlite:////var/lib/nyctr/demo.db"
        assert {"name": "demo-data", "mountPath": "/var/lib/nyctr"} in container(manifests)["volumeMounts"]


@pytest.mark.parametrize("route", ["ingress", "httpRoute"])
def test_https_route_matches_origin_listener_and_service(helm_binary, tmp_path, route):
    """Derive the hostname once and point either supported proxy interface at the same Service."""
    changes = {"service": {"port": 8088}}
    if route == "ingress":
        changes[route] = {"enabled": True, "className": "nginx", "tlsSecretName": "nyctr-tls"}
    else:
        changes[route] = {"enabled": True, "parentRefs": [{"name": "shared", "namespace": "networking",
                                                          "sectionName": "https"}]}
    manifests = render(helm_binary, tmp_path, merge(fixture("live-values.yaml"), changes))
    if route == "ingress":
        spec = manifests["Ingress"]["spec"]
        assert "HTTPRoute" not in manifests
        assert spec["tls"] == [{"hosts": ["nyctr.example.test"], "secretName": "nyctr-tls"}]
        assert spec["rules"][0]["host"] == "nyctr.example.test"
        target = spec["rules"][0]["http"]["paths"][0]["backend"]["service"]
        assert target == {"name": "nyctr", "port": {"number": 8088}}
    else:
        spec = manifests["HTTPRoute"]["spec"]
        assert "Ingress" not in manifests
        assert manifests["HTTPRoute"]["apiVersion"] == "gateway.networking.k8s.io/v1"
        assert spec["parentRefs"] == changes[route]["parentRefs"]
        assert spec["hostnames"] == ["nyctr.example.test"]
        assert spec["rules"][0]["backendRefs"] == [{"name": "nyctr", "port": 8088}]
        assert spec["rules"][0]["timeouts"]["request"] == "100s"


@pytest.mark.parametrize("changes", [
    {"replicaCount": 2},
    {"publicUrl": "http://nyctr.example.test"},
    {"publicUrl": "https://user:password@nyctr.example.test"},
    {"publicUrl": "https://nyctr.example.test/path"},
    {"publicUrl": "https://nyctr.example.test:65536"},
    {"forwardedAllowIps": []},
    {"forwardedAllowIps": ["*"]},
    {"forwardedAllowIps": ["10.0.0.0/8"]},
    {"forwardedAllowIps": ["0.0.0.0/0"]},
    {"forwardedAllowIps": ["10.42.0.0/15"]},
    {"forwardedAllowIps": ["10.42.0.0/33"]},
    {"forwardedAllowIps": ["2001:db8::/32"]},
    {"forwardedAllowIps": ["10.42.0.0/16"], "networkPolicy": {"enabled": False}},
    {"forwardedAllowIps": ["10.42.0.0/16,10.43.0.0/16"]},
    {"forwardedAllowIps": ["not-an-ip"]},
    {"forwardedAllowIps": ["999.0.0.1"]},
    {"database": {"existingSecret": ""}},
    {"database": {"url": "postgresql://inline-credential@database/nyctr"}},
    {"auth": {"oidc": {"clientSecret": "inline-credential"}}},
    {"auth": {"oidc": {"issuer": "http://auth.example.test"}}},
    {"auth": {"oidc": {"existingSecret": ""}}},
    {"auth": {"oidc": {"adminGroups": []}}},
    {"auth": {"oidc": {"enabled": False}}},
    {"auth": {"local": {"bootstrap": {"existingSecret": "unused"}}}},
    {"image": {"tag": "latest"}},
    {"image": {"tag": ""}},
    {"image": {"digest": "sha256:" + "b" * 64}},
    {"image": {"tag": "", "digest": "sha256:short"}},
    {"ingress": {"enabled": True, "className": "nginx"}},
    {"httpRoute": {"enabled": True}},
    {"httpRoute": {"enabled": True, "parentRefs": [{"name": "gateway"}]}},
    {"ingress": {"enabled": True}, "httpRoute": {"enabled": True}},
    {"networkPolicy": {"ingressFrom": []}},
    {"networkPolicy": {"ingressFrom": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}},
    {"demo": {"ephemeralDatabase": True}},
    {"extraEnv": [{"name": "NYCTR_MODE", "value": "demo"}]},
    {"providerWrites": ["NextDNS"]},
    {"providerWrites": ["nextdns,unifi_network"]},
    {"providerWrites": ["nextdns", "nextdns"]},
    {"providerWrites": "nextdns"},
    {"collection": {"intervalSeconds": 30}},
    {"collection": {"intervalSeconds": 100000}},
    {"collection": {"nudge": {"token": "inline-credential-that-is-long-enough-000"}}},
    {"assistant": {"baseUrl": "http://gateway.ai.svc:4000/v1"}},
    {"assistant": {"model": "local/reasoner"}},
    {"assistant": {"existingSecret": "nyctr-model"}},
    {"assistant": {"baseUrl": "https://user:password@gateway.example.test/v1", "model": "m"}},
    {"assistant": {"baseUrl": "https://gateway.example.test/v1?key=inline", "model": "m"}},
    {"assistant": {"baseUrl": "https://gateway.example.test/v1", "model": "m", "apiKey": "inline-credential"}},
    {"podSecurityContext": {"runAsUser": 0}},
    {"connectors": {"secrets": [{"envName": "NYCTR_MODE", "existingSecret": "secret", "key": "mode"}]}},
    {"connectors": {"secrets": [
        {"envName": "NYCTR_CONNECTOR_SECRET_HOME", "existingSecret": "one", "key": "key"},
        {"envName": "NYCTR_CONNECTOR_SECRET_HOME", "existingSecret": "two", "key": "key"},
    ]}},
])
def test_invalid_or_unsafe_live_configuration_fails_before_rendering(helm_binary, tmp_path, changes):
    """Reject deployment mistakes that expose secrets, weaken isolation, or make live auth unusable."""
    result = run_helm(helm_binary, tmp_path, merge(fixture("live-values.yaml"), changes))
    assert result.returncode != 0, f"Unsafe values rendered successfully: {changes!r}"
    assert "kind: Deployment" not in result.stdout


@pytest.mark.parametrize("changes", [
    {"demo": {"allowKnownCredentials": False}},
    {"demo": {"ephemeralDatabase": True}},
    {"database": {"existingSecret": ""}},
    {"publicUrl": "https://nyctr.example.test"},
    {"forwardedAllowIps": ["127.0.0.1"]},
    {"ingress": {"enabled": True, "className": "nginx", "tlsSecretName": "tls"}},
    {"httpRoute": {"enabled": True, "parentRefs": [{"name": "gateway", "sectionName": "https"}]}},
    {"connectors": {"secrets": [{"envName": "NYCTR_CONNECTOR_SECRET_HOME", "existingSecret": "real", "key": "key"}]}},
    {"auth": {"oidc": {"enabled": True}}},
    {"providerWrites": ["nextdns"]},
    {"collection": {"intervalSeconds": 300}},
    {"collection": {"nudge": {"existingSecret": "nyctr-nudge"}}},
    {"assistant": {"baseUrl": "http://gateway.ai.svc:4000/v1", "model": "m"}},
])
def test_demo_cannot_be_accidentally_exposed_or_connected_to_live_providers(helm_binary, tmp_path, changes):
    """Keep known credentials on the explicit isolated path and require a single database choice."""
    result = run_helm(helm_binary, tmp_path, merge(fixture("demo-postgres-values.yaml"), changes))
    assert result.returncode != 0


def test_unconfigured_defaults_do_not_create_a_deployment_or_credentials(helm_binary, tmp_path):
    """Force an operator to select an image and configure live dependencies explicitly."""
    result = run_helm(helm_binary, tmp_path, {})
    assert result.returncode != 0
    assert "kind: Secret" not in result.stdout and "kind: Deployment" not in result.stdout
