"""Explicit operational settings; no secrets are returned by API serializers."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _browser_origin(name: str, parsed) -> str:
    """Write an origin the way a browser sends it, so the origin check cannot fail for a correct request.

    Browsers lower-case the host and leave the scheme's default port out of the
    Origin header. An address configured as `https://Host:443` would never
    match, and every change would be refused. The sign-in redirect is built from
    the same normalised origin.
    """
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"{name} has an invalid port") from None
    host = (parsed.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == {"http": 80, "https": 443}.get(parsed.scheme):
        return f"{parsed.scheme}://{host}"
    return f"{parsed.scheme}://{host}:{port}"


class Settings(BaseSettings):
    """Operational configuration loaded from NYCTR_ environment variables.

    Secrets stay server-side; invalid configuration suppresses input values in errors.
    """
    model_config = SettingsConfigDict(env_prefix="NYCTR_", extra="ignore", hide_input_in_errors=True)

    mode: Literal["demo", "live"] = "live"
    database_url: str = "sqlite:///./nyctr.db"
    public_url: str = "http://localhost:8080"
    # Optional second origin for the member portal. Empty serves everything on public_url.
    portal_url: str = ""
    cookie_secure: bool | None = None
    local_login_enabled: bool = True
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    session_hours: int = 12
    block_retention_hours: int = 24
    static_dir: str = ""
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_admin_groups: str = ""
    oidc_allowed_groups: str = ""
    oidc_groups_claim: str = "groups"
    # Comma-separated integration ids Nyctr may change. Empty keeps every connector read-only.
    provider_writes: str = ""
    # Starting value for the collection schedule, in seconds, until an administrator saves one in the
    # Console. 0 leaves it to the product default (every 15 minutes in live mode).
    collect_interval_seconds: int = 0
    worker_enabled: bool = True
    # Optional OpenAI-compatible chat endpoint for the assistant. The key never leaves the server.
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    # Optional shared secret that lets a network console ask Nyctr to collect now (a webhook).
    nudge_token: str = ""

    @model_validator(mode="after")
    def validate_settings(self):
        """Normalize the public origin and reject unsafe or incomplete configuration.

        Raises ValueError for invalid lifetimes, non-HTTPS OIDC issuers, partial OIDC
        credentials, or combining demo data with live identity-provider access.
        """
        self.public_url = self.public_url.rstrip("/")
        parsed = urlsplit(self.public_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path:
            raise ValueError("NYCTR_PUBLIC_URL must be an HTTP(S) origin without a path")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("NYCTR_PUBLIC_URL must be a plain HTTP(S) origin")
        self.public_url = _browser_origin("NYCTR_PUBLIC_URL", parsed)
        if self.portal_url:
            self.portal_url = self.portal_url.rstrip("/")
            portal = urlsplit(self.portal_url)
            if portal.scheme not in ("http", "https") or not portal.netloc or portal.path:
                raise ValueError("NYCTR_PORTAL_URL must be an HTTP(S) origin without a path")
            if portal.username or portal.password or portal.query or portal.fragment:
                raise ValueError("NYCTR_PORTAL_URL must be a plain HTTP(S) origin")
            self.portal_url = _browser_origin("NYCTR_PORTAL_URL", portal)
            if portal.scheme != parsed.scheme:
                raise ValueError("NYCTR_PORTAL_URL must use the same scheme as NYCTR_PUBLIC_URL")
            # Hostnames, not host:port. A browser shares cookies between ports of one
            # host, so two ports of the same name would share a session.
            if (portal.hostname or "").lower() == (parsed.hostname or "").lower():
                raise ValueError("NYCTR_PORTAL_URL must be a different hostname from NYCTR_PUBLIC_URL; "
                                 "leave it empty to serve the portal on the console address")
        if self.cookie_secure is None:
            self.cookie_secure = self.mode == "live"
        if not 1 <= self.session_hours <= 24:
            raise ValueError("Session lifetime must be between 1 and 24 hours")
        if not 1 <= self.block_retention_hours <= 168:
            raise ValueError("Block retention must be between 1 and 168 hours")
        oidc_fields = (self.oidc_issuer, self.oidc_client_id, self.oidc_client_secret)
        if any(oidc_fields) and not all(oidc_fields):
            raise ValueError("OIDC issuer, client ID, and client secret must be configured together")
        if self.oidc_issuer:
            issuer = urlsplit(self.oidc_issuer)
            if issuer.scheme != "https" or not issuer.netloc or issuer.username or issuer.password:
                raise ValueError("OIDC issuer must use HTTPS")
            if issuer.query or issuer.fragment:
                raise ValueError("OIDC issuer cannot contain query or fragment")
        from .integrations import registry

        if self.writable_providers - registry.writable():
            raise ValueError("NYCTR_PROVIDER_WRITES accepts only integrations that can change their source: "
                             + ", ".join(sorted(registry.writable())))
        if self.collect_interval_seconds and not 60 <= self.collect_interval_seconds <= 86400:
            raise ValueError("Automatic collection interval must be 0 or between 60 and 86400 seconds")
        if self.nudge_token and len(self.nudge_token) < 32:
            raise ValueError("The collection nudge token must be at least 32 characters")
        if bool(self.ai_base_url) != bool(self.ai_model):
            raise ValueError("Assistant base URL and model must be configured together")
        if self.ai_base_url:
            self.ai_base_url = self.ai_base_url.rstrip("/")
            endpoint = urlsplit(self.ai_base_url)
            if endpoint.scheme not in ("http", "https") or not endpoint.netloc or endpoint.username \
                    or endpoint.password or endpoint.query or endpoint.fragment:
                raise ValueError("Assistant base URL must be a plain HTTP(S) URL")
        if self.mode == "demo" and self.oidc_issuer:
            raise ValueError("OIDC is disabled in demo mode; use a separate live database")
        return self

    @property
    def oidc_enabled(self) -> bool:
        """Report whether a complete OIDC configuration passed settings validation."""
        return bool(self.oidc_issuer)

    @property
    def writable_providers(self) -> set[str]:
        """Return the providers an operator explicitly allowed Nyctr to change."""
        return {x.strip() for x in self.provider_writes.split(",") if x.strip()}

    def write_mode(self, provider: str) -> str:
        """Say how a change to this provider is carried out: simulated, enabled or disabled."""
        if self.mode == "demo":
            return "simulated"
        return "enabled" if provider in self.writable_providers else "disabled"

    @property
    def ai_enabled(self) -> bool:
        """Report whether a model endpoint was configured for the assistant."""
        return bool(self.ai_base_url and self.ai_model)

    @property
    def admin_groups(self) -> set[str]:
        """Return exact configured identity-provider group names that grant administration."""
        return {x.strip() for x in self.oidc_admin_groups.split(",") if x.strip()}

    @property
    def allowed_groups(self) -> set[str]:
        """Return the optional sign-in group allowlist; an empty set adds no group restriction."""
        return {x.strip() for x in self.oidc_allowed_groups.split(",") if x.strip()}
