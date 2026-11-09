"""Explicit operational settings; no secrets are returned by API serializers."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NYCTR_", extra="ignore", hide_input_in_errors=True)

    mode: Literal["demo", "live"] = "live"
    database_url: str = "sqlite:///./nyctr.db"
    public_url: str = "http://localhost:8080"
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

    @model_validator(mode="after")
    def validate_settings(self):
        self.public_url = self.public_url.rstrip("/")
        parsed = urlsplit(self.public_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path:
            raise ValueError("NYCTR_PUBLIC_URL must be an HTTP(S) origin without a path")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("NYCTR_PUBLIC_URL must be a plain HTTP(S) origin")
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
        if self.mode == "demo" and self.oidc_issuer:
            raise ValueError("OIDC is disabled in demo mode; use a separate live database")
        return self

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    @property
    def admin_groups(self) -> set[str]:
        return {x.strip() for x in self.oidc_admin_groups.split(",") if x.strip()}

    @property
    def allowed_groups(self) -> set[str]:
        return {x.strip() for x in self.oidc_allowed_groups.split(",") if x.strip()}
