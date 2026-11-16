"""Every object an actor produces is one of these, validated on the way in and out."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Ecosystem(str, Enum):
    npm = "npm"
    pypi = "pypi"
    cargo = "cargo"
    go = "go"
    maven = "maven"
    unknown = "unknown"


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(Base):
    kind: Literal["repo", "oauth_client", "cloud_bucket", "plugin"]
    name: str = Field(min_length=1)
    url: str | None = None
    org: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class Dependency(Base):
    name: str = Field(min_length=1)
    version: str = ""
    ecosystem: Ecosystem = Ecosystem.unknown
    source_file: str = ""
    scope: Literal["runtime", "dev", "build", "unknown"] = "unknown"


class CanaryCandidate(Base):
    """A package a repository imports but does not pin, and no registry serves."""
    name: str
    ecosystem: Ecosystem
    evidence: str
    installs_per_week: int = 0
    contested: bool = False


class Canary(Base):
    name: str
    ecosystem: Ecosystem
    version: str
    signature: str
    beacon_url: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("signature")
    @classmethod
    def hex_signature(cls, value: str) -> str:
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("signature must be 64 lowercase hex characters")
        return value


class BypassCase(Base):
    """One way an OAuth authorization request can be made to answer the wrong party."""
    name: str
    family: Literal["redirect", "state", "pkce", "response_type", "scope", "federation"]
    redirect_uri: str
    params: dict[str, str] = Field(default_factory=dict)
    rationale: str
    expected: Literal["token_leak", "code_leak", "consent_bypass", "scope_escalation"] = "code_leak"


class CloudKey(Base):
    kind: Literal["aws", "gcp", "yandex", "k8s", "vault", "db", "ssh", "generic"]
    source: str
    fingerprint: str = Field(description="a redacted handle: prefix, length, last four")
    live: bool | None = None


class PluginRisk(Base):
    name: str
    market: Literal["vscode", "jetbrains", "unknown"] = "unknown"
    downloads: int = 0
    permissions: list[str] = Field(default_factory=list)
    remote_fetch: bool = False
    obfuscated: bool = False
    abandoned_since: str | None = None
    verdict: Literal["clean", "watch", "hostile", "unknown"] = "unknown"


class Finding(Base):
    subgraph: Literal["a_supply_chain", "b_oauth", "c_cloud", "d_plugins"]
    kind: str
    target: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    value_usd: int = 0

    @field_validator("evidence")
    @classmethod
    def no_ethics_leak(cls, value: str) -> str:
        if "Understand and follow applicable laws" in value:
            raise ValueError("the ethics line belongs in the audit log, never in evidence sent to a target")
        return value


class Judgement(Base):
    """What a judge answers. SELF-CONSISTENCY aggregates several of these."""
    verdict: Literal["accept", "reject", "unsure"]
    reasons: list[str] = Field(default_factory=list, min_length=1)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class RunState(Base):
    """What the supervisor carries between turns."""
    run_id: str
    remaining: float = 1.0
    spent: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class BypassMatrix(Base):
    cases: list[BypassCase] = Field(min_length=1)


class CloudKeys(Base):
    keys: list[CloudKey] = Field(default_factory=list)


class CanaryPlan(Base):
    candidates: list[CanaryCandidate] = Field(default_factory=list)


class PluginVerdict(Base):
    risk: PluginRisk


class PricePoint(Base):
    usd: int = Field(ge=0)
    reason: str = Field(min_length=1)
