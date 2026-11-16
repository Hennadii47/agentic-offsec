"""The deterministic expert behind every purpose: what answers when no model key is set.

Each function is the same judgement a model is asked for, written as rules over the
evidence, so a run without keys still produces a defensible answer instead of a mock.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from lib import cloud, deps as deps_mod, oauth, plugins
from lib.schemas import (BypassMatrix, CanaryPlan, CloudKeys, Dependency, Ecosystem, Judgement,
                          PluginVerdict, PricePoint)

ROOT = Path(__file__).resolve().parent.parent


def answer(purpose: str, schema, context: dict) -> dict:
    handler = {
        "dep_judge": dep_judge,
        "canary_plan": canary_plan,
        "oauth_matrix": oauth_matrix,
        "oauth_judge": oauth_judge,
        "cloud_extract": cloud_extract,
        "plugin_audit": plugin_audit,
        "monetize": monetize,
    }.get(purpose)
    if handler is None:
        raise ValueError(f"no local expert for {purpose}")
    return schema.model_validate(handler(context)).model_dump()


def dep_judge(context: dict) -> Judgement:
    name = context["name"]
    prefixes = context.get("prefixes", [])
    prefixed = any(name.startswith(prefix) for prefix in prefixes)
    published = context.get("published", 0)
    if prefixed and not published:
        return Judgement(verdict="accept", confidence=0.9,
                         reasons=[f"{name} carries an organisation prefix and no registry answers for it"])
    if published:
        return Judgement(verdict="reject", confidence=0.95,
                         reasons=[f"{name} is already published, so a canary would be contested"])
    return Judgement(verdict="unsure", confidence=0.4,
                     reasons=[f"{name} neither carries a known prefix nor a measured registry record"])


def canary_plan(context: dict) -> CanaryPlan:
    rows = [Dependency(**row) if isinstance(row, dict) else row for row in context.get("dependencies", [])]
    return CanaryPlan(candidates=deps_mod.missing_internal(rows, context.get("prefixes", [])))


def oauth_matrix(context: dict) -> BypassMatrix:
    cases = oauth.bypass_matrix(context.get("redirect_uri", "https://client.example/cb"),
                                 context.get("client_id", "client"),
                                 context.get("scopes", "openid email"))
    wanted = set(context.get("families", []))
    if wanted:
        cases = [case for case in cases if case.family in wanted]
    return BypassMatrix(cases=cases)


def oauth_judge(context: dict) -> Judgement:
    """Whether one bypass case is worth sending, judged on its family and expected impact."""
    family = context.get("family", "")
    expected = context.get("expected", "code_leak")
    name = context.get("case", "a case")
    if family in oauth.FAMILIES and expected in {"code_leak", "token_leak", "consent_bypass", "scope_escalation"}:
        weight = 0.75 if expected in ("token_leak", "consent_bypass") else 0.65
        return Judgement(verdict="accept", confidence=weight,
                         reasons=[f"{name} is a {family} case whose failure mode is {expected}"])
    if not family:
        return Judgement(verdict="unsure", confidence=0.3, reasons=[f"{name} names no family to judge"])
    return Judgement(verdict="reject", confidence=0.7, reasons=[f"{name}: {family} is not a recognised family"])


def cloud_extract(context: dict) -> CloudKeys:
    text = context.get("text") or (Path(context["path"]).read_text(errors="replace") if context.get("path") else "")
    keys = cloud.extract_keys(text, context.get("source", "<text>"))
    return CloudKeys(keys=cloud.rank(keys))


def plugin_audit(context: dict) -> PluginVerdict:
    path = Path(context["path"])
    risk = (plugins.scan_vsix(path, context.get("downloads", 0)) if path.suffix == ".vsix"
            else plugins.scan_jar(path, context.get("downloads", 0)))
    return PluginVerdict(risk=risk)


def monetize(context: dict) -> PricePoint:
    pricing = yaml.safe_load((ROOT / "configs/pricing.yaml").read_text())["initial_access"]
    kind = context.get("kind", "generic_api_key")
    return PricePoint(usd=int(pricing.get(kind, pricing["generic_api_key"])),
                      reason=f"{kind} is priced from configs/pricing.yaml")


def ecosystem_of(value: str) -> Ecosystem:
    try:
        return Ecosystem(value)
    except ValueError:
        return Ecosystem.unknown
