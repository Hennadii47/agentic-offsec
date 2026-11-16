"""The bypass matrix: every way an authorization request can answer the wrong party."""
from __future__ import annotations

from urllib.parse import urlsplit

from lib.schemas import BypassCase

FAMILIES = ("redirect", "state", "pkce", "response_type", "scope", "federation")


def _host(redirect: str) -> str:
    return urlsplit(redirect).netloc or "client.example"


def bypass_matrix(redirect: str, client_id: str = "client", scopes: str = "openid email") -> list[BypassCase]:
    host = _host(redirect)
    base = redirect.rstrip("/")
    cases = [
        BypassCase(name="path traversal", family="redirect", redirect_uri=f"{base}/../attacker",
                   rationale="a normalising proxy and the authorisation server may resolve '..' differently",
                   expected="code_leak"),
        BypassCase(name="host suffix", family="redirect", redirect_uri=f"{base}.attacker.tld",
                   rationale="a suffix check without a dot boundary accepts any host that ends with ours",
                   expected="code_leak"),
        BypassCase(name="userinfo confusion", family="redirect",
                   redirect_uri=f"https://{host}@attacker.tld/cb",
                   rationale="the browser reads attacker.tld, a naive parser reads the first host",
                   expected="code_leak"),
        BypassCase(name="scheme downgrade", family="redirect",
                   redirect_uri=base.replace("https://", "http://"),
                   rationale="an http callback can be intercepted on the wire", expected="code_leak"),
        BypassCase(name="port variation", family="redirect", redirect_uri=f"{base}:8443/cb",
                   rationale="port often unvalidated when the scheme and host are", expected="code_leak"),
        BypassCase(name="fragment injection", family="redirect", redirect_uri=f"{base}#@attacker.tld",
                   rationale="the fragment reaches the implicit flow's token, not the server", expected="token_leak"),
        BypassCase(name="state omitted", family="state", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id, "scope": scopes},
                   rationale="without state a cross-site request is indistinguishable from a user's",
                   expected="code_leak"),
        BypassCase(name="state echoed", family="state", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id, "scope": scopes,
                           "state": "fixed"},
                   rationale="a constant state proves the flow was written, not that it is bound to a session",
                   expected="code_leak"),
        BypassCase(name="pkce omitted", family="pkce", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id, "scope": scopes,
                           "code_challenge": "", "code_challenge_method": ""},
                   rationale="without PKCE an intercepted code is redeemable by anyone", expected="code_leak"),
        BypassCase(name="pkce plain", family="pkce", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id,
                           "code_challenge_method": "plain"},
                   rationale="with 'plain' the challenge is the verifier, so the interception wins",
                   expected="code_leak"),
        BypassCase(name="implicit response", family="response_type", redirect_uri=base,
                   params={"response_type": "token", "client_id": client_id, "scope": scopes},
                   rationale="the token travels in the fragment where a redirect target can read it",
                   expected="token_leak"),
        BypassCase(name="scope escalation", family="scope", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id,
                           "scope": scopes + " docs tax bank"},
                   rationale="consent screens show the requested scope, servers often grant the union",
                   expected="scope_escalation"),
        BypassCase(name="federation confusion", family="federation", redirect_uri=base,
                   params={"response_type": "code", "client_id": client_id,
                           "issuer": "https://attacker.tld", "scope": scopes},
                   rationale="an unsigned issuer parameter lets a second provider mint the first one's subject",
                   expected="consent_bypass"),
    ]
    return cases


def complete_matrix(cases: list[BypassCase]) -> dict[str, bool]:
    """What a client is missing, by family."""
    present = {case.family for case in cases}
    return {family: family in present for family in FAMILIES}
