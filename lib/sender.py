"""B's hands: send one authorisation request and record where it actually went.

Nothing is sent to a host the operator has not listed in configs/targets.yaml under
authorized. A refused host is an error, not a silent skip.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlencode, urlsplit, urlunsplit

from lib import net
from lib.schemas import BypassCase


class OutOfScope(RuntimeError):
    pass


@dataclass
class ProbeResult:
    case: str
    url: str
    status: int
    location: str | None
    error: str | None = None
    sent: bool = True


def build_url(authorize: str, client_id: str, case: BypassCase, scopes: str = "openid") -> str:
    parts = urlsplit(authorize)
    params = {"client_id": client_id, "redirect_uri": case.redirect_uri, "scope": scopes,
              "response_type": "code", **case.params}
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def probe(authorize: str, client_id: str, case: BypassCase, allow: list[str],
          transport: Callable[..., net.Response] = net.get, dry_run: bool = True,
          scopes: str = "openid") -> ProbeResult:
    url = build_url(authorize, client_id, case, scopes)
    if not net.allowed(url, allow):
        raise OutOfScope(f"{net.host_of(url)} is not in the authorised list")
    if dry_run:
        return ProbeResult(case=case.name, url=url, status=0, location=None, sent=False)
    answer = transport(url)
    return ProbeResult(case=case.name, url=url, status=answer.status,
                       location=answer.headers.get("location"), error=answer.error)


def campaign(authorize: str, client_id: str, cases: list[BypassCase], allow: list[str],
             transport: Callable[..., net.Response] = net.get, dry_run: bool = True,
             scopes: str = "openid") -> list[ProbeResult]:
    return [probe(authorize, client_id, case, allow, transport, dry_run, scopes) for case in cases]
