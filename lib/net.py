"""One HTTP seam. Every vector goes through it, and a test can replace it."""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

UA = "Mozilla/5.0 (compatible; agentic-offsec/0.1)"
MAX_BYTES = 8 * 1024 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is the answer we are looking for, not a step to follow."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


def get(url: str, timeout: float = 20.0, user_agent: str = UA, limit: int = MAX_BYTES) -> Response:
    request = urllib.request.Request(url, headers={"user-agent": user_agent, "accept": "*/*"})
    try:
        with OPENER.open(request, timeout=timeout) as answer:
            body = answer.read(limit)
            return Response(url=url, status=answer.status,
                            headers={k.lower(): v for k, v in answer.headers.items()}, body=body)
    except urllib.error.HTTPError as error:
        return Response(url=url, status=error.code,
                        headers={k.lower(): v for k, v in (error.headers or {}).items()},
                        body=(error.read(limit) if error.fp else b""))
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return Response(url=url, status=0, error=str(error))


def host_of(url: str) -> str:
    return urlsplit(url).netloc.lower()


def allowed(url: str, allow: list[str]) -> bool:
    """A host is in scope when it is listed exactly or as a parent domain."""
    host = host_of(url)
    return any(host == entry.lower() or host.endswith("." + entry.lower()) for entry in allow)
