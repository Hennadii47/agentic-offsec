"""C's hands: bring an infrastructure artefact from where it is published."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from lib import net

NAME_HINTS = ("terraform.tfstate", ".env", "values.yaml", "kubeconfig", ".tfvars", "config.json")


def name_for(url: str) -> str:
    name = url.rstrip("/").split("/")[-1] or "download"
    return name if any(hint in name for hint in NAME_HINTS) else name


def fetch(url: str, cache: Path, transport: Callable[..., net.Response] = net.get) -> tuple[Path | None, str]:
    answer = transport(url)
    if answer.status != 200 or not answer.body:
        return None, f"status {answer.status} {answer.error or ''}".strip()
    target = cache / name_for(url)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(answer.body)
    return target, f"{len(answer.body)} bytes"
