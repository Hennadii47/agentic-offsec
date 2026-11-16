"""D's hands: fetch the artefact an editor marketplace would serve."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from lib import net

VSIX = ("https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisher}"
        "/vsextensions/{name}/{version}/vspackage")
JETBRAINS = "https://plugins.jetbrains.com/plugin/download?pluginId={ident}&updateId={update}"


def vsix_url(publisher: str, name: str, version: str = "latest") -> str:
    return VSIX.format(publisher=publisher, name=name, version=version)


def jetbrains_url(ident: str, update: str) -> str:
    return JETBRAINS.format(ident=ident, update=update)


def fetch(url: str, dest: Path, transport: Callable[..., net.Response] = net.get) -> tuple[Path | None, str]:
    """Download URL to DEST. Answers the path, and why it is missing when it is."""
    answer = transport(url)
    if answer.status != 200 or not answer.body:
        return None, f"status {answer.status} {answer.error or ''}".strip()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(answer.body)
    return dest, f"{len(answer.body)} bytes"
