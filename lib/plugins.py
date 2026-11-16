"""What an editor extension asks for, and whether it takes more than it needs."""
from __future__ import annotations

import json
import math
import re
import zipfile
from pathlib import Path

from lib.schemas import PluginRisk

DANGEROUS = {
    "fs.readFile": "reads local files",
    "os.homedir": "walks the home directory",
    ".ssh": "touches ssh material",
    ".aws": "touches cloud credentials",
    ".kube": "touches cluster credentials",
    "child_process": "runs a process",
    "execSync": "runs a process",
    "eval(": "evaluates code",
    "Buffer.from": "decodes a payload",
}
REMOTE = re.compile(r"https?://[^\s\"'`)]+")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(text))
    return -sum((n / total) * math.log2(n / total) for n in counts.values() if n)


def scan_vsix(path: Path, downloads: int = 0, abandoned_since: str | None = None) -> PluginRisk:
    permissions: list[str] = []
    remote = False
    obfuscated = False
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith("package.json") or name == "extension/package.json":
                try:
                    manifest = json.loads(archive.read(name))
                except json.JSONDecodeError:
                    continue
                if "*" in (manifest.get("activationEvents") or []):
                    permissions.append("activates on startup")
                for key in ("contributes", "capabilities"):
                    if manifest.get(key):
                        permissions.append(f"contributes {key}")
                if manifest.get("extensionKind") == ["workspace"] and manifest.get("main"):
                    permissions.append("runs workspace code")
            if name.endswith((".js", ".ts")):
                body = archive.read(name).decode("utf-8", "replace")
                for needle, meaning in DANGEROUS.items():
                    if needle in body and meaning not in permissions:
                        permissions.append(meaning)
                if REMOTE.search(body):
                    remote = True
                longest = max((len(line) for line in body.splitlines()), default=0)
                if longest > 4000 or entropy(body) > 5.6:
                    obfuscated = True
    verdict = "unknown"
    if permissions and remote and obfuscated:
        verdict = "hostile"
    elif remote and obfuscated:
        verdict = "watch"
    elif not permissions:
        verdict = "clean"
    return PluginRisk(name=path.stem, market="vscode", downloads=downloads, permissions=sorted(permissions),
                      remote_fetch=bool(remote), obfuscated=obfuscated, abandoned_since=abandoned_since,
                      verdict=verdict)


def scan_jar(path: Path, downloads: int = 0) -> PluginRisk:
    permissions, remote, obfuscated = [], False, False
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name == "META-INF/plugin.xml":
                body = archive.read(name).decode("utf-8", "replace")
                for tag in ("idea-version", "depends", "extensionPoints"):
                    if f"<{tag}" in body:
                        permissions.append(f"declares {tag}")
                if "since-build" in body:
                    permissions.append("declares a platform range")
            if name.endswith(".class"):
                body = archive.read(name)
                if b"java/net/URL" in body or b"HttpClient" in body:
                    remote = True
                if b"java/lang/Runtime" in body and b"exec" in body:
                    permissions.append("runs a process")
            if name.endswith(".xml") and "plugin" in name:
                body = archive.read(name).decode("utf-8", "replace")
                if REMOTE.search(body):
                    remote = True
    verdict = "watch" if remote else ("clean" if not permissions else "unknown")
    return PluginRisk(name=path.stem, market="jetbrains", downloads=downloads, permissions=sorted(set(permissions)),
                      remote_fetch=remote, obfuscated=obfuscated, verdict=verdict)
