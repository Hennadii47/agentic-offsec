"""Read what a repository actually depends on, in the four ecosystems that matter."""
from __future__ import annotations

import json
import re
from pathlib import Path

from lib.schemas import CanaryCandidate, Dependency, Ecosystem

NPM_LINE = re.compile(r'"(@?[\w.\-/]+)"\s*:\s*"([^"]+)"')


def from_package_json(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    rows = []
    for scope, key in (("runtime", "dependencies"), ("dev", "devDependencies"),
                       ("build", "peerDependencies")):
        for name, version in (data.get(key) or {}).items():
            rows.append(Dependency(name=name, version=str(version), ecosystem=Ecosystem.npm,
                                   source_file=path.name, scope=scope))
    return rows


def from_requirements(path: Path) -> list[Dependency]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+\s*(\S+))?", line)
        if match:
            rows.append(Dependency(name=match.group(1), version=match.group(2) or "",
                                   ecosystem=Ecosystem.pypi, source_file=path.name))
    return rows


def from_go_mod(path: Path) -> list[Dependency]:
    rows = []
    for line in path.read_text().splitlines():
        match = re.match(r"\s*(?:require\s+)?([\w.\-/]+)\s+v(\S+)", line)
        if match and "." in match.group(1):
            rows.append(Dependency(name=match.group(1), version=match.group(2),
                                   ecosystem=Ecosystem.go, source_file=path.name))
    return rows


def from_cargo(path: Path) -> list[Dependency]:
    rows, section = [], "runtime"
    for line in path.read_text().splitlines():
        if line.strip().startswith("["):
            section = "dev" if "dev-dependencies" in line else (
                "build" if "build-dependencies" in line else "runtime")
            continue
        match = re.match(r"\s*([A-Za-z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*)?\"([^\"]+)\"", line)
        if match:
            rows.append(Dependency(name=match.group(1), version=match.group(2),
                                   ecosystem=Ecosystem.cargo, source_file=path.name, scope=section))
    return rows


PARSERS = {("package.json",): from_package_json, ("requirements.txt",): from_requirements,
           ("go.mod",): from_go_mod, ("Cargo.toml",): from_cargo}


def scan_repo(root: Path) -> list[Dependency]:
    rows: list[Dependency] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        parser = PARSERS.get((path.name,))
        if parser:
            try:
                rows.extend(parser(path))
            except (json.JSONDecodeError, OSError):
                continue
    return rows




def carries_org(name: str, prefixes: list[str]) -> bool:
    """Whether NAME belongs to one of the organisations in PREFIXES.

    A scope ("@sber/ui-kit") and a plain package ("sber-tools") are the same
    claim written two ways, so the prefix is read as the organisation and the
    boundary after it must be a separator, never another word character:
    "sberbank" is not Sber.
    """
    lowered = name.lower().lstrip("@")
    for prefix in prefixes:
        org = prefix.lower().lstrip("@").rstrip("/-_")
        if lowered == org or lowered.startswith(org + "/") or lowered.startswith(org + "-")                 or lowered.startswith(org + "_") or lowered.startswith(org + "."):
            return True
    return False


def missing_internal(deps: list[Dependency], prefixes: list[str]) -> list[CanaryCandidate]:
    """Names that look like an organisation's own packages and are not pinned to a registry.

    A name is a canary candidate when it carries an org prefix, or a scope that no
    public registry serves, and the version is absent or a wildcard: the build will
    resolve it from whatever registry answers first.
    """
    seen: dict[str, CanaryCandidate] = {}
    for dep in deps:
        prefixed = carries_org(dep.name, prefixes)
        unpinned = dep.version in ("", "*", "latest", "^0.0.0", ">=0")
        if prefixed and unpinned and dep.name not in seen:
            seen[dep.name] = CanaryCandidate(
                name=dep.name, ecosystem=dep.ecosystem,
                evidence=f"{dep.source_file}: {dep.name}={dep.version or '(none)'}",
                contested=dep.name in seen)
    return list(seen.values())
