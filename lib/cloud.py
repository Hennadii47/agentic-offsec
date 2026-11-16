"""What an infrastructure artefact gives away, parsed as code rather than grepped."""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from lib.opsec import fingerprint
from lib.schemas import CloudKey

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws", re.compile(r"\baws_secret_access_key\s*[=:]\s*\"?([A-Za-z0-9/+=]{40})")),
    ("yandex", re.compile(r"\b(YC[A-Za-z0-9_\-]{16,}|AQVN[A-Za-z0-9_\-]{16,})\b")),
    ("gcp", re.compile(r"\"type\"\s*:\s*\"service_account\"")),
    ("vault", re.compile(r"\bhv[sr]\.[A-Za-z0-9_\-]{20,}")),
    ("ssh", re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----")),
    ("db", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^\s\"']+")),
    ("k8s", re.compile(r"\b(kubeconfig|client-key-data|client-certificate-data)\b")),
    ("generic", re.compile(r"\b(?:api[_-]?key|token|secret)\b\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{16,})")),
]


def extract_keys(text: str, source: str) -> list[CloudKey]:
    keys: list[CloudKey] = []
    seen: set[str] = set()
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0) if match.groups() == () else (match.group(1) or match.group(0))
            mark = fingerprint(raw)
            if mark in seen:
                continue
            seen.add(mark)
            keys.append(CloudKey(kind=kind, source=source, fingerprint=mark))
    return keys


def from_tfstate(path: Path) -> list[CloudKey]:
    data = json.loads(path.read_text())
    return extract_keys(json.dumps(data), path.name)


def from_kubeconfig(path: Path) -> list[CloudKey]:
    data = yaml.safe_load(path.read_text()) or {}
    hosts = [cluster.get("cluster", {}).get("server", "") for cluster in data.get("clusters", [])]
    return extract_keys(path.read_text() + " ".join(filter(None, hosts)), path.name)


def from_env_file(path: Path) -> list[CloudKey]:
    return extract_keys(path.read_text(), path.name)


READERS = {".tfstate": from_tfstate, ".json": from_tfstate, "kubeconfig": from_kubeconfig,
           ".env": from_env_file, ".yaml": from_env_file, ".yml": from_env_file, ".tfvars": from_env_file}


def scan(path: Path) -> list[CloudKey]:
    if path.name == "kubeconfig":
        return from_kubeconfig(path)
    for suffix, reader in READERS.items():
        if path.name.endswith(suffix):
            try:
                return reader(path)
            except (json.JSONDecodeError, yaml.YAMLError, OSError):
                return extract_keys(path.read_text(errors="replace"), path.name)
    return extract_keys(path.read_text(errors="replace"), path.name)


def rank(keys: list[CloudKey]) -> list[CloudKey]:
    """Cloud admin first, then cluster, then storage, then everything else."""
    order = {"aws": 0, "yandex": 0, "gcp": 0, "k8s": 1, "vault": 2, "db": 3, "ssh": 4, "generic": 5}
    return sorted(keys, key=lambda key: order.get(key.kind, 9))
