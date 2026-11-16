"""Reading what rang: hits, verified against the same key that signed the canary."""
from __future__ import annotations

import json
from pathlib import Path

from lib.opsec import Signer
from lib.schemas import Hit


def read_hits(source: str | Path, signer: Signer) -> list[Hit]:
    """A JSONL file of beacon records, each verified by re-signing name@version."""
    path = Path(source)
    hits: list[Hit] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        name, version = record.get("name", ""), record.get("version", "")
        signature = record.get("sig") or record.get("signature") or ""
        hits.append(Hit(name=name, version=version, at=record.get("at", ""),
                        country=record.get("country"), asn=record.get("asn"),
                        user_agent=record.get("ua", ""),
                        verified=signer.verify(name, version, signature) if signature else False))
    return hits


def from_worker(records: list[dict], signer: Signer) -> list[Hit]:
    """The KV values the beacon worker wrote, already parsed."""
    return read_hits_of(records, signer)


def read_hits_of(records: list[dict], signer: Signer) -> list[Hit]:
    hits = []
    for record in records:
        name, version = record.get("name", ""), record.get("version", "")
        hits.append(Hit(name=name, version=version, at=record.get("at", ""),
                        country=record.get("country"), asn=record.get("asn"),
                        user_agent=record.get("ua", ""),
                        verified=signer.verify(name, version, record.get("sig", ""))))
    return hits
