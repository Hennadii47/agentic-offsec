"""Reading what rang: hits, verified against the same key that signed the canary."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
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



def from_cloudflare(namespace_id: str, account_id: str | None = None,
                    token: str | None = None, limit: int = 200) -> list[dict]:
    """The beacon worker's KV, read back as records. Nothing is copied by hand."""
    account = account_id or os.environ.get("CF_ACCOUNT_ID", "")
    secret = token or os.environ.get("CF_API_TOKEN", "")
    if not account or not secret:
        return []
    base = f"https://api.cloudflare.com/client/v4/accounts/{account}/storage/kv/namespaces/{namespace_id}"
    headers = {"authorization": f"Bearer {secret}"}
    with urllib.request.urlopen(urllib.request.Request(base + f"/keys?limit={limit}", headers=headers), timeout=30) as answer:
        keys = json.loads(answer.read()).get("result", [])
    records = []
    for row in keys:
        url = base + "/values/" + urllib.parse.quote(row["name"])
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as answer:
            try:
                records.append(json.loads(answer.read()))
            except json.JSONDecodeError:
                continue
    return records


def read_source(source: str, signer: Signer) -> list[Hit]:
    """HITS is either a JSONL path or cf://<namespace-id>."""
    if str(source).startswith("cf://"):
        return read_hits_of(from_cloudflare(str(source)[5:]), signer)
    return read_hits(source, signer)
