"""C: infrastructure written down where anyone can read it."""
from __future__ import annotations

import os
from pathlib import Path

from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of
from lib import assets, cloud, prompts
from lib.schemas import CloudKeys, Finding

VALUE = {"aws": "cloud_admin", "yandex": "cloud_admin", "gcp": "cloud_admin",
         "k8s": "k8s_cluster_admin", "vault": "generic_api_key", "db": "generic_api_key",
         "ssh": "ssh_key", "generic": "generic_api_key"}


def harvest(state: State, *, router, audit, limits) -> State:
    """A path is read where it is; a URL is brought down first."""
    cache = Path(os.environ.get("AGENTIC_ASSET_CACHE", Path.home() / ".cache" / "agentic-assets"))
    files, fetched, failed = [], 0, []
    for entry in state.get("targets", {}).get("files", []):
        if isinstance(entry, str) and entry.startswith(("http://", "https://")):
            path, why = assets.fetch(entry, cache)
            if path is None:
                failed.append(f"{entry}: {why}")
                continue
            files.append(path)
            fetched += 1
            continue
        path = Path(entry)
        if path.exists():
            files.append(path)
    audit.log("c.harvest", files=len(files), fetched=fetched, failed=len(failed))
    return {**state, "_files": files}


def extract(state: State, *, router, audit, limits) -> State:
    found = []
    for path in state.get("_files", []):
        found.extend(cloud.scan(path))
    audit.log("c.extract", keys=len(found))
    return {**state, "_keys": cloud.rank(found)}


def emit(state: State, *, router, audit, limits) -> State:
    current = state
    for key in state.get("_keys", []):
        usd = value_of(router, VALUE.get(key.kind, "generic_api_key"))
        current = add_finding(current, Finding(
            subgraph="c_cloud", kind=key.kind, target=key.source,
            evidence=f"{key.kind} key {key.fingerprint} in {key.source}", confidence=0.7, value_usd=usd))
    return current


def build(router, audit, limits):
    graph = StateGraph(State)
    graph.add_node("harvest", lambda state: harvest(state, router=router, audit=audit, limits=limits))
    graph.add_node("extract", lambda state: extract(state, router=router, audit=audit, limits=limits))
    graph.add_node("emit", lambda state: emit(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "extract")
    graph.add_edge("extract", "emit")
    graph.add_edge("emit", END)
    return graph.compile()
