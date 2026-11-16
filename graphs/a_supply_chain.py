"""A: a build that installs a name nobody owns yet."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of
from lib import deps as deps_mod
from lib.opsec import Signer
from lib import beacon, publish as publisher
from lib.schemas import Canary, CanaryPlan, Finding

PUBLISH = yaml.safe_load((Path(__file__).resolve().parent.parent / 'configs/publish.yaml').read_text())

BEACON = "https://beacon.example/c"


CACHE = Path(os.environ.get("AGENTIC_REPO_CACHE", Path.home() / ".cache" / "agentic-repos"))


def resolve(reference: str) -> Path | None:
    """A local directory for REFERENCE: itself when it exists, else a shallow clone.

    configs/targets.yaml names repositories the way GitHub names them, so a run
    without this would harvest nothing at all.
    """
    path = Path(reference)
    if path.exists():
        return path
    if not reference.startswith(("http://", "https://", "git@")):
        return None
    slug = reference.rstrip("/").split("/")[-2:]
    target = CACHE / ("-".join(slug).replace(".git", ""))
    if target.exists():
        return target
    CACHE.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["git", "clone", "--depth", "1", "--quiet", reference, str(target)],
                            capture_output=True, text=True, timeout=180)
    return target if result.returncode == 0 else None


def harvest(state: State, *, router, audit, limits) -> State:
    references = state.get("targets", {}).get("repos", [])
    roots, rows, missed = [], [], []
    for reference in references:
        root = resolve(reference)
        if root is None:
            missed.append(reference)
            continue
        roots.append(root)
        rows.extend(deps_mod.scan_repo(root))
    audit.log("a.harvest", targets=len(roots), dependencies=len(rows), unreachable=len(missed))
    return {**state, "notes": [f"dependencies={len(rows)}"], "_deps": rows}


def plan(state: State, *, router, audit, limits) -> State:
    prefixes = state.get("targets", {}).get("org_prefixes", [])
    payload = [row.model_dump() for row in state.get("_deps", [])]
    plan_result: CanaryPlan = router.complete("canary_plan", "plan canaries", CanaryPlan,
                                              {"dependencies": payload, "prefixes": prefixes})
    audit.log("a.plan", candidates=len(plan_result.candidates))
    return {**state, "_plan": plan_result}


def sign(state: State, *, router, audit, limits) -> State:
    signer = Signer.from_key(limits.get("canary_key", "dev-key"))
    canaries = []
    for index, candidate in enumerate(state.get("_plan").candidates):
        version = "0.0.1" if candidate.ecosystem.value == "pypi" else "99.0.0"
        signature = signer.sign(candidate.name, version)
        if not signer.verify(candidate.name, version, signature):
            continue
        canaries.append(Canary(name=candidate.name, ecosystem=candidate.ecosystem, version=version,
                               signature=signature, beacon_url=BEACON))
    audit.log("a.sign", canaries=len(canaries))
    return {**state, "_canaries": canaries}


def emit(state: State, *, router, audit, limits) -> State:
    usd = value_of(router, "ci_cd_secrets")
    current = state
    for canary in state.get("_canaries", []):
        current = add_finding(current, Finding(
            subgraph="a_supply_chain", kind="canary", target=canary.name,
            evidence=f"{canary.ecosystem.value}:{canary.name}@{canary.version} signed, beacon {canary.beacon_url}",
            confidence=0.8, value_usd=usd))
    return current


def publish(state: State, *, router, audit, limits) -> State:
    """Build every canary into a real artefact and hand it to the real client."""
    settings = PUBLISH["publish"]
    dry_run = settings.get("mode", "dry_run") != "live"
    artifacts = []
    for canary in state.get("_canaries", []):
        artifact = (publisher.build_npm(canary) if canary.ecosystem.value == "npm"
                    else publisher.build_pypi(canary))
        registry = settings.get("npm_registry" if artifact.ecosystem == "npm" else "pypi_index")
        outcome = publisher.publish(artifact, registry=registry, dry_run=dry_run)
        artifacts.append((artifact, outcome))
        audit.log("a.publish", package=artifact.name, version=artifact.version,
                  sha256=artifact.sha256, published=outcome.get("published", False),
                  dry_run=dry_run, command=outcome.get("command"))
    return {**state, "_artifacts": artifacts}


def monitor(state: State, *, router, audit, limits) -> State:
    """What rang: every hit the beacon recorded, verified against the signing key."""
    source = state.get("targets", {}).get("hits") or PUBLISH["monitor"].get("hits_file")
    if not source or not Path(source).exists():
        audit.log("a.monitor", hits=0, source=None)
        return {**state, "_hits": []}
    signer = Signer.from_key(limits.get("canary_key", "dev-key"))
    hits = beacon.read_hits(source, signer)
    audit.log("a.monitor", hits=len(hits), verified=sum(1 for hit in hits if hit.verified), source=str(source))
    current = state
    for hit in hits:
        if not hit.verified:
            continue
        current = add_finding(current, Finding(
            subgraph="a_supply_chain", kind="beacon_hit", target=hit.name,
            evidence=f"{hit.name}@{hit.version} installed at {hit.at} from {hit.country or 'unknown'} (asn {hit.asn})",
            confidence=0.95, value_usd=int(PUBLISH["monitor"]["value_usd"])))
    return {**current, "_hits": hits}


def build(router, audit, limits):
    graph = StateGraph(State)
    graph.add_node("harvest", lambda state: harvest(state, router=router, audit=audit, limits=limits))
    graph.add_node("plan", lambda state: plan(state, router=router, audit=audit, limits=limits))
    graph.add_node("sign", lambda state: sign(state, router=router, audit=audit, limits=limits))
    graph.add_node("emit", lambda state: emit(state, router=router, audit=audit, limits=limits))
    graph.add_node("publish", lambda state: publish(state, router=router, audit=audit, limits=limits))
    graph.add_node("monitor", lambda state: monitor(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "plan")
    graph.add_edge("plan", "sign")
    graph.add_edge("sign", "emit")
    graph.add_edge("emit", "publish")
    graph.add_edge("publish", "monitor")
    graph.add_edge("monitor", END)
    return graph.compile()
