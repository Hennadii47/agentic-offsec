"""A: a build that installs a name nobody owns yet."""
from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of
from lib import deps as deps_mod
from lib.opsec import Signer
from lib.schemas import Canary, CanaryPlan, Finding

BEACON = "https://beacon.example/c"


def harvest(state: State, *, router, audit, limits) -> State:
    roots = [Path(path) for path in state.get("targets", {}).get("repos", [])]
    rows = []
    for root in roots:
        if root.exists():
            rows.extend(deps_mod.scan_repo(root))
    audit.log("a.harvest", targets=len(roots), dependencies=len(rows))
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


def build(router, audit, limits):
    graph = StateGraph(State)
    graph.add_node("harvest", lambda state: harvest(state, router=router, audit=audit, limits=limits))
    graph.add_node("plan", lambda state: plan(state, router=router, audit=audit, limits=limits))
    graph.add_node("sign", lambda state: sign(state, router=router, audit=audit, limits=limits))
    graph.add_node("emit", lambda state: emit(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "plan")
    graph.add_edge("plan", "sign")
    graph.add_edge("sign", "emit")
    graph.add_edge("emit", END)
    return graph.compile()
