"""B: authorisation business logic, fuzzed as a matrix rather than a payload."""
from __future__ import annotations

from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of
from lib.llm.judges import judge
from lib.schemas import BypassMatrix, Finding


def harvest(state: State, *, router, audit, limits) -> State:
    clients = state.get("targets", {}).get("clients", [])
    audit.log("b.harvest", clients=len(clients))
    return {**state, "_clients": clients}


def matrix(state: State, *, router, audit, limits) -> State:
    built = []
    for client in state.get("_clients", []):
        result: BypassMatrix = router.complete(
            "oauth_matrix", f"matrix for {client.get('id')}", BypassMatrix,
            {"redirect_uri": client.get("redirect_uri", f"https://{client.get('id')}.example/cb"),
             "client_id": client.get("id", "client"), "scopes": client.get("scope", "openid email")})
        built.append((client, result.cases))
    audit.log("b.matrix", clients=len(built), cases=sum(len(cases) for _, cases in built))
    return {**state, "_matrices": built}


def triage(state: State, *, router, audit, limits) -> State:
    kept = []
    for client, cases in state.get("_matrices", []):
        for case in cases:
            verdict = judge(router, "oauth_judge", f"is {case.name} plausible for {client.get('id')}",
                            {"case": case.name, "family": case.family, "expected": case.expected}, n=3)
            if verdict.verdict == "reject":
                continue
            kept.append((client, case, verdict))
    audit.log("b.triage", kept=len(kept))
    return {**state, "_kept": kept}


def emit(state: State, *, router, audit, limits) -> State:
    current = state
    for client, case, verdict in state.get("_kept", []):
        usd = value_of(router, "bank_oauth_token" if "bank" in case.redirect_uri else "gov_oauth_token")
        current = add_finding(current, Finding(
            subgraph="b_oauth", kind=case.family, target=client.get("id", "client"),
            evidence=f"{case.name}: {case.redirect_uri} {case.params}",
            confidence=verdict.confidence, value_usd=usd))
    return current


def build(router, audit, limits):
    graph = StateGraph(State)
    for name, node in (("harvest", harvest), ("matrix", matrix), ("triage", triage), ("emit", emit)):
        graph.add_node(name, lambda state, node=node: node(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "matrix")
    graph.add_edge("matrix", "triage")
    graph.add_edge("triage", "emit")
    graph.add_edge("emit", END)
    return graph.compile()
