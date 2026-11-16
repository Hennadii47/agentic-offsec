"""B: authorisation business logic, fuzzed as a matrix rather than a payload."""
from __future__ import annotations

from pathlib import Path

import yaml
from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of

SEND = yaml.safe_load((Path(__file__).resolve().parent.parent / 'configs/send.yaml').read_text())["send"]
from lib import sender
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


def _evidence(case, sent) -> str:
    if sent is None or not getattr(sent, "sent", False):
        return f"{case.name}: {case.redirect_uri} {case.params} (not sent)"
    return (f"{case.name}: sent {case.redirect_uri} -> {sent.status}"
            + (f" {sent.location}" if sent.location else "") + (f" {sent.error}" if sent.error else ""))


def emit(state: State, *, router, audit, limits) -> State:
    current = state
    by_case = {result.case: result for _, _, result in state.get("_probes", [])}
    for client, case, verdict in state.get("_kept", []):
        sent = by_case.get(case.name)
        usd = value_of(router, "bank_oauth_token" if "bank" in case.redirect_uri else "gov_oauth_token")
        current = add_finding(current, Finding(
            subgraph="b_oauth", kind=case.family, target=client.get("id", "client"),
            evidence=_evidence(case, sent),
            confidence=verdict.confidence, value_usd=usd))
    return current


def send(state: State, *, router, audit, limits) -> State:
    """Send what triage kept, to hosts the operator listed, and record the answer."""
    dry_run = SEND.get("mode", "dry_run") != "live"
    allow = SEND.get("authorized", [])
    probes = []
    for client, case, verdict in state.get("_kept", []):
        try:
            result = sender.probe(client.get("authorize", ""), client.get("id", "client"), case,
                                  allow, dry_run=dry_run, scopes=client.get("scope", "openid"))
            probes.append((client, case, result))
            audit.log("b.send", client=client.get("id"), case=case.name, sent=result.sent,
                      status=result.status, location=result.location)
        except sender.OutOfScope as error:
            audit.log("b.send", client=client.get("id"), case=case.name, refused=str(error))
    return {**state, "_probes": probes}


def build(router, audit, limits):
    graph = StateGraph(State)
    for name, node in (("harvest", harvest), ("matrix", matrix), ("triage", triage), ("emit", emit)):
        graph.add_node(name, lambda state, node=node: node(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "matrix")
    graph.add_edge("matrix", "triage")
    graph.add_node("send", lambda state: send(state, router=router, audit=audit, limits=limits))
    graph.add_edge("triage", "send")
    graph.add_edge("send", "emit")
    graph.add_edge("emit", END)
    return graph.compile()
