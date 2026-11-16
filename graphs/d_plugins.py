"""D: an extension that can read more than it needs."""
from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, StateGraph

from graphs.common import State, add_finding, value_of
from lib.schemas import Finding, PluginVerdict


def harvest(state: State, *, router, audit, limits) -> State:
    files = [Path(path) for path in state.get("targets", {}).get("plugins", []) if Path(path).exists()]
    audit.log("d.harvest", plugins=len(files))
    return {**state, "_plugins": files}


def audit_plugins(state: State, *, router, audit, limits) -> State:
    rows = []
    for path in state.get("_plugins", []):
        verdict: PluginVerdict = router.complete("plugin_audit", f"audit {path.name}", PluginVerdict,
                                                 {"path": str(path), "downloads": 0})
        rows.append(verdict.risk)
    audit.log("d.audit", plugins=len(rows))
    return {**state, "_risks": rows}


def emit(state: State, *, router, audit, limits) -> State:
    current = state
    for risk in state.get("_risks", []):
        if risk.verdict in ("clean", "unknown"):
            continue
        usd = value_of(router, "ide_publisher_account")
        current = add_finding(current, Finding(
            subgraph="d_plugins", kind=risk.verdict, target=risk.name,
            evidence=f"{risk.market}: permissions={risk.permissions} remote={risk.remote_fetch} obfuscated={risk.obfuscated}",
            confidence=0.75 if risk.verdict == "hostile" else 0.55, value_usd=usd))
    return current


def build(router, audit, limits):
    graph = StateGraph(State)
    graph.add_node("harvest", lambda state: harvest(state, router=router, audit=audit, limits=limits))
    graph.add_node("audit", lambda state: audit_plugins(state, router=router, audit=audit, limits=limits))
    graph.add_node("emit", lambda state: emit(state, router=router, audit=audit, limits=limits))
    graph.set_entry_point("harvest")
    graph.add_edge("harvest", "audit")
    graph.add_edge("audit", "emit")
    graph.add_edge("emit", END)
    return graph.compile()
