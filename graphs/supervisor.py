"""One run: decide what is worth the next minute, then let each subgraph earn it."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from langgraph.graph import END, StateGraph

from graphs import a_supply_chain, b_oauth, c_cloud, d_plugins
from graphs.common import State
from lib.llm.router import Router
from lib.opsec import Audit, load_limits
from lib.schemas import Finding, RunState

SUBGRAPHS = {"a_supply_chain": a_supply_chain, "b_oauth": b_oauth, "c_cloud": c_cloud, "d_plugins": d_plugins}
VALUE_KEY = {"a_supply_chain": "ci_cd_secrets", "b_oauth": "bank_oauth_token",
             "c_cloud": "cloud_admin", "d_plugins": "ide_publisher_account"}


def priority(limits: dict, pricing: dict) -> list[str]:
    """Value per second of budget, highest first. Deterministic, so a run is reproducible."""
    scores = {}
    for name in SUBGRAPHS:
        seconds = float(limits["per_subgraph"][name]["budget"]) or 1.0
        scores[name] = pricing["initial_access"][VALUE_KEY[name]] / seconds
    return sorted(scores, key=lambda name: (-scores[name], name))


def route(state: State, *, limits, pricing) -> State:
    order = priority(limits, pricing)
    budget = state.get("budget") or {name: limits["per_subgraph"][name]["budget"] for name in order}
    selected = [name for name in order if budget.get(name, 0) > 0]
    return {**state, "selected": selected[: int(limits["run"].get("max_targets", 4))], "budget": budget}


def runner(name: str, *, router, audit, limits):
    graph = SUBGRAPHS[name].build(router, audit, limits)

    def node(state: State) -> State:
        if name not in state.get("selected", []):
            return state
        started = time.monotonic()
        result = graph.invoke({"run_id": state.get("run_id", "run"),
                               "targets": state.get("targets", {}),
                               "findings": state.get("findings", [])})
        spent = round(time.monotonic() - started, 3)
        audit.log("supervisor.subgraph", subgraph=name, seconds=spent,
                  findings=len(result.get("findings", [])) - len(state.get("findings", [])))
        return {**state, "findings": result.get("findings", [])}
    return node


def build_supervisor(router: Router, audit: Audit, limits: dict | None = None, pricing: dict | None = None):
    import yaml
    limits = limits or load_limits()
    pricing = pricing or yaml.safe_load((Path(__file__).resolve().parent.parent / "configs/pricing.yaml").read_text())
    graph = StateGraph(State)
    graph.add_node("route", lambda state: route(state, limits=limits, pricing=pricing))
    graph.set_entry_point("route")
    previous = "route"
    for name in SUBGRAPHS:
        graph.add_node(name, runner(name, router=router, audit=audit, limits=limits))
        graph.add_edge(previous, name)
        previous = name
    graph.add_edge(previous, END)
    return graph.compile(), limits


def run_once(run_id: str, targets: dict[str, Any], offline: bool = True,
             router: Router | None = None, limits: dict | None = None) -> RunState:
    """One whole run. OFFLINE (the default) skips every provider without a key."""
    router = router or Router(offline=offline)
    audit = Audit(run_id=run_id)
    graph, limits = build_supervisor(router, audit, limits)
    audit.log("supervisor.start", targets={key: len(value) for key, value in targets.items()},
              offline=offline, providers=[p.id for p in router.usable()])
    result = graph.invoke({"run_id": run_id, "targets": targets, "findings": []})
    findings = result.get("findings", [])
    audit.log("supervisor.done", findings=len(findings), value_usd=sum(f.value_usd for f in findings))
    return RunState(run_id=run_id, findings=findings,
                    spent={name: limits["per_subgraph"][name]["budget"] for name in result.get("selected", [])})
