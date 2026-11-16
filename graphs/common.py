"""State and helpers every subgraph shares."""
from __future__ import annotations

from typing import Any, TypedDict

from lib.schemas import Finding


class State(TypedDict, total=False):
    run_id: str
    targets: dict[str, Any]
    findings: list[Finding]
    notes: list[str]
    selected: list[str]
    budget: dict[str, int]
    # The working set. LangGraph carries only declared keys, so a node that
    # hands evidence to the next one must name it here or lose it.
    _deps: list
    _plan: Any
    _canaries: list
    _files: list
    _keys: list
    _clients: list
    _matrices: list
    _kept: list
    _plugins: list
    _risks: list
    _artifacts: list
    _hits: list
    _probes: list


def value_of(router, kind: str) -> int:
    from lib.schemas import PricePoint
    point: PricePoint = router.complete("monetize", f"price {kind}", PricePoint, {"kind": kind})
    return point.usd


def add_finding(state: State, finding: Finding) -> State:
    findings = list(state.get("findings", []))
    findings.append(finding)
    return {**state, "findings": findings}
