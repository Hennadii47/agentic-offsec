"""Golden sets. Each eval measures accuracy on labelled evidence and fails under 90%."""
from __future__ import annotations

from pathlib import Path

import pytest

from graphs.supervisor import priority, run_once
from lib import cloud, plugins
from lib.deps import from_package_json, missing_internal
from lib.opsec import load_limits
from lib.schemas import Dependency, Ecosystem

THRESHOLD = 0.9


def accuracy(correct: int, total: int) -> float:
    return correct / total if total else 1.0


def test_eval_dependency_candidates(root):
    rows = from_package_json(root / "fixtures/repo-npm/package.json")
    rows += [Dependency(name="sber-tools", version="", ecosystem=Ecosystem.pypi),
             Dependency(name="secure-lib", version="1.2.3", ecosystem=Ecosystem.pypi)]
    labelled = {"@yandex/cloud-sdk": True, "@sber/ui-kit": True, "@ozon/internal-api": True,
                "react": False, "typescript": False, "sber-tools": True, "secure-lib": False}
    found = {candidate.name for candidate in missing_internal(rows, ["@yandex/", "@sber/", "@ozon/"])}
    score = accuracy(sum(1 for name, expected in labelled.items() if (name in found) == expected), len(labelled))
    assert score >= THRESHOLD, f"dependency eval {score:.2f}"


def test_eval_cloud_kind_detection(root):
    labelled = {
        ("terraform.tfstate", "aws"), ("terraform.tfstate", "gcp"),
        ("kubeconfig", "k8s"), (".env", "yandex"), (".env", "db"), (".env", "ssh"),
    }
    hits = set()
    for filename in {"terraform.tfstate", "kubeconfig", ".env"}:
        for key in cloud.scan(root / "fixtures/cloud" / filename):
            hits.add((filename, key.kind))
    score = accuracy(sum(1 for pair in labelled if pair in hits), len(labelled))
    assert score >= THRESHOLD, f"cloud eval {score:.2f}"


def test_eval_plugin_verdicts(root):
    labelled = {"yandex-cloud-tools.vsix": "hostile", "clean-sql.vsix": "clean",
                "sber-plugin.jar": "watch"}
    correct = 0
    for name, expected in labelled.items():
        path = root / "fixtures/plugins" / name
        risk = plugins.scan_vsix(path) if path.suffix == ".vsix" else plugins.scan_jar(path)
        if expected == "watch":
            correct += int(risk.verdict in ("watch", "hostile"))
        else:
            correct += int(risk.verdict == expected)
    assert accuracy(correct, len(labelled)) >= THRESHOLD


def test_eval_oauth_family_coverage(root):
    from lib.oauth import bypass_matrix, complete_matrix, FAMILIES
    cases = bypass_matrix("https://app.example.com/cb")
    coverage = complete_matrix(cases)
    score = accuracy(sum(1 for family in FAMILIES if coverage[family]), len(FAMILIES))
    assert score >= THRESHOLD


def test_eval_supervisor_priority_is_value_per_second(root):
    import yaml
    limits = load_limits()
    pricing = yaml.safe_load((root / "configs/pricing.yaml").read_text())
    order = priority(limits, pricing)
    assert order[0] == "c_cloud" and order[-1] == "a_supply_chain"
    assert set(order) == {"a_supply_chain", "b_oauth", "c_cloud", "d_plugins"}


def test_eval_whole_run(root, tmp_path):
    targets = {
        "repos": [str(root / "fixtures/repo-npm")],
        "files": [str(path) for path in sorted((root / "fixtures/cloud").iterdir())],
        "clients": [{"id": "esia", "redirect_uri": "https://esia.example.ru/cb", "scope": "openid"}],
        "plugins": [str(path) for path in sorted((root / "fixtures/plugins").iterdir())],
        "org_prefixes": ["@yandex/", "@sber/", "@ozon/"],
    }
    run = run_once("eval-run", targets, offline=True)
    assert run.findings, "a run over the fixtures must find something"
    kinds = {finding.subgraph for finding in run.findings}
    assert "c_cloud" in kinds and "a_supply_chain" in kinds
    assert all(finding.value_usd >= 0 for finding in run.findings)
    assert all("Understand and follow" not in finding.evidence for finding in run.findings)


def test_eval_audit_trail_exists(root):
    path = root / "audits" / "eval-run.jsonl"
    assert path.exists(), "a run must leave its ledger"
    lines = path.read_text().strip().splitlines()
    assert len(lines) >= 4
    assert any('"supervisor.done"' in line for line in lines)
