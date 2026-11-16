"""The prompt an actor actually sends: system + rules + recorded examples + the evidence.

prompts/ is the authority. This module is the only place that reads it, so a
change of wording is a file change, not a code change.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from lib import fewshot

ROOT = Path(__file__).resolve().parent.parent
JUDGES = ROOT / "prompts" / "judges"

# purpose -> (judge file, few-shot tag)
PURPOSES = {
    "dep_judge": ("dep", "dep"),
    "canary_plan": ("canary", "canary"),
    "oauth_matrix": ("oauth", "oauth"),
    "oauth_judge": ("oauth", "oauth"),
    "cloud_extract": ("cloud", "cloud"),
    "plugin_audit": ("plugin", "plugin"),
    "monetize": (None, None),
}


def judge_of(purpose: str) -> dict:
    name, _ = PURPOSES.get(purpose, (None, None))
    if name is None:
        return {"system": "Answer with JSON only.", "rules": []}
    path = JUDGES / f"{name}.yaml"
    return yaml.safe_load(path.read_text()) if path.exists() else {"system": "Answer with JSON only.", "rules": []}


def schema_hint(schema) -> str:
    """The shape the answer must have, written from the model itself."""
    return json.dumps(schema.model_json_schema(), indent=None)[:1800]


def build(purpose: str, context: dict, schema, shots: int = 3, seed: str = "") -> str:
    judge = judge_of(purpose)
    _, tag = PURPOSES.get(purpose, (None, None))
    examples = fewshot.select(tag, shots, seed) if tag else []
    parts = [judge.get("system", "").strip()]
    rules = judge.get("rules") or []
    if rules:
        parts.append("Rules:\n" + "\n".join(f"- {rule}" for rule in rules))
    if examples:
        parts.append("Recorded examples (the shape, not the answer):\n" + fewshot.render(examples))
    parts.append("Evidence:\n" + json.dumps(context, ensure_ascii=False, default=str)[:6000])
    parts.append("Answer with one JSON object matching this schema, and nothing else:\n" + schema_hint(schema))
    return "\n\n".join(part for part in parts if part)
