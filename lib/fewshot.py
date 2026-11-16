"""Few-shot examples as files. Ten or more per actor, selected by tag and stable per seed."""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "prompts" / "fewshots"


def load_all(folder: Path | None = None) -> list[dict]:
    folder = folder or EXAMPLES
    rows: list[dict] = []
    for path in sorted(folder.glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        for example in data.get("examples", []):
            rows.append({"id": example["id"], "tags": example.get("tags", []),
                         "input": example["input"], "output": example["output"], "source": path.name})
    return rows


def select(tag: str, k: int = 3, seed: str = "") -> list[dict]:
    """K examples carrying TAG, ordered by a hash of the seed so a run is reproducible."""
    rows = [row for row in load_all() if tag in row["tags"]]
    rows.sort(key=lambda row: hashlib.sha256(f"{seed}:{row['id']}".encode()).hexdigest())
    return rows[:k]


def render(rows: list[dict]) -> str:
    parts = []
    for row in rows:
        parts.append("INPUT:\n" + str(row["input"]) + "\nOUTPUT:\n" + str(row["output"]).strip())
    return "\n---\n".join(parts)
