"""Custom rules for the shapes that make a build step malicious."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "scripts" / "sast" / "rules"


def load_rules(folder: Path | None = None) -> list[dict]:
    rows: list[dict] = []
    for path in sorted((folder or RULES).glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        for rule in data.get("rules", []):
            rule["source"] = path.name
            rows.append(rule)
    return rows


def scan_text(text: str, path: str = "<text>", rules: list[dict] | None = None) -> list[dict]:
    hits = []
    for rule in rules if rules is not None else load_rules():
        pattern = re.compile(rule["pattern"], re.M)
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            hits.append({"rule": rule["id"], "severity": rule.get("severity", "warn"),
                         "path": path, "line": line, "snippet": match.group(0)[:160],
                         "message": rule.get("message", "")})
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(errors="replace"), str(path))


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(folder: Path) -> list[dict]:
    """The real semgrep when it is installed, our rules when it is not."""
    if semgrep_available():
        result = subprocess.run(["semgrep", "--config", str(RULES), "--json", str(folder)],
                                capture_output=True, text=True, timeout=300)
        import json
        return json.loads(result.stdout or "{}").get("results", [])
    rows = []
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.suffix in {".sh", ".yml", ".yaml", ".js", ".ts", ".py"}:
            rows.extend(scan_file(path))
    return rows
