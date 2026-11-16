#!/usr/bin/env python3
"""What is ready, and what is missing, before anyone believes a green run.

Two verdicts, because they fail for different reasons: CODE READY is about the
repository; DEPLOY READY is about this machine's accounts. The first must be
yes; the second is the operator's to fix, and each line says how.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def ok(label: str, good: bool, hint: str = "") -> tuple[str, bool, str]:
    return label, good, "" if good else hint


def check_code() -> list[tuple[str, bool, str]]:
    rows = []
    rows.append(ok("python >= 3.11", sys.version_info >= (3, 11), "install a newer interpreter"))
    rows.append(ok("package installed", importlib.util.find_spec("lib") is not None,
                   "pip install -e \".[dev]\""))
    rows.append(ok("configs present", all((ROOT / "configs" / name).exists()
                   for name in ("targets.yaml", "limits.yaml", "pricing.yaml", "providers.yaml", "publish.yaml", "send.yaml")),
                   "a config file is missing"))
    rows.append(ok("prompts present", len(list((ROOT / "prompts" / "fewshots").glob("*.yaml"))) >= 4,
                   "run scripts/gen_prompts.py"))
    try:
        result = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q"], cwd=ROOT,
                                capture_output=True, text=True, timeout=900)
        rows.append(ok("tests green", result.returncode == 0, (result.stdout or "").strip().splitlines()[-1:][0] if result.stdout else ""))
    except Exception as error:
        rows.append(ok("tests green", False, str(error)))
    workers = ROOT / "workers"
    rows.append(ok("worker deps", (workers / "node_modules").exists(), "cd workers && npm install"))
    return rows


def check_deploy() -> list[tuple[str, bool, str]]:
    rows = []
    rows.append(ok("git remote", bool(subprocess.run(["git", "remote"], cwd=ROOT,
                   capture_output=True, text=True).stdout.strip()),
                   "git remote add origin <url> && git push -u origin main"))
    gh = shutil.which("gh")
    logged = False
    if gh:
        logged = subprocess.run([gh, "auth", "status"], capture_output=True, text=True).returncode == 0
    rows.append(ok("gh authenticated", logged, "gh auth login"))
    rows.append(ok("wrangler available", shutil.which("wrangler") is not None,
                   "npm i -g wrangler (or let npx fetch it)"))
    for name in ("GROQ_API_KEY", "GEMINI_API_KEY", "CANARY_KEY", "CF_API_TOKEN", "CF_ACCOUNT_ID"):
        rows.append(ok(f"secret {name}", bool(os.environ.get(name)), f"gh secret set {name}"))
    return rows


def report(title: str, rows: list[tuple[str, bool, str]]) -> bool:
    print(f"\n{title}")
    width = max(len(row[0]) for row in rows)
    for label, good, hint in rows:
        mark = "ok  " if good else "MISS"
        print(f"  {mark}  {label:<{width}}  {hint}")
    return all(good for _, good, _ in rows)


def main() -> int:
    code_ready = report("CODE READY", check_code())
    deploy_ready = report("DEPLOY READY", check_deploy())
    print()
    print("code:   " + ("ready" if code_ready else "NOT ready"))
    print("deploy: " + ("ready" if deploy_ready else "needs the operator (see MISS lines)"))
    return 0 if code_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
