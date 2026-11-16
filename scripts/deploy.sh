#!/usr/bin/env bash
# One command from a clone to a running hunt. --dry-run prints every step and touches nothing.
set -euo pipefail
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

say() { printf '\n== %s\n' "$*"; }
run() { if [[ $DRY -eq 1 ]]; then printf '   would: %s\n' "$*"; else "$@"; fi; }

say "check the toolchain"
for tool in gh node python3; do
  command -v "$tool" >/dev/null || { echo "missing $tool"; exit 1; }
  printf '   %-8s %s\n' "$tool" "$(command -v "$tool")"
done

say "preflight"
run .venv/bin/python scripts/preflight.py || { echo "code is not ready; stopping"; exit 1; }

say "python environment"
run python3 -m venv .venv
run .venv/bin/pip install -q -e ".[dev]"

say "tests before anything leaves the machine"
run .venv/bin/python -m pytest tests -q

say "worker typecheck"
run bash -lc 'cd workers && npm install --no-audit --no-fund && npx tsc --noEmit'

say "secrets"
for name in GROQ_API_KEY GEMINI_API_KEY CANARY_KEY CF_API_TOKEN CF_ACCOUNT_ID; do
  if [[ -n "${!name:-}" ]]; then
    run gh secret set "$name" --body "${!name}"
  else
    printf '   %s not set here; set it in the repository settings\n' "$name"
  fi
done

say "workers"
run bash -lc 'cd workers && npx wrangler deploy || npx wrangler deploy --dry-run'

say "queues and schedules"
run gh workflow enable evals.yml
run gh workflow enable sast.yml
run gh workflow enable nightly_hunt.yml
run gh workflow enable canary_publish.yml

say "done"
[[ $DRY -eq 1 ]] && echo "   (dry run: nothing was changed)"
