# agentic-offsec

Four research subgraphs over one supervisor, built to answer a single question about a
software supply chain: **where is a name that a build will resolve, and who answers for it.**

Not a CVE scanner. A CVE scanner asks what is broken; this asks what is *unowned*.

```
                supervisor (priority = value / second of budget)
                 │
   ┌─────────────┼──────────────┬──────────────┐
   A supply     B oauth        C cloud        D plugins
   chain        logic          exposure       supply chain
```

## The four subgraphs

| | input | what it produces | why it is worth a minute |
|---|---|---|---|
| **A supply chain** | a repository | `CanaryCandidate` → signed `Canary` | a dependency the build imports, no registry serves, and a CI runner will install |
| **B OAuth logic** | a client configuration | `BypassCase` matrix, judged | authorisation business logic, where scanners do not look |
| **C cloud** | `.tfstate`, kubeconfig, `.env` | ranked `CloudKey` fingerprints | infrastructure written down where anyone can read it |
| **D plugins** | `.vsix`, `.jar` | `PluginRisk` | permissions against need, and who can push an update |

Every finding carries a confidence and a price from `configs/pricing.yaml`; the supervisor
spends the next minute where value per second is highest.

## Quickstart (15 minutes, free tiers)

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests -q          # 37 tests, no network, no keys
bash scripts/deploy.sh --dry-run             # what the deploy would do
bash scripts/deploy.sh                       # venv, tests, secrets, workers, workflows
```

When no model key is present the router uses **the local expert** in `lib/local_experts.py`:
the same judgement written as rules over the evidence. A run without keys is still a run,
not a mock — and `tests/evals/` measures it against labelled fixtures at a 90% floor.

## What one run looks like

```bash
.venv/bin/python -c "
from graphs.supervisor import run_once
run = run_once('manual', {'repos': ['fixtures/repo-npm'], 'files': ['fixtures/cloud/.env'],
                          'clients': [{'id': 'esia', 'redirect_uri': 'https://esia.example/cb'}],
                          'plugins': ['fixtures/plugins/yandex-cloud-tools.vsix'],
                          'org_prefixes': ['@yandex/', '@sber/']})
print(len(run.findings), sum(f.value_usd for f in run.findings))
"
```

Every action lands in `audits/<run>.jsonl`, each record carrying the ethics line. The line
never travels to a target: `Finding` refuses evidence that contains it.

## Layout

```
graphs/            supervisor + four subgraphs (LangGraph)
lib/               schemas, router, judges, opsec, and one engine per vector
prompts/           judges/, actors/, fewshots/ — 50 recorded examples
workers/           beacon.ts, oauth-fuzzer.ts, monetization.ts + wrangler.toml
scripts/sast/      our own Semgrep rules for a build step that turns hostile
configs/           targets, limits, pricing, providers
fixtures/          labelled evidence the evals measure against
tests/unit         behaviour  ·  tests/evals  golden sets at a 90% floor
```

## Limits, stated plainly

- The offline expert is rule-based: it will not invent a bypass the rules do not know.
- `b_oauth` generates and judges a matrix; it does not send a request. Sending belongs to
  `workers/oauth-fuzzer.ts`, against targets you are authorised to touch.
- `c_cloud` reads files you point it at. Fetching buckets by dork is deliberately not built in.
- No sandbox. Untrusted artefacts are parsed, never executed.

## The one rule

> Understand and follow applicable laws; you are responsible for your own choices.

Signed into every audit record; never sent to a target.
