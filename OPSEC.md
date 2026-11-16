# OPSEC

What keeps a run attributable, polite, and reversible.

## Attribution

- One Cloudflare account, one GitHub organisation, one Telegram bot **per subgraph**. A burn
  in one does not spend the others.
- The beacon is HMAC-signed with `CANARY_KEY`; a hit proves the install came from a build
  that resolved our package, not from a crawler.
- User-Agent is stable per run seed (`lib.opsec.user_agent`), so one actor looks like one
  browser for the whole run instead of a rotating swarm.
- Egress through Cloudflare WARP when the worker fetches; the worker's own address is never
  the runner's.

## Politeness

- `configs/limits.yaml` is the only place a budget lives; prompts cannot raise it.
- `RateLimiter` enforces a minimum interval per subgraph, and the supervisor refuses to start
  a subgraph whose budget is spent.
- No retries against a target that answered 4xx: a 404 is an answer.
- One canary per ecosystem per run. A flood is what gets an account noticed.

## Evidence

Every action is one JSONL record: `run_id`, `at`, `action`, its fields, and the ethics line.
Records are append-only, one file per run, uploaded as a workflow artefact.

A credential is written down as a **fingerprint** (`AKIA...MPLE:20`), never as itself, so a
ledger can be shared without a rotation.

## The rules of engagement, as code

1. Only targets you are authorised to test. `configs/targets.yaml` is a list, not a licence.
2. Read-only where possible: validate a key, never use one to change state.
3. No persistence, no lateral movement, no exfiltration beyond the proof.
4. Untrusted artefacts are parsed, never executed — there is no sandbox here.
5. A run leaves the audit ledger, or it did not happen.

> Understand and follow applicable laws; you are responsible for your own choices.
