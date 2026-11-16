.PHONY: test check run clean

test:
	.venv/bin/python -m pytest tests -q

check: test
	cd workers && NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--max-old-space-size=6370" npx tsc --noEmit

run:
	.venv/bin/python -c "from graphs.supervisor import run_once; import yaml, pathlib; t=yaml.safe_load(pathlib.Path('configs/targets.yaml').read_text()); r=run_once('manual', {'repos': t['supply_chain']['repos'], 'clients': t['oauth']['clients'], 'files': [], 'plugins': [], 'org_prefixes': t['supply_chain']['org_prefixes']}); print(len(r.findings), 'findings')"

clean:
	rm -rf .cache audits/*.jsonl workers/node_modules
