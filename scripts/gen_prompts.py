"""Writes prompts/ from the tables below: every example is a real shape an actor meets."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

JUDGES = {
    "dep": {
        "system": "You decide whether a dependency name is a canary candidate: imported by a build, "
                  "served by no registry, and therefore installable by whoever publishes first.",
        "rules": ["one organisation prefix is stronger evidence than a familiar-looking name",
                  "a package that is published already is contested; reject it",
                  "a wildcard or missing version is what makes the install resolve to us"],
        "schema": "Judgement",
    },
    "canary": {
        "system": "You write the canary package plan: which names to publish, in which ecosystem, "
                  "with a beacon that proves the install came from a CI runner.",
        "rules": ["never claim a name that answers on the public registry",
                  "the beacon must be signed, so a hit is attributable",
                  "one canary per ecosystem per run, not a flood"],
        "schema": "CanaryPlan",
    },
    "oauth": {
        "system": "You read an OAuth client's public configuration and name the business-logic bypasses "
                  "its authorisation server is likely to accept.",
        "rules": ["a redirect check that is a suffix rather than a dot boundary is a code leak",
                  "state without binding is decoration",
                  "PKCE plain is PKCE absent for an intercepting party"],
        "schema": "BypassMatrix",
    },
    "cloud": {
        "system": "You read infrastructure artefacts as code and rank what an operator could reach with them.",
        "rules": ["a service-account JSON is admin until a policy says otherwise",
                  "a kubeconfig is cluster-admin until a RoleBinding says otherwise",
                  "never copy a secret into evidence; a fingerprint is enough"],
        "schema": "CloudKeys",
    },
    "plugin": {
        "system": "You judge whether an editor extension's permissions exceed what its feature needs.",
        "rules": ["activation on startup plus a remote fetch is the exfiltration shape",
                  "high entropy in a small bundle means a decoder is coming",
                  "an abandoned publisher is an acquisition target, not a verdict"],
        "schema": "PluginVerdict",
    },
}

ACTORS = {
    "canary_author": "You turn a canary plan into publishable packages: name, version, beacon, signature.",
    "bypass_matrix": "You turn a client configuration into concrete authorisation requests a tester can send.",
    "exfil_planner": "You describe, in steps, what a compromised runner would copy and where it would send it.",
    "plugin_auditor": "You read an extension bundle and report what it can touch against what it needs.",
}

EXAMPLES = [
    ("dep-1", ["dep"], {"name": "@yandex/cloud-sdk", "version": "*", "published": 0},
     {"verdict": "accept", "reasons": ["scoped to an organisation and unpinned"], "confidence": 0.9}),
    ("dep-2", ["dep"], {"name": "@sber/ui-kit", "version": "", "published": 0},
     {"verdict": "accept", "reasons": ["no version and no registry record"], "confidence": 0.85}),
    ("dep-3", ["dep"], {"name": "react", "version": "^18.2.0", "published": 1},
     {"verdict": "reject", "reasons": ["published, pinned, contested"], "confidence": 0.95}),
    ("dep-4", ["dep"], {"name": "@ozon/internal-api", "version": "latest", "published": 0},
     {"verdict": "accept", "reasons": ["latest resolves at install time"], "confidence": 0.88}),
    ("dep-5", ["dep"], {"name": "left-pad", "version": "*", "published": 1},
     {"verdict": "reject", "reasons": ["famous public package; a canary would be contested"], "confidence": 0.97}),
    ("dep-6", ["dep"], {"name": "internal-tools", "version": "", "published": 0},
     {"verdict": "unsure", "reasons": ["no prefix, so attribution is a guess"], "confidence": 0.4}),
    ("dep-7", ["dep"], {"name": "@tinkoff/design", "version": ">=0", "published": 0},
     {"verdict": "accept", "reasons": ["range with no lower bound"], "confidence": 0.8}),
    ("dep-8", ["dep"], {"name": "@vk/payments", "version": "1.2.3", "published": 0},
     {"verdict": "unsure", "reasons": ["pinned exactly, so a canary is only taken by a fresh install"], "confidence": 0.5}),
    ("dep-9", ["dep"], {"name": "@avito/tracking", "version": "^0.0.0", "published": 0},
     {"verdict": "accept", "reasons": ["^0.0.0 resolves to any patch"], "confidence": 0.82}),
    ("dep-10", ["dep"], {"name": "@mts/logger", "version": "", "published": 1},
     {"verdict": "reject", "reasons": ["published already"], "confidence": 0.93}),
    ("canary-1", ["canary"], {"candidates": ["@yandex/cloud-sdk"], "ecosystem": "npm"},
     {"package": "@yandex/cloud-sdk", "version": "99.0.0", "beacon": "https://beacon.example/c"}),
    ("canary-2", ["canary"], {"candidates": ["@sber/ui-kit"], "ecosystem": "npm"},
     {"package": "@sber/ui-kit", "version": "0.0.1", "beacon": "https://beacon.example/c"}),
    ("canary-3", ["canary"], {"candidates": ["sber-tools"], "ecosystem": "pypi"},
     {"package": "sber-tools", "version": "1.0.0", "beacon": "https://beacon.example/c"}),
    ("canary-4", ["canary"], {"candidates": ["yandex-maps-sdk"], "ecosystem": "cargo"},
     {"package": "yandex-maps-sdk", "version": "0.1.0", "beacon": "https://beacon.example/c"}),
    ("canary-5", ["canary"], {"candidates": ["github.com/ozon/kit"], "ecosystem": "go"},
     {"package": "github.com/ozon/kit", "version": "v9.9.9", "beacon": "https://beacon.example/c"}),
    ("canary-6", ["canary"], {"candidates": ["vk-pay"], "ecosystem": "pypi"},
     {"package": "vk-pay", "version": "3.0.0", "beacon": "https://beacon.example/c"}),
    ("canary-7", ["canary"], {"candidates": ["@avito/analytics"], "ecosystem": "npm"},
     {"package": "@avito/analytics", "version": "2.0.0-rc1", "beacon": "https://beacon.example/c"}),
    ("canary-8", ["canary"], {"candidates": ["@mts/logger"], "ecosystem": "npm"},
     {"package": "@mts/logger", "version": "0.0.0", "beacon": "https://beacon.example/c"}),
    ("canary-9", ["canary"], {"candidates": ["tinkoff-api"], "ecosystem": "pypi"},
     {"package": "tinkoff-api", "version": "1.1.1", "beacon": "https://beacon.example/c"}),
    ("canary-10", ["canary"], {"candidates": ["wildberries-sdk"], "ecosystem": "npm"},
     {"package": "wildberries-sdk", "version": "5.0.0", "beacon": "https://beacon.example/c"}),
    ("oauth-1", ["oauth"], {"redirect_uri": "https://app.example.com/cb", "scope": "openid"},
     {"case": "host suffix", "request": "redirect_uri=https://app.example.com/cb.attacker.tld"}),
    ("oauth-2", ["oauth"], {"redirect_uri": "https://id.example.ru/cb", "scope": "openid"},
     {"case": "userinfo confusion", "request": "redirect_uri=https://id.example.ru@attacker.tld/cb"}),
    ("oauth-3", ["oauth"], {"redirect_uri": "https://lk.example.ru/cb"},
     {"case": "path traversal", "request": "redirect_uri=https://lk.example.ru/cb/../x"}),
    ("oauth-4", ["oauth"], {"redirect_uri": "https://sso.example.ru/cb"},
     {"case": "state echoed", "request": "state=fixed"}),
    ("oauth-5", ["oauth"], {"redirect_uri": "https://sso.example.ru/cb"},
     {"case": "pkce plain", "request": "code_challenge_method=plain"}),
    ("oauth-6", ["oauth"], {"redirect_uri": "https://esia.example.ru/cb"},
     {"case": "scope escalation", "request": "scope=openid+docs+tax"}),
    ("oauth-7", ["oauth"], {"redirect_uri": "https://id.vk.com/cb"},
     {"case": "implicit response", "request": "response_type=token"}),
    ("oauth-8", ["oauth"], {"redirect_uri": "https://bank.example.ru/cb"},
     {"case": "federation confusion", "request": "issuer=https://attacker.tld"}),
    ("oauth-9", ["oauth"], {"redirect_uri": "https://gov.example.ru/cb"},
     {"case": "scheme downgrade", "request": "redirect_uri=http://gov.example.ru/cb"}),
    ("oauth-10", ["oauth"], {"redirect_uri": "https://mts.example.ru/cb"},
     {"case": "port variation", "request": "redirect_uri=https://mts.example.ru:8443/cb"}),
    ("cloud-1", ["cloud"], {"file": "terraform.tfstate", "match": "service_account"},
     {"kind": "gcp", "rank": 0, "note": "a service-account JSON in state"}),
    ("cloud-2", ["cloud"], {"file": "terraform.tfstate", "match": "AKIA"},
     {"kind": "aws", "rank": 0, "note": "an access key id in state"}),
    ("cloud-3", ["cloud"], {"file": "kubeconfig", "match": "client-key-data"},
     {"kind": "k8s", "rank": 1, "note": "a client key, so a cluster identity"}),
    ("cloud-4", ["cloud"], {"file": ".env", "match": "YC"},
     {"kind": "yandex", "rank": 0, "note": "a yandex cloud key"}),
    ("cloud-5", ["cloud"], {"file": "values.yaml", "match": "hvs."},
     {"kind": "vault", "rank": 2, "note": "a vault token"}),
    ("cloud-6", ["cloud"], {"file": ".env", "match": "postgres://"},
     {"kind": "db", "rank": 3, "note": "a database URL with credentials"}),
    ("cloud-7", ["cloud"], {"file": "id_rsa", "match": "BEGIN OPENSSH"},
     {"kind": "ssh", "rank": 4, "note": "a private key"}),
    ("cloud-8", ["cloud"], {"file": "ci.yml", "match": "AWS_SECRET_ACCESS_KEY"},
     {"kind": "aws", "rank": 0, "note": "a secret in a workflow file"}),
    ("cloud-9", ["cloud"], {"file": ".env", "match": "api_key"},
     {"kind": "generic", "rank": 5, "note": "an unclassified key"}),
    ("cloud-10", ["cloud"], {"file": "main.tf", "match": "tls_private_key"},
     {"kind": "ssh", "rank": 4, "note": "a generated private key in code"}),
    ("plugin-1", ["plugin"], {"activation": ["*"], "remote": True, "entropy": 5.9},
     {"verdict": "hostile", "reason": "startup activation plus a remote fetch in an obfuscated bundle"}),
    ("plugin-2", ["plugin"], {"activation": ["onLanguage:go"], "remote": False, "entropy": 4.2},
     {"verdict": "clean", "reason": "language activation only"}),
    ("plugin-3", ["plugin"], {"activation": ["*"], "remote": False, "entropy": 4.4},
     {"verdict": "unknown", "reason": "startup activation with no remote fetch"}),
    ("plugin-4", ["plugin"], {"activation": ["onCommand:x"], "remote": True, "entropy": 5.8},
     {"verdict": "watch", "reason": "a remote fetch in an obfuscated bundle"}),
    ("plugin-5", ["plugin"], {"activation": ["*"], "remote": True, "entropy": 5.0},
     {"verdict": "watch", "reason": "startup activation plus a fetch"}),
    ("plugin-6", ["plugin"], {"activation": ["onLanguage:sql"], "remote": True, "entropy": 5.9},
     {"verdict": "watch", "reason": "language plugin that decodes and fetches"}),
    ("plugin-7", ["plugin"], {"activation": [], "remote": False, "entropy": 4.0},
     {"verdict": "clean", "reason": "no activation, no network"}),
    ("plugin-8", ["plugin"], {"activation": ["*"], "remote": True, "entropy": 6.1},
     {"verdict": "hostile", "reason": "the classic exfiltration shape"}),
    ("plugin-9", ["plugin"], {"activation": ["onStartupFinished"], "remote": False, "entropy": 5.9},
     {"verdict": "unknown", "reason": "obfuscated but silent"}),
    ("plugin-10", ["plugin"], {"activation": ["workspaceContains:**/*.kt"], "remote": True, "entropy": 4.9},
     {"verdict": "watch", "reason": "workspace trigger with a fetch"}),
]


def main() -> None:
    judges = ROOT / "prompts" / "judges"
    actors = ROOT / "prompts" / "actors"
    shots = ROOT / "prompts" / "fewshots"
    for folder in (judges, actors, shots):
        folder.mkdir(parents=True, exist_ok=True)
    for name, body in JUDGES.items():
        (judges / f"{name}.yaml").write_text(yaml.safe_dump(body, sort_keys=False, allow_unicode=True))
    for name, system in ACTORS.items():
        (actors / f"{name}.yaml").write_text(yaml.safe_dump(
            {"system": system, "examples_from": f"prompts/fewshots/{name}.yaml"},
            sort_keys=False, allow_unicode=True))
    for name in ACTORS:
        tag = "canary" if name == "canary_author" else ("oauth" if name == "bypass_matrix" else (
            "cloud" if name == "exfil_planner" else "plugin"))
        rows = [{"id": rid, "tags": tags, "input": value, "output": out}
                for rid, tags, value, out in EXAMPLES if tag in tags]
        (shots / f"{name}.yaml").write_text(yaml.safe_dump({"examples": rows}, sort_keys=False, allow_unicode=True))
    print("judges", len(JUDGES), "actors", len(ACTORS), "examples", len(EXAMPLES))


if __name__ == "__main__":
    main()
