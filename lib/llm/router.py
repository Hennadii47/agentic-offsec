"""One call shape for every actor; providers chosen from config, never faked."""
from __future__ import annotations

import json
import os
import time
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Type

import yaml
from pydantic import BaseModel, ValidationError

from lib import local_experts

ROOT = Path(__file__).resolve().parent.parent.parent
# Groq answers 403 to "Python-urllib/3.15" and 200 to a browser-shaped one; the
# header is not decoration, it is what gets the request past the WAF.
AGENT = "Mozilla/5.0 (compatible; agentic-offsec/0.1; +https://nodecode.ai)"
JSON_BLOCK = re.compile(r"\{.*\}|\[.*\]", re.S)

def first_json(text: str) -> str:
    """The first complete JSON value in TEXT, balanced and string-aware.

    A model wraps an answer in prose, in fences, or in two objects; a greedy
    regex takes all of it and then fails to parse. This walks the text once.
    """
    body = text.strip()
    if body.startswith("```"):
        body = body.split("```")[1] if "```" in body[3:] else body[3:]
        body = body.split("\n", 1)[1] if body.lower().startswith(("json", "yaml")) else body
    for opener in ("{", "["):
        start = body.find(opener)
        if start < 0:
            continue
        depth, in_string, escape = 0, False, False
        for index in range(start, len(body)):
            char = body[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char in "{[":
                depth += 1
            elif char in "}]":
                depth -= 1
                if depth == 0:
                    return body[start:index + 1]
    return ""



class RouterError(RuntimeError):
    pass


@dataclass
class Provider:
    id: str
    kind: str
    model: str
    base_url: str = ""
    key_env: str = ""
    rpm: int = 0


class Router:
    """Answers a pydantic model for a named purpose.

    A provider without a key is skipped. When no remote provider is usable the
    local expert for the purpose answers -- a deterministic implementation of the
    same judgement, so a run without keys is still a run, not a mock.
    """

    def __init__(self, config: Path | None = None, cache: Path | None = None, offline: bool = False):
        data = yaml.safe_load((config or ROOT / "configs/providers.yaml").read_text())
        self.providers = [Provider(**row) for row in data["providers"]]
        self.temperature = data.get("temperature", 0.2)
        self.max_retries = data.get("max_retries", 2)
        self.offline = offline
        self.cache = cache or ROOT / ".cache" / "llm"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.calls = 0
        self._last_call: dict[str, float] = {}
        self.waited = 0.0

    def _throttle(self, provider: "Provider") -> None:
        """The rpm in configs/providers.yaml is a promise to the provider, so keep it."""
        if not provider.rpm:
            return
        interval = 60.0 / float(provider.rpm)
        last = self._last_call.get(provider.id)
        if last is not None:
            delay = interval - (time.monotonic() - last)
            if delay > 0:
                time.sleep(delay)
                self.waited += delay
        self._last_call[provider.id] = time.monotonic()

    def usable(self) -> list[Provider]:
        """OFFLINE means the local expert alone, even when keys are in the environment."""
        if self.offline:
            return [p for p in self.providers if p.kind == "local"]
        rows = [p for p in self.providers
                if p.kind != "local" and os.environ.get(p.key_env)]
        return rows or [p for p in self.providers if p.kind == "local"]

    def complete(self, purpose: str, prompt: str, schema: Type[BaseModel],
                 context: dict[str, Any] | None = None, variant: str = "") -> BaseModel:
        """VARIANT separates samples of the same question, so a self-consistency
        vote asks the model three times instead of reading its own cache."""
        context = context or {}
        # The key carries the evidence: two runs that ask the same question of
        # different inputs must not share an answer.
        key = hashlib_of(purpose, prompt, schema.__name__, variant,
                         json.dumps(context, sort_keys=True, default=str))
        cached = self.cache / f"{key}.json"
        if cached.exists():
            return schema.model_validate_json(cached.read_text())
        last: Exception | None = None
        for provider in self.usable():
            for attempt in range(self.max_retries):
                try:
                    self._throttle(provider)
                    raw = (local_experts.answer(purpose, schema, context) if provider.kind == "local"
                           else self._remote(provider, prompt))
                    answer = schema.model_validate(raw)
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    cached.write_text(answer.model_dump_json())
                    self.calls += 1
                    return answer
                except urllib.error.HTTPError as error:
                    last = error
                    if error.code == 429:
                        after = error.headers.get("retry-after") if error.headers else None
                        time.sleep(float(after) if after else min(2 ** attempt * 3, 30))
                except (ValidationError, RouterError, ValueError, OSError, json.JSONDecodeError) as error:
                    last = error
        raise RouterError(f"no provider answered {purpose}: {last}")

    def _remote(self, provider: Provider, prompt: str) -> Any:
        key = os.environ.get(provider.key_env, "")
        if provider.kind == "openai-compatible":
            body = json.dumps({"model": provider.model, "temperature": self.temperature,
                               # gpt-oss answers with its reasoning first; 2000 leaves an
                               # empty content, so the ceiling has to cover both.
                               "max_tokens": 4000,
                               "messages": [{"role": "user", "content": prompt}]}).encode()
            request = urllib.request.Request(provider.base_url.rstrip("/") + "/chat/completions", data=body,
                                             headers={"content-type": "application/json",
                                                      "user-agent": AGENT,
                                                      "authorization": f"Bearer {key}"})
            with urllib.request.urlopen(request, timeout=60) as answer:
                payload = json.loads(answer.read())
            text = payload["choices"][0]["message"]["content"]
        elif provider.kind == "gemini":
            url = f"{provider.base_url}/models/{provider.model}:generateContent?key={key}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}],
                               "generationConfig": {"temperature": self.temperature}}).encode()
            request = urllib.request.Request(url, data=body,
                                             headers={"content-type": "application/json", "user-agent": AGENT})
            with urllib.request.urlopen(request, timeout=60) as answer:
                payload = json.loads(answer.read())
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
        else:
            raise RouterError(f"unknown provider kind {provider.kind}")
        candidate = first_json(text)
        if not candidate:
            raise RouterError("answer carried no JSON")
        return json.loads(candidate)


def hashlib_of(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]
