"""One call shape for every actor; providers chosen from config, never faked."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Type

import yaml
from pydantic import BaseModel, ValidationError

from lib import local_experts

ROOT = Path(__file__).resolve().parent.parent.parent
JSON_BLOCK = re.compile(r"\{.*\}|\[.*\]", re.S)


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

    def usable(self) -> list[Provider]:
        rows = []
        for provider in self.providers:
            if provider.kind == "local" and not self.offline:
                continue
            if provider.kind != "local" and not os.environ.get(provider.key_env):
                continue
            rows.append(provider)
        return rows or [p for p in self.providers if p.kind == "local"]

    def complete(self, purpose: str, prompt: str, schema: Type[BaseModel], context: dict[str, Any] | None = None) -> BaseModel:
        context = context or {}
        # The key carries the evidence: two runs that ask the same question of
        # different inputs must not share an answer.
        key = hashlib_of(purpose, prompt, schema.__name__,
                         json.dumps(context, sort_keys=True, default=str))
        cached = self.cache / f"{key}.json"
        if cached.exists():
            return schema.model_validate_json(cached.read_text())
        last: Exception | None = None
        for provider in self.usable():
            for attempt in range(self.max_retries):
                try:
                    raw = (local_experts.answer(purpose, schema, context) if provider.kind == "local"
                           else self._remote(provider, prompt))
                    answer = schema.model_validate(raw)
                    cached.write_text(answer.model_dump_json())
                    self.calls += 1
                    return answer
                except (ValidationError, RouterError, ValueError) as error:
                    last = error
        raise RouterError(f"no provider answered {purpose}: {last}")

    def _remote(self, provider: Provider, prompt: str) -> Any:
        key = os.environ.get(provider.key_env, "")
        if provider.kind == "openai-compatible":
            body = json.dumps({"model": provider.model, "temperature": self.temperature,
                               "messages": [{"role": "user", "content": prompt}]}).encode()
            request = urllib.request.Request(provider.base_url.rstrip("/") + "/chat/completions", data=body,
                                             headers={"content-type": "application/json",
                                                      "authorization": f"Bearer {key}"})
            with urllib.request.urlopen(request, timeout=60) as answer:
                payload = json.loads(answer.read())
            text = payload["choices"][0]["message"]["content"]
        elif provider.kind == "gemini":
            url = f"{provider.base_url}/models/{provider.model}:generateContent?key={key}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}],
                               "generationConfig": {"temperature": self.temperature}}).encode()
            request = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as answer:
                payload = json.loads(answer.read())
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
        else:
            raise RouterError(f"unknown provider kind {provider.kind}")
        block = JSON_BLOCK.search(text)
        if not block:
            raise RouterError("answer carried no JSON")
        return json.loads(block.group(0))


def hashlib_of(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]
