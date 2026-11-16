"""Everything that keeps a run polite, attributable and auditable."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from lib import ETHICS

ROOT = Path(__file__).resolve().parent.parent


def load_limits(path: Path | None = None) -> dict:
    return yaml.safe_load((path or ROOT / "configs/limits.yaml").read_text())


class RateLimiter:
    """A minimum interval between requests, with the clock injectable so a test needs no sleep."""

    def __init__(self, min_seconds: float, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.min_seconds = float(min_seconds)
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> float:
        now = self._clock()
        slept = 0.0
        if self._last is not None:
            delay = self.min_seconds - (now - self._last)
            if delay > 0:
                self._sleep(delay)
                slept = delay
                now = self._clock()
        self._last = now
        return slept


@dataclass
class Audit:
    """One JSONL record per action. Every record carries the ethics line; nothing else does."""

    run_id: str
    path: Path | None = None
    records: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = self.path or ROOT / "audits" / f"{self.run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, **fields) -> dict:
        record = {"run_id": self.run_id, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "action": action, "ethics": ETHICS, **fields}
        self.records.append(record)
        with self.path.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def actions(self) -> list[str]:
        return [record["action"] for record in self.records]


@dataclass
class Signer:
    """A canary is only useful if a hit proves it came from us."""

    secret: bytes

    @classmethod
    def from_key(cls, key: str) -> "Signer":
        return cls(key.encode())

    def sign(self, name: str, version: str) -> str:
        return hmac.new(self.secret, f"{name}@{version}".encode(), hashlib.sha256).hexdigest()

    def verify(self, name: str, version: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(name, version), signature)


def user_agent(limits: dict, seed: str = "") -> str:
    """A stable UA per seed, so one actor looks like one browser for a whole run."""
    pool = limits["http"]["user_agents"]
    index = int(hashlib.sha256(seed.encode()).hexdigest(), 16) % len(pool)
    return pool[index]


def fingerprint(secret: str) -> str:
    """A handle for a credential that can be written down without writing the credential."""
    body = secret.strip()
    return f"{body[:4]}...{body[-4:]}:{len(body)}" if len(body) > 8 else f"{body[:1]}...:{len(body)}"
