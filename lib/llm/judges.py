"""Self-consistency: ask N times, take the verdict the majority can defend."""
from __future__ import annotations

from collections import Counter
from typing import Any, Type

from pydantic import BaseModel

from lib.schemas import Judgement


def judge(router, purpose: str, prompt: str, context: dict[str, Any] | None = None,
          n: int = 3, schema: Type[BaseModel] = Judgement) -> Judgement:
    answers: list[Judgement] = [router.complete(purpose, prompt, schema, context, variant=f"sample-{index}")
                                for index in range(n)]
    tally = Counter(answer.verdict for answer in answers)
    verdict, count = tally.most_common(1)[0]
    if list(tally.values()).count(count) > 1:
        verdict = "unsure"
    reasons: list[str] = []
    for answer in answers:
        for reason in answer.reasons:
            if reason not in reasons:
                reasons.append(reason)
    return Judgement(verdict=verdict, reasons=reasons[:5] or ["no reason offered"],
                     confidence=round(count / n, 3))
