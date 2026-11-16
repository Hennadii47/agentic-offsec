import pytest
from pydantic import ValidationError

from lib import ETHICS
from lib.schemas import Canary, Ecosystem, Finding, Judgement


def test_canary_signature_must_be_hex():
    with pytest.raises(ValidationError):
        Canary(name="a", ecosystem=Ecosystem.npm, version="1", signature="NOTHEX", beacon_url="https://b")


def test_ethics_line_never_reaches_evidence():
    with pytest.raises(ValidationError):
        Finding(subgraph="c_cloud", kind="aws", target="x", evidence=ETHICS, confidence=0.5)
    Finding(subgraph="c_cloud", kind="aws", target="x", evidence="key AKIA...:20", confidence=0.5)


def test_judgement_needs_a_reason():
    with pytest.raises(ValidationError):
        Judgement(verdict="accept", reasons=[], confidence=0.9)
    assert Judgement(verdict="accept", reasons=["why"], confidence=0.9).verdict == "accept"


def test_extra_fields_are_refused():
    with pytest.raises(ValidationError):
        Finding(subgraph="a_supply_chain", kind="k", target="t", evidence="e", surprise=1)
