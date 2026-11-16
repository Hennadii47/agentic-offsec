from lib import ETHICS
from lib.opsec import Audit, RateLimiter, Signer, fingerprint, user_agent, load_limits


def test_signer_roundtrip_and_tamper():
    signer = Signer.from_key("k")
    signature = signer.sign("pkg", "1.0.0")
    assert signer.verify("pkg", "1.0.0", signature)
    assert not signer.verify("pkg", "1.0.1", signature)


def test_rate_limiter_waits_only_when_it_must():
    clock = {"now": 0.0}
    slept = []
    limiter = RateLimiter(1.0, clock=lambda: clock["now"], sleep=lambda s: (slept.append(s), clock.update(now=clock["now"] + s)))
    assert limiter.wait() == 0.0
    clock["now"] = 0.4
    assert limiter.wait() == 0.6
    clock["now"] = 5.0
    assert limiter.wait() == 0.0


def test_every_audit_record_carries_the_ethics_line(tmp_path):
    audit = Audit(run_id="t", path=tmp_path / "a.jsonl")
    audit.log("x.harvest", rows=3)
    audit.log("x.emit", findings=1)
    assert all(record["ethics"] == ETHICS for record in audit.records)
    assert audit.actions() == ["x.harvest", "x.emit"]
    assert (tmp_path / "a.jsonl").read_text().count(ETHICS) == 2


def test_fingerprint_never_carries_the_secret():
    secret = "AKIAIOSFODNN7EXAMPLE"
    mark = fingerprint(secret)
    assert mark == "AKIA...MPLE:20"
    assert secret not in mark
    assert mark.endswith(f":{len(secret)}")


def test_user_agent_is_stable_per_seed():
    limits = load_limits()
    assert user_agent(limits, "a") == user_agent(limits, "a")
    assert user_agent(limits, "a") in limits["http"]["user_agents"]
