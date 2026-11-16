from lib.llm.judges import judge
from lib.llm.router import Router
from lib.schemas import BypassMatrix, Judgement


def test_the_local_expert_answers_without_a_key():
    router = Router(offline=True, cache=__import__("pathlib").Path("/tmp/agentic-cache-1"))
    assert [p.id for p in router.usable()] == ["offline"]
    result: BypassMatrix = router.complete("oauth_matrix", "m", BypassMatrix,
                                           {"redirect_uri": "https://a.example/cb"})
    assert len(result.cases) >= 12


def test_the_second_call_is_served_from_the_cache(tmp_path):
    router = Router(offline=True, cache=tmp_path)
    router.complete("oauth_matrix", "m", BypassMatrix, {"redirect_uri": "https://a.example/cb"})
    calls = router.calls
    router.complete("oauth_matrix", "m", BypassMatrix, {"redirect_uri": "https://a.example/cb"})
    assert router.calls == calls


def test_self_consistency_takes_the_majority_and_names_agreement():
    class Fixed:
        def __init__(self, answers):
            self.answers = answers

        def complete(self, purpose, prompt, schema, context=None):
            return self.answers.pop(0)

    accepting = Judgement(verdict="accept", reasons=["ok"], confidence=0.9)
    rejecting = Judgement(verdict="reject", reasons=["no"], confidence=0.9)
    result = judge(Fixed([accepting, accepting, rejecting]), "dep_judge", "p")
    assert result.verdict == "accept" and result.confidence == 0.667


def test_a_tie_is_unsure():
    class Fixed:
        def __init__(self, answers):
            self.answers = answers

        def complete(self, purpose, prompt, schema, context=None):
            return self.answers.pop(0)

    accepting = Judgement(verdict="accept", reasons=["ok"], confidence=0.9)
    unsure = Judgement(verdict="unsure", reasons=["?"], confidence=0.3)
    result = judge(Fixed([accepting, unsure]), "dep_judge", "p", n=2)
    assert result.verdict == "unsure"
