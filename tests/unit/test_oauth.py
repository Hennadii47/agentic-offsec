from lib.oauth import bypass_matrix, complete_matrix


def test_every_family_is_represented():
    cases = bypass_matrix("https://app.example.com/cb", "client", "openid email")
    assert set(complete_matrix(cases).values()) == {True}
    assert len(cases) >= 12


def test_the_matrix_names_the_real_confusions():
    cases = {case.name: case for case in bypass_matrix("https://app.example.com/cb")}
    assert "@" in cases["userinfo confusion"].redirect_uri
    assert cases["host suffix"].redirect_uri.endswith(".attacker.tld")
    assert cases["pkce plain"].params["code_challenge_method"] == "plain"


def test_a_case_is_validated_by_its_schema():
    for case in bypass_matrix("https://a.example/cb"):
        assert case.family in {"redirect", "state", "pkce", "response_type", "scope", "federation"}
        assert case.rationale
