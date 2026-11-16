from lib.plugins import scan_jar, scan_vsix


def test_startup_activation_with_remote_fetch_in_an_obfuscated_bundle_is_hostile(root):
    risk = scan_vsix(root / "fixtures/plugins/yandex-cloud-tools.vsix")
    assert risk.verdict == "hostile"
    assert risk.remote_fetch and risk.obfuscated
    assert any("startup" in permission for permission in risk.permissions)


def test_a_language_plugin_that_touches_nothing_is_clean(root):
    assert scan_vsix(root / "fixtures/plugins/clean-sql.vsix").verdict == "clean"


def test_a_jar_that_reaches_the_network_is_watched(root):
    risk = scan_jar(root / "fixtures/plugins/sber-plugin.jar")
    assert risk.market == "jetbrains" and risk.remote_fetch
    assert risk.verdict in ("watch", "hostile")
