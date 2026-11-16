import pytest

from lib import assets, marketplace, net, sender
from lib.schemas import BypassCase


def case():
    return BypassCase(name="host suffix", family="redirect",
                      redirect_uri="https://app.example.com/cb.attacker.tld", rationale="why")


def fake(status=302, location="https://app.example.com/cb", body=b""):
    def transport(url, **_):
        return net.Response(url=url, status=status, headers={"location": location} if location else {}, body=body)
    return transport


def test_scope_is_a_host_list_not_a_prefix():
    assert net.allowed("https://id.example.ru/a", ["example.ru"])
    assert not net.allowed("https://evil.example.ru.attacker.tld/a", ["example.ru"])


def test_out_of_scope_is_refused_by_name():
    with pytest.raises(sender.OutOfScope) as error:
        sender.probe("https://evil.tld/a", "cid", case(), ["example.ru"], transport=fake())
    assert "evil.tld" in str(error.value)


def test_a_dry_run_sends_nothing_but_builds_the_request():
    result = sender.probe("https://id.example.ru/a", "cid", case(), ["example.ru"], dry_run=True)
    assert result.sent is False and "redirect_uri=" in result.url


def test_a_live_probe_records_the_location_it_was_sent_to():
    result = sender.probe("https://id.example.ru/a", "cid", case(), ["example.ru"],
                          transport=fake(), dry_run=False)
    assert result.sent and result.status == 302 and result.location.endswith("/cb")


def test_marketplace_and_asset_fetch_write_what_they_got(tmp_path):
    plugin, why = marketplace.fetch(marketplace.vsix_url("sber", "tools", "1.0.0"),
                                    tmp_path / "x.vsix", transport=fake(200, None, b"PK\x03\x04"))
    asset, _ = assets.fetch("https://example.ru/terraform.tfstate", tmp_path, transport=fake(200, None, b"{}"))
    assert plugin.exists() and plugin.read_bytes().startswith(b"PK")
    assert asset.name == "terraform.tfstate"


def test_a_missing_artefact_says_why(tmp_path):
    path, why = marketplace.fetch(marketplace.vsix_url("a", "b"), tmp_path / "y.vsix",
                                  transport=fake(404, None, b""))
    assert path is None and "404" in why
