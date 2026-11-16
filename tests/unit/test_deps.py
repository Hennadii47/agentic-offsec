from pathlib import Path

from lib.deps import from_cargo, from_go_mod, from_package_json, from_requirements, missing_internal, scan_repo
from lib.schemas import Dependency, Ecosystem


def test_package_json_keeps_scope_and_version(root):
    rows = from_package_json(root / "fixtures/repo-npm/package.json")
    by_name = {row.name: row for row in rows}
    assert by_name["@yandex/cloud-sdk"].version == "*"
    assert by_name["typescript"].scope == "dev"
    assert by_name["react"].ecosystem is Ecosystem.npm


def test_requirements_ignores_comments_and_pins(root):
    rows = from_requirements(root / "fixtures/repo-py/requirements.txt")
    names = [row.name for row in rows]
    assert "sber-tools" in names and "tinkoff-api" in names
    assert all(not name.startswith("#") for name in names)


def test_go_and_cargo_parse(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\nrequire github.com/ozon/kit v9.9.9\n")
    (tmp_path / "Cargo.toml").write_text("[dependencies]\nyandex = \"0.1\"\n")
    assert from_go_mod(tmp_path / "go.mod")[0].name == "github.com/ozon/kit"
    assert from_cargo(tmp_path / "Cargo.toml")[0].ecosystem is Ecosystem.cargo


def test_only_prefixed_and_unpinned_names_are_candidates(root):
    rows = scan_repo(root / "fixtures/repo-npm") + scan_repo(root / "fixtures/repo-py")
    names = {row.name for row in missing_internal(rows, ["@yandex/", "@sber/", "@ozon/"])}
    assert names == {"@yandex/cloud-sdk", "@sber/ui-kit", "@ozon/internal-api", "sber-tools"}
    assert "react" not in names and "secure-lib" not in names


def test_a_pinned_prefixed_name_is_not_a_candidate():
    rows = [Dependency(name="@sber/ui-kit", version="1.2.3", ecosystem=Ecosystem.npm)]
    assert missing_internal(rows, ["@sber/"]) == []


def test_a_go_module_names_its_organisation_after_the_host():
    from lib.deps import carries_org
    assert carries_org("github.com/ozon/kit", ["ozon"])
    assert carries_org("github.com/ozontech/kit", ["ozon"]) is False
    assert carries_org("@sber/ui-kit", ["@sber/"]) is True
    assert carries_org("sberbank-api", ["@sber/"]) is False
