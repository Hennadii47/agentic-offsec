import json
import tarfile

from lib.opsec import Signer
from lib.publish import build_npm, build_pypi, command_for, publish
from lib.schemas import Canary, Ecosystem


def canary(name="@sber/ui-kit", ecosystem=Ecosystem.npm, version="99.0.0"):
    signer = Signer.from_key("k")
    return Canary(name=name, ecosystem=ecosystem, version=version,
                  signature=signer.sign(name, version), beacon_url="https://beacon.example/c")


def test_npm_artifact_is_a_real_tarball_with_a_postinstall(tmp_path):
    artifact = build_npm(canary(), dist=tmp_path)
    assert artifact.path.exists() and artifact.sha256
    with tarfile.open(artifact.path) as archive:
        manifest = json.loads(archive.extractfile("package/package.json").read())
    assert manifest["name"] == "@sber/ui-kit"
    assert manifest["scripts"]["postinstall"].startswith("node beacon.js @sber/ui-kit 99.0.0")


def test_pypi_artifact_pings_during_install(tmp_path):
    artifact = build_pypi(canary(name="sber-tools", ecosystem=Ecosystem.pypi, version="0.0.1"), dist=tmp_path)
    with tarfile.open(artifact.path) as archive:
        setup = archive.extractfile("sber_tools-0.0.1/setup.py").read().decode()
    assert "class Ping(install)" in setup and "beacon.example" in setup


def test_dry_run_reports_the_command_and_touches_nothing(tmp_path):
    outcome = publish(build_npm(canary(), dist=tmp_path), dry_run=True)
    assert outcome["dry_run"] is True and outcome["published"] is False
    assert outcome["command"].startswith("npm publish")


def test_the_command_matches_the_ecosystem(tmp_path):
    npm = build_npm(canary(), dist=tmp_path)
    pypi = build_pypi(canary(name="sber-tools", ecosystem=Ecosystem.pypi, version="0.0.1"), dist=tmp_path)
    assert command_for(npm)[0] == "npm" and command_for(pypi)[0] == "twine"
