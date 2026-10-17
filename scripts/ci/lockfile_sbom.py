#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 inventory from the committed lockfiles.

Only Python's standard library is needed (Python 3.11+). This is a source
dependency inventory, not an installed-product or container-image SBOM.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "Cargo.lock"
NPM = ROOT / "frontend/package-lock.json"
OUTPUT = ROOT / "sbom/lockfiles.spdx.json"
SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")


def package_id(ecosystem: str, identity: str) -> str:
    digest = hashlib.sha256(f"{ecosystem}\0{identity}".encode()).hexdigest()[:20]
    return f"SPDXRef-{ecosystem}-{digest}"


def package(name: str, version: str, spdx_id: str, checksum=None) -> dict:
    item = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if checksum:
        item["checksums"] = [checksum]
    return item


def cargo_packages(lock: dict) -> list[dict]:
    result = []
    for entry in lock["package"]:
        name, version = entry["name"], entry["version"]
        identity = f"{name}\0{version}\0{entry.get('source', 'workspace')}"
        checksum = entry.get("checksum")
        if checksum and not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError(f"invalid Cargo checksum for {name}")
        result.append(package(name, version, package_id("cargo", identity),
                              {"algorithm": "SHA256", "checksumValue": checksum} if checksum else None))
    return result


def npm_packages(lock: dict) -> list[dict]:
    if lock.get("lockfileVersion") != 3:
        raise ValueError("expected npm lockfile v3")
    result = []
    for path, entry in lock["packages"].items():
        if path == "":
            name = entry["name"]
        else:
            if not path.startswith("node_modules/"):
                raise ValueError(f"unexpected npm package path: {path}")
            name = path.rsplit("node_modules/", 1)[1]
        version = entry["version"]
        integrity = entry.get("integrity", "")
        checksum = None
        if integrity:
            if not integrity.startswith("sha512-"):
                raise ValueError(f"unsupported npm integrity for {path}")
            digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
            if len(digest) != 64:
                raise ValueError(f"invalid npm integrity for {path}")
            checksum = {"algorithm": "SHA512", "checksumValue": digest.hex()}
        result.append(package(name, version, package_id("npm", path), checksum))
    return result


def build(created: str) -> dict:
    cargo_bytes, npm_bytes = CARGO.read_bytes(), NPM.read_bytes()
    cargo = tomllib.loads(cargo_bytes.decode("utf-8"))
    npm = json.loads(npm_bytes)
    packages = cargo_packages(cargo) + npm_packages(npm)
    packages.sort(key=lambda p: (p["name"], p["versionInfo"], p["SPDXID"]))
    ids = [p["SPDXID"] for p in packages]
    if len(ids) != len(set(ids)) or not all(SPDX_ID.fullmatch(i) for i in ids):
        raise ValueError("duplicate or malformed SPDX package ID")
    digest = hashlib.sha256(cargo_bytes + b"\0" + npm_bytes).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "trust-platform-locked-source-dependencies",
        "documentNamespace": f"https://github.com/knehari/trust-platform/spdxdocs/lockfiles-{digest}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: trust-lockfile-sbom-1.0"],
            "comment": "Inventory of Cargo.lock and frontend/package-lock.json only. "
                       "No installed artifacts, containers, license conclusions, or runtime selection asserted.",
        },
        "packages": packages,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": i}
            for i in ids
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if committed SBOM differs from lockfiles")
    args = parser.parse_args()
    if args.check:
        existing = json.loads(OUTPUT.read_text())
        created = existing["creationInfo"]["created"]
    else:
        created = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expected = json.dumps(build(created), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if OUTPUT.read_text() != expected:
            print("SBOM differs from committed lockfiles; regenerate with scripts/ci/lockfile_sbom.py", file=sys.stderr)
            return 1
        print(f"SBOM current: {len(json.loads(expected)['packages'])} locked packages")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected)
        print(f"Wrote {OUTPUT.relative_to(ROOT)} with {len(json.loads(expected)['packages'])} locked packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
