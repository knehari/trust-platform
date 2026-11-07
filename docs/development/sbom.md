# Lockfile SBOM (lab)

`sbom/lockfiles.spdx.json` is an SPDX 2.3 JSON inventory of every package entry
in `Cargo.lock` and `frontend/package-lock.json`, including platform-optional npm
packages and workspace roots. Package checksums come from the lockfiles when
present. The generator does not query registries, infer resolved runtime
dependencies, inspect built containers, or conclude that declared licenses are
correct. Those checks remain separate supply-chain work.

Regenerate after changing either lockfile with Python 3.11 or newer:

```sh
python3 scripts/ci/lockfile_sbom.py
python3 scripts/ci/lockfile_sbom.py --check
```

The generator assigns a document namespace from the exact lockfile bytes and
stable IDs to package records. `--check` retains the committed document's
creation timestamp and compares the complete generated JSON byte for byte;
GitHub Actions runs this on every PR and main push. A lockfile change without
an updated SBOM fails the gate. No credentials or registry URLs are copied
into the SBOM. This is evidence for TRUST-15, not a release attestation.
