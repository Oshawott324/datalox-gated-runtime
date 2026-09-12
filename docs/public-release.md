# Public Release Runbook

A public release is built from an allowlisted source tree; the private repository
remains the superset containing restricted provider evidence.

## Required commands

```bash
uv sync --frozen --extra dev
uv run ruff check . --select E4,E7,E9,F
uv run pytest -q
uv run python scripts/public_release.py check
uv run python scripts/demo/offline-world-smoke.py
uv build
```

Build and test the exact public source tree:

```bash
rm -rf .tmp/public-source
uv run python scripts/public_release.py build --out .tmp/public-source
uv run python scripts/public_release.py verify-built --source .tmp/public-source
```

`verify-built` validates the manifest and file set, checks public-code lint and
formatting, runs the complete public test suite and credential-free demo, and
builds the wheel and source distribution from the generated tree. Classified
data roots are content-hashed and are intentionally excluded from formatter
rewrites.

The private superset may contain restricted provider payloads and must not
become the public Git history. Scan the exact generated tree before its first
commit:

```bash
gitleaks dir --redact=100 --config .gitleaks.toml .tmp/public-source
```

After the generated tree becomes the public repository, every CI run scans its
complete Git history with `gitleaks git`. Never attach the private superset's Git
objects, branches, tags, or pull-request refs to the public remote.

## Acceptance conditions

- all tracked data is classified and only public entries are exported;
- the entire Git history passes the secret scan;
- tests, lint, formatting, and package build pass from a fresh checkout;
- the wheel installs in an empty environment and `datalox-gate --help` works;
- the offline demo proves mutation, deterministic verification, functional reset,
  and replay equivalence without credentials or network access;
- public documentation contains no private paths or unsupported fidelity claims;
- release artifacts include a source manifest, checksums, SBOM, and build
  provenance.

Do not change repository visibility until the generated public tree has been
reviewed and the old private Git history is guaranteed not to become reachable
from the public remote.

## Reviewed experiment evidence

An experiment snapshot is a GitHub release, not an implicit runtime version or
PyPI publication. Publish its runner from the verified public source tree.
Keep raw controller output outside Git and derive an explicitly bounded public
view only after inspecting its source rights and contents.

For the Verifiers repeated-run experiment:

- retain the original private native audit and collection unchanged;
- include every scheduled run in the declared completed cohort;
- record each public artifact with the same digest, origin, date, license,
  redistribution basis, sensitivity, payload, sanitization and grounding fields
  required by this policy, in `PUBLIC_EVIDENCE_MANIFEST.json`;
- run `datalox-dirty-public-evidence --source REVIEWED_DIRECTORY` and scan the
  expanded directory with Gitleaks before archiving it;
- publish the evidence archive and its checksum file alongside the exact
  public source manifest/archive, runtime SBOM and publication provenance;
- download the public asset and run the documented offline check again.

The public checker validates the declared provider/tool projection. Original
native-file hashes are commitments to withheld evidence, not substitutes for
an independent native audit. State this limit on the result page. The
publication provenance records the checks actually performed; distinguish a
publisher-generated record from a CI-signed build attestation.
