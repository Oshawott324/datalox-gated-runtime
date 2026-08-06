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
