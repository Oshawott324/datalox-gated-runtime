# Contributing

Thank you for helping improve Datalox Gated Runtime.

## Development setup

Python 3.11 or newer is required. The locked development environment uses `uv`:

```bash
git clone <repository-url>
cd datalox-gated-runtime
uv sync --frozen --extra dev
uv run pytest -q
```

`pip install -e '.[dev]'` is also supported for local development, but CI and
release builds use the committed lock file.

## Required checks

Before opening a pull request, run:

```bash
uv run ruff check . --select E4,E7,E9,F
uv run pytest -q
uv run python scripts/public_release.py check
uv run python scripts/public_release.py build --out .tmp/public-source
uv run python scripts/public_release.py verify-built --source .tmp/public-source
```

`verify-built` checks formatting for every distributable Python file outside the
classified data roots, then runs the public tests, offline demo, and package
build. Format changed Python files with `uv run ruff format <paths>` before
running the gate.

Changes to the synthetic reference world must also pass:

```bash
uv run python scripts/demo/offline-world-smoke.py
uv run datalox-gate env admit-world --env envs/commerce_support_ops_v0 --json
```

## Design constraints

- Preserve the explicit gate-decision model and structured error codes.
- Runtime live writes must remain inexpressible.
- Do not forward agent-supplied credentials upstream.
- Keep provider grounding, replay completion, and world admission as distinct
  claims.
- Prefer deterministic filesystem and SQLite-backed contracts over hidden
  services.
- Do not add provider-derived data without a distribution classification.
- New behavior must include tests that exercise failure and denial paths, not
  only a happy path.

## Pull requests

Keep changes focused and explain the contract being changed. Include tests,
documentation, and any schema compatibility impact. Pull requests that modify a
wire format must state whether the change is backward compatible and update the
versioned schema or migration notes.

Contributors certify the Developer Certificate of Origin by adding a sign-off to
each commit:

```bash
git commit -s
```

The sign-off means you have the right to submit the contribution under this
project's license. See <https://developercertificate.org/>.

## Provider data

Do not submit raw provider responses, credentials, tenant identifiers, customer
data, or sandbox write transcripts in a normal pull request. Start with a public
issue describing the proposed source and intended grounding. Maintainers will
decide whether the material belongs in the public tree, a restricted evidence
store, or nowhere.
