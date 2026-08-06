## Contract changed

Describe the runtime, schema, world, provider, or documentation contract changed.

## Evidence

- [ ] Tests cover success, failure, and denial behavior where applicable.
- [ ] `ruff check .` and `ruff format --check .` pass.
- [ ] `pytest -q` passes.
- [ ] `python scripts/public_release.py check` passes.
- [ ] Provider-derived data is classified and contains no credentials or tenant data.
- [ ] Wire-format compatibility and migration impact are documented.

## Security and data boundary

Explain any new network access, credential use, filesystem write, live action, or
public/restricted data decision. Write “none” when the change adds none.
