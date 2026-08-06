# Provider Core Completeness

Provider core completeness answers one narrow question: does a provider-scoped
environment implement every operation family in its declared,
official-source-grounded operational scope strongly enough for agents to use
the core workflow safely and deterministically?

It is independent from three other results:

- `replay_complete` means the recorded replay cases execute without misses;
- world admission means a composed world passes reset, trajectory, parity,
  provenance, safety, and export checks; and
- provider-observed fidelity means a particular call has G2, G3, or G4
  execution evidence.

None of those results implies provider core completeness.

## Declaration

A provider environment opts into the strict pass with
`provider_core_coverage.json`. The declaration contains no `status`, `pass`, or
`complete` field. The checked inventory computes the result.

The v1 declaration records:

- provider id, versioned scope, primary workflow, and official scope sources;
- whether the official provider surface is mutable or genuinely read-only;
- core families, each marked primary or supporting, with official capability
  kinds: `read`, `write`, or `non_mutating_process`;
- every implemented operation with method, effect, source refs, and a separate
  `observed` or `not_observed` provider-execution claim;
- every write family and one `local_shadow` assurance per write, including
  implementation, reset, and invalid/duplicate/atomicity evidence, plus either
  an official read-after-write operation or an explicit `direct_write_response`
  observation with local evidence when the exact provider collection has no
  official GET;
- one `local_replay` assurance per non-mutating POST/query/job/process;
- source-grounded adjacent exclusions; and
- explicit blocking or nonblocking gaps.

The declaration is filesystem-backed and lives beside the compiled
environment. Local evidence uses `repo/path.py::test_or_function` references so
the validator can prove that both the file and anchor exist.

## Machine Pass

The evaluator derives `core_complete` only when:

- declared operations exactly cover the world tool inventory and families;
- every family and capability has official source grounding;
- every primary family with official write capability has at least one
  provider-shaped write;
- a mutable provider has writes, while a source-grounded read-only provider has
  none;
- every write is a deterministic local shadow with official grounding, reset,
  and negative/atomicity evidence, and is observed either through an official
  read-after-write operation or, where no such read exists, through a direct
  write response backed by local evidence;
- every non-mutating process is represented as credential-free local replay;
- observed-provider claims point separately to G2 or stronger provider
  execution evidence;
- no primary family is hidden as an exclusion; and
- no blocking core gap remains.

Live writes are not an allowed execution mode.

Machine validation is deliberately limited to the declared,
official-source-grounded scope. It cannot prove that an author chose a complete
scope from declaration text alone. Acceptance review must compare the scope to
the official provider surface and reject any omitted primary family rather than
shrinking scope until the check passes.

## Commands

Refresh and check the portfolio report without failing undeclared legacy
assets:

```bash
python scripts/report_api_building_blocks.py --write
python scripts/report_api_building_blocks.py --check
```

Require one provider to pass the strict gate:

```bash
python scripts/report_api_building_blocks.py --check \
  --require-core-complete openlmis_supply_chain_v0
```

Modeled cross-provider composite worlds are `not_applicable`; they are not
counted as undeclared providers. Imported source-pack drafts remain a separate
construction phase until they become registered provider environments.
