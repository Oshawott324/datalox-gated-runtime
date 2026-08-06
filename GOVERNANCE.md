# Governance

Datalox Gated Runtime uses a maintainer-led governance model.

## Roles

- **Contributors** propose issues, documentation, tests, and code changes.
- **Maintainers** review changes, manage releases, triage security reports, and
  protect the public data boundary.

Maintainer status is earned through sustained, technically sound contributions
and responsible handling of security and provider-data boundaries. Existing
maintainers decide additions and removals by documented consensus.

## Decisions

Routine changes are decided through pull-request review. Changes to the security
model, licensing, public data policy, wire contracts, or runtime live-action
boundary require approval from at least two maintainers and a durable design note.

No maintainer may unilaterally publish restricted provider evidence. Ambiguous
redistribution or sensitivity classifications fail closed.

## Releases

Maintainers cut tagged releases only from a protected branch after CI, package,
secret, dependency, public-tree, and offline-demo checks pass. Release notes must
describe compatibility changes and known limitations.

## Project scope

The canonical scope is [`docs/what-we-are-building.md`](docs/what-we-are-building.md).
Governance changes must not silently redefine the project as a benchmark catalog,
provider clone, or model-training system.
