# Data Release Policy

The Apache-2.0 license applies to the public source code and explicitly released
synthetic assets. It does not automatically grant rights to provider responses,
documentation snapshots, tenant data, or other third-party material stored near
the code.

## Classifications

Every tracked data artifact has exactly one distribution classification:

- **public** — self-authored or redistribution-cleared material included in the
  generated public source tree;
- **restricted** — provider- or documentation-derived material retained for
  internal development but excluded from public source;
- **private** — runtime output, tenant-scoped evidence, or sensitive operational
  material that must not be published.

Unknown classification fails closed. A public URL or unauthenticated API does not
by itself establish redistribution rights.

## Required evidence for public classification

A public data entry must record:

- the exact artifact path and SHA-256 digest;
- origin and capture or generation date;
- copyright or source license where applicable;
- the legal or contractual redistribution basis;
- sensitivity and tenant-data review;
- whether provider payload bytes are present;
- sanitization and secret-scan outcome;
- grounding level and known gaps.

Synthetic fixtures must state that they are self-authored and must not reproduce
provider payloads or real personal data.

## Release construction

`release/data-classification.json` is the private-source inventory.
`release/public-release.json` defines the non-data public boundary. The release
builder includes only files explicitly classified as public and writes a
content-hashed `PUBLIC_SOURCE_MANIFEST.json` into the generated tree.

```bash
python scripts/public_release.py check
python scripts/public_release.py build --out /tmp/datalox-public
```

The checker fails when:

- a tracked data path is absent from the classification manifest;
- a manifest entry refers to a missing path;
- a public artifact has incomplete release metadata;
- a public file contains a local-machine path;
- a path matches conflicting release rules.

## Restricted evidence

Restricted behavior evidence is part of Datalox's provider-grounding corpus. It
may be used by private tests and compilation but is never copied into a public
source build. Public catalog summaries may disclose provider names, program
counts, grounding labels, and content hashes without disclosing raw payloads or
business-logic programs.

The private superset must retain the exact restricted artifact when a grounding
claim depends on it. A digest or normalized summary pointing to an untracked
operator path is provenance for missing data, not durable provider evidence.

Redaction is not a redistribution license and is not sufficient by itself to
promote an artifact from restricted to public.

## Harness exports

HUD, Harbor, OCI, or other harness projections are packaging operations, not
distribution reviews. Runtime-only compilation omits authoring evidence,
captures, trajectories, and source manifests, but executable state and declared
runtime data can still be provider-derived. An export therefore inherits the
most restrictive classification of its source world. Operator-generated
exports must stay outside the repository and public release unless every
included artifact is separately cleared and classified.
