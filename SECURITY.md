# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, credential exposure,
or sensitive evidence disclosure. Use GitHub's **Security → Report a
vulnerability** flow for this repository. Include the affected version, a
minimal reproduction, impact, and any evidence needed to confirm the report.

Maintainers will acknowledge a complete report as soon as practical, coordinate
validation privately, and publish a remediation and advisory when disclosure is
safe. Please do not access provider or user data beyond what is necessary to
demonstrate the issue.

## Supported versions

Security fixes are provided for the latest tagged minor release. The default
branch may contain unreleased changes and is not a stable support channel.

## Security boundary

Datalox sits between an agent and API or MCP tools. Its security goals are:

- route each call through an explicit, fail-closed policy decision;
- keep live provider writes inexpressible in the runtime;
- require both a declared live-capture rule and an operator flag for live GETs;
- inject credentials from operator-controlled environment variables;
- never forward agent-supplied authentication, cookie, or secret headers;
- preserve an append-only execution ledger and deterministic verifier evidence;
- avoid exposing hidden verifier inputs or mutable world storage to the agent;
- treat provider responses, run exports, and forensic records as potentially
  sensitive even after ordinary secret redaction.

Provider sandbox writes, when explicitly authorized for behavior authoring, run
through a separate utility and account boundary. They are not a runtime feature.

## Threat model

The runtime assumes the agent, task text, tool arguments, provider responses,
captured artifacts, and imported packs may be hostile. Relevant threats include:

- path traversal, symlink substitution, and unsafe artifact extraction;
- credential forwarding or accidental persistence;
- policy bypass through ambiguous route matching or alternate tool surfaces;
- replay confusion, generated-identifier substitution, and evidence tampering;
- hidden-state or verifier leakage;
- unbounded responses, malformed JSON, duplicate keys, and binary payloads;
- concurrent state mutation, partial completion, and reset contamination;
- sensitive values retained in logs, captures, or exported case bundles.

The host operating Datalox remains responsible for OS isolation, filesystem
permissions, network egress policy, provider-account scoping, and protecting the
directory containing runs and restricted evidence.

## Data handling

Run directories and provider evidence must be treated as sensitive by default.
Do not commit runtime outputs. Public artifacts must pass the classification and
release checks described in [`docs/data-release-policy.md`](docs/data-release-policy.md).
Redaction reduces accidental disclosure; it does not prove that an artifact is
safe or legally redistributable.

## Known limitations

Datalox does not prove the authenticity or completeness of upstream provider
responses. A replay-complete run proves that the local environment fulfilled its
declared cases, not that the environment is behaviorally identical to a provider.
Grounding claims require the separate evidence contract documented in
[`docs/provider-behavior-grounding.md`](docs/provider-behavior-grounding.md).
