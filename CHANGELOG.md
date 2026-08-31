# Changelog

All notable changes to Datalox Gated Runtime will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses semantic versioning for tagged public releases.

## [Unreleased]

### Added

- Public-source release boundary and per-artifact data classification.
- Security, contribution, governance, support, and conduct policies.
- Reproducible dependency lock, CI checks, and package smoke testing.
- Credential-free mutation, reset, replay, and verifier demonstration.
- A core-complete Hamilton STAR dry-run provider through PyLabRobot 0.2.1,
  including native SDK routing, stateful writes, provider-shaped failures, and
  explicit physical-hardware exclusions.
- Provider-neutral per-step principal contexts for multi-role differential
  traces, with an exact passing OpenLMIS write/denial/duplicate/readback proof.
- Provider-native identity policies for stateful runtime bundles, including
  credential commitments, provider-shaped auth failures, and spoof protection.
- Ordered, content-addressed task-free provider sets and a trusted node-local
  pool for concurrent isolated rollout leases.
- A current veRL V1 `ToolAgentLoop` adapter and familiar GRPO example that keep
  provider URLs unchanged and return veRL training outputs without mutation.
- Per-session provider state/workspace retention, 32-sibling isolation checks,
  shutdown cleanup, and provider-state evidence exports for parallel rollouts.

### Changed

- Replaced the internal long-form README with a concise public entry point.
- Versioned the reference trace and world target contracts for explicit
  per-step principals while keeping behavior-harvest engines immutable.

## [0.1.0] - 2026-08-01

### Added

- Initial gated HTTP and MCP execution runtime.
- Replay, shadow state, denials, ledgers, audits, and run exports.
- Stateful world bundle, admission, session, and verifier contracts.
- Provider probe and behavior-harvest authoring contracts.
