"""Stable contracts for harness-specific world-package adapters."""

ADAPTER_SCHEMA_VERSION = "datalox_harness_adapter_v1"
ADAPTER_MANIFEST = "DATALOX_ADAPTER.json"
HUD_VERSION = "0.6.12"
HARBOR_VERSION = "0.21.0"


class HarnessAdapterError(ValueError):
    """A canonical world package cannot be adapted to a target harness."""
