"""Strict runtime binding for an admitted Composition Pack and Provider Set v2."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from datalox_gated_runtime.composition.admission import (
    LoadedCompositionAdmission,
    _AdmissionReleaseContract,
    _load_composition_admission_from_contracts,
)
from datalox_gated_runtime.composition.pack import (
    LoadedCompositionPack,
    _ProviderReleaseContract,
    _load_composition_pack_from_contracts,
)
from datalox_gated_runtime.composition.session import CompositionRuntimeRelease
from datalox_gated_runtime.rollout.provider_set import (
    LoadedMaterializedRolloutProviderSetV2,
    load_materialized_rollout_provider_set_v2,
)


@dataclass(frozen=True)
class LoadedRuntimeComposition:
    """One admitted composition bound to exact materialized release profiles."""

    provider_set: LoadedMaterializedRolloutProviderSetV2
    pack: LoadedCompositionPack
    admission: LoadedCompositionAdmission
    releases: Mapping[str, CompositionRuntimeRelease]


def load_runtime_composition(
    *,
    provider_set: LoadedMaterializedRolloutProviderSetV2,
    pack_dir: Path,
    admission_path: Path,
) -> LoadedRuntimeComposition:
    """Revalidate all runtime bytes without requiring the full OCI release store.

    The caller cannot supply release JSON directly. The release capabilities are
    derived only from a complete, strictly reloaded Provider Set v2
    materialization whose selected runtime, admission, manifest, and config
    digests have already been checked together.
    """

    if not isinstance(provider_set, LoadedMaterializedRolloutProviderSetV2):
        raise TypeError("provider_set must be a strict materialized Provider Set v2")
    reloaded = load_materialized_rollout_provider_set_v2(provider_set.root)

    pack_contracts: dict[str, _ProviderReleaseContract] = {}
    admission_contracts: dict[str, _AdmissionReleaseContract] = {}
    runtime_releases: dict[str, CompositionRuntimeRelease] = {}
    for binding in reloaded.bindings:
        selected = binding.provider
        config = binding.release_config
        pack_contracts[selected.provider_id] = _ProviderReleaseContract(
            provider_id=selected.provider_id,
            release_manifest_sha256=selected.release_manifest_sha256,
            config=config,
        )
        admission_contracts[selected.provider_id] = _AdmissionReleaseContract(
            provider_id=selected.provider_id,
            release_manifest_sha256=selected.release_manifest_sha256,
            config=config,
            allowed_profile_ids=frozenset({selected.profile_id}),
        )
        runtime_releases[selected.provider_id] = (
            CompositionRuntimeRelease.from_admitted_rollout_binding(binding)
        )

    pack = _load_composition_pack_from_contracts(
        pack_dir,
        provider_contracts=MappingProxyType(pack_contracts),
    )
    admission = _load_composition_admission_from_contracts(
        admission_path,
        pack=pack,
        provider_contracts=MappingProxyType(admission_contracts),
    )
    return LoadedRuntimeComposition(
        provider_set=reloaded,
        pack=pack,
        admission=admission,
        releases=MappingProxyType(runtime_releases),
    )
