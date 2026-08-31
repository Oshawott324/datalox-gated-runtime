from __future__ import annotations

import json
from pathlib import Path

from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime.provider_runtime import build_provider_runtime_from_world

PROVIDER_ID = "example_provider"
PROVIDER_AUTHORITY = "api.provider.example"
EPISODE_ID = "episode-1"


def build_stateful_provider_bundle(
    tmp_path: Path,
    *,
    authority: str = PROVIDER_AUTHORITY,
) -> Path:
    source = create_valid_bundle(tmp_path / "source-world")
    bundle = tmp_path / "provider-bundle"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id=PROVIDER_ID,
        authorities=(authority,),
        episode_id=EPISODE_ID,
    )
    return bundle


def write_replay_provider_config(tmp_path: Path) -> Path:
    path = tmp_path / "source-gate-config.json"
    path.write_text(
        json.dumps(
            {
                "config_id": "example_provider_replay",
                "response_cases": [
                    {
                        "case_id": "example:records:list",
                        "method": "GET",
                        "path": "/v1/records",
                        "status_code": 200,
                        "body": {"data": [{"id": "rec_1"}]},
                    }
                ],
                "audit_rules": [],
                "policy": {
                    "deny": [
                        {
                            "method": "POST",
                            "path_prefix": "/v1/records",
                            "reason_code": "example_replay_only",
                            "message": "This provider fixture is replay-only.",
                        }
                    ],
                    "shadow_write": [],
                    "live_capture": [],
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path
