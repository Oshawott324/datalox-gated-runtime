from __future__ import annotations

import argparse
import json
from pathlib import Path

from datalox_gated_runtime.harness_adapters import build_harbor_adapter

ROOT = Path(__file__).resolve().parents[3]
INTEGRATION = Path(__file__).resolve().parent
ENV = ROOT / "envs" / "incident_customer_coordination_v0"
EPISODE_ID = "incident-customer-coordination-00"
ACTOR_ROLES = ("incident_commander", "support_owner", "communications")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the shareable Harbor incident-coordination task."
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = build_harbor_adapter(
        env_dir=ENV,
        out_dir=args.out,
        project_root=ROOT,
        episode_id=EPISODE_ID,
        actor_roles=ACTOR_ROLES,
        readme_text=(INTEGRATION / "README.md").read_text(encoding="utf-8"),
        solution_dir=INTEGRATION / "solution",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
