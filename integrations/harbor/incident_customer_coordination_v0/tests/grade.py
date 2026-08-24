from __future__ import annotations

import json
import math
from pathlib import Path


VERDICT_PATH = Path("/var/lib/datalox/verdict.json")
OUTPUT_DIR = Path("/logs/verifier")
EXPECTED = {'package_content_sha256': 'sha256:19280e925e9eb428139c74b069d099871f891766598011afc322aea30519303c', 'source_manifest_sha256': 'sha256:472a24e667cd1ef0d9b86c3fcd0c6a47e6f16bffca21afb0469d45e2850c3fab', 'world_id': 'incident_customer_coordination_v0', 'bundle_version': '1.0.0', 'episode_id': 'incident-customer-coordination-00', 'task_id': 'incident-customer-coordination-00'}


def _valid_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def _reward(verdict: object) -> float:
    if not isinstance(verdict, dict):
        return 0.0
    required_text = ("schema_version", "world_id", "bundle_version", "episode_id", "task_id")
    if any(not isinstance(verdict.get(field), str) or not verdict[field] for field in required_text):
        return 0.0
    if verdict["schema_version"] != "datalox_world_package_verdict_v1":
        return 0.0
    if any(verdict.get(field) != expected for field, expected in EXPECTED.items()):
        return 0.0
    if not _valid_digest(verdict.get("package_content_sha256")):
        return 0.0
    if not _valid_digest(verdict.get("source_manifest_sha256")):
        return 0.0
    if not _valid_digest(verdict.get("run_export_sha256")):
        return 0.0
    audit = verdict.get("audit")
    if not isinstance(audit, dict):
        return 0.0
    if not isinstance(audit.get("passed"), bool):
        return 0.0
    if not _valid_digest(audit.get("sha256")):
        return 0.0
    if audit.get("reward_source") not in {"binary_audit", "world_verifier"}:
        return 0.0
    failure_codes = audit.get("failure_codes")
    if not isinstance(failure_codes, list) or any(not isinstance(code, str) for code in failure_codes):
        return 0.0
    reward = audit.get("reward")
    if isinstance(reward, bool) or not isinstance(reward, (int, float)):
        return 0.0
    score = float(reward)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        return 0.0
    if audit["passed"] and score <= 0.0:
        return 0.0
    if not audit["passed"] and score >= 1.0:
        return 0.0
    return score


def grade(
    verdict_path: Path = VERDICT_PATH,
    output_dir: Path = OUTPUT_DIR,
) -> float:
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        verdict = None
    score = _reward(verdict)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "reward.json").write_text(
        json.dumps({"datalox": score}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return score


if __name__ == "__main__":
    grade()
