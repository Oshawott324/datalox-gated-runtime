"""Public projection tests use a model-free transport, never pilot data."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
import test_verifiers_repeat_end_to_end as cohort
from test_verifiers_repeat_native import _call, _response

native_transport = cohort.native_transport
native_launch = cohort.native_launch
public = importlib.import_module("datalox_dirty_integration.repeat_public")


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _refresh(root: Path) -> None:
    manifest = json.loads((root / "PUBLIC_EVIDENCE_MANIFEST.json").read_text())
    for entry in manifest["artifacts"]:
        entry["sha256"] = public.sha256_file(root / entry["path"])
    _write(root / "PUBLIC_EVIDENCE_MANIFEST.json", manifest)


@pytest.fixture
def bundle(tmp_path: Path, native_launch: dict) -> Path:
    native_launch["responses"] = [
        _response(tool_calls=[_call("clean", "list_products", offset=0, limit=10)]),
        _response(),
        _response(tool_calls=[_call("hostile", "list_products", offset=0, limit=10)]),
        _response(),
    ]
    config = cohort._config()
    source = tmp_path / "private"
    result = cohort.driver.run_experiment(config, source, spend_approved=True)
    assert result["status"] == "completed"
    root = tmp_path / "reviewed"
    root.mkdir()
    _write(root / "experiment.json", config.model_dump(mode="json"))
    rows = [
        public.project_slot(source / "slots" / slot.slot_id, config, slot)
        for slot in config.schedule
    ]
    (root / "rollouts.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    _write(root / "summary.json", public.summarize(rows))
    _write(
        root / "PUBLIC_EVIDENCE_MANIFEST.json",
        {
            "schema_version": "datalox_reviewed_repeat_evidence_v1",
            "scope": public.SCOPE,
            "source_commitments": {
                "experiment_file": public.sha256_file(root / "experiment.json"),
                "collection_file": "sha256:" + "1" * 64,
                "native_analysis_summary": "sha256:" + "2" * 64,
                "public_source_manifest": "sha256:" + "3" * 64,
            },
            "artifacts": [
                {
                    **{
                        key: "self-authored model-free test fixture" for key in public.REVIEW_FIELDS
                    },
                    "path": name,
                    "sha256": public.sha256_file(root / name),
                    "distribution": "public",
                    "contains_provider_payload": False,
                }
                for name in sorted(public.FILES)
            ],
        },
    )
    return root


def test_public_projection_rechecks_failed_tasks_without_inference(
    bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY")
    assert public.verify_public_bundle(bundle)["runs"] == 2
    assert public.main(["--source", str(bundle)]) == 0
    content = (bundle / "rollouts.jsonl").read_text()
    assert "encrypted_content" not in content
    assert "openai_responses_output" not in content
    assert "reasoning_content" not in content
    assert str(bundle.parent) not in content
    summary = json.loads((bundle / "summary.json").read_text())
    assert all(group["task_passes"] == 0 for group in summary["groups"])


@pytest.mark.parametrize(
    "mutation",
    [
        "omit_run",
        "reverse_runs",
        "observation",
        "tool_call",
        "score",
        "summary",
        "profile",
        "extra_prose",
    ],
)
def test_public_semantic_tampering_fails_after_file_hash_refresh(
    bundle: Path, mutation: str
) -> None:
    path = bundle / "rollouts.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if mutation == "omit_run":
        rows.pop()
    elif mutation == "reverse_runs":
        rows.reverse()
    elif mutation == "observation":
        rows[0]["episode_export"]["delivered_calls"][0]["observation"]["body"]["count"] = "50"
    elif mutation == "tool_call":
        tool = json.loads(rows[0]["tool_transcript"][0]["tool_calls"][0])
        tool["arguments"] = json.dumps({"offset": 10, "limit": 10})
        rows[0]["tool_transcript"][0]["tool_calls"][0] = json.dumps(tool)
    elif mutation == "score":
        rows[0]["verification"]["task_correctness"]["score"] = 1.0
    elif mutation == "profile":
        rows[0]["episode_manifest"]["profile"] = "hostile"
    elif mutation == "extra_prose":
        rows[0]["tool_transcript"][0]["content"] = "unreviewed assistant prose"
    else:
        _write(bundle / "summary.json", {"runs": 999})
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    _refresh(bundle)
    with pytest.raises(public.RepeatEvidenceError):
        public.verify_public_bundle(bundle)


@pytest.mark.parametrize(
    "mutation",
    ["digest", "extra_file", "symlink", "unreviewed", "empty_rights", "duplicate_artifact"],
)
def test_public_inventory_and_release_review_are_required(bundle: Path, mutation: str) -> None:
    path = bundle / "PUBLIC_EVIDENCE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    if mutation == "digest":
        manifest["artifacts"][0]["sha256"] = "sha256:" + "0" * 64
    elif mutation == "extra_file":
        (bundle / "extra").touch()
    elif mutation == "symlink":
        (bundle / "extra").symlink_to(bundle / "summary.json")
    elif mutation == "unreviewed":
        manifest["artifacts"][0]["distribution"] = "private"
    elif mutation == "empty_rights":
        manifest["artifacts"][0]["redistribution_basis"] = ""
    else:
        manifest["artifacts"][0] = manifest["artifacts"][1]
    _write(path, manifest)
    with pytest.raises(public.RepeatEvidenceError):
        public.verify_public_bundle(bundle)
