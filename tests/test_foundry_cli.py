from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

from test_provider_release_registry import _profile

from datalox_gated_runtime.cli import main
from datalox_gated_runtime.rollout.provider_set import (
    load_materialized_rollout_provider_set_v2,
)


def _run_json(arguments: list[str], capsys: object) -> dict[str, object]:
    with patch.object(sys, "argv", ["datalox-gate", *arguments, "--json"]):
        assert main() == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    return json.loads(captured.out)


def test_foundry_cli_builds_publishes_selects_and_materializes(
    tmp_path: Path, capsys: object
) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release_root = tmp_path / "release"
    built = _run_json(
        [
            "provider",
            "release-build",
            "--profile",
            profile.profile_id,
            str(profile.bundle_dir),
            str(profile.admission_path),
            "--release-version",
            "2026.08.25",
            "--out",
            str(release_root),
        ],
        capsys,
    )
    assert built["provider_id"] == "example_provider"
    assert built["profiles"] == ["default"]

    registry_root = tmp_path / "registry"
    assert _run_json(["provider", "registry-create", "--root", str(registry_root)], capsys) == {
        "registry": str(registry_root.resolve())
    }
    published = _run_json(
        [
            "provider",
            "registry-publish",
            "--root",
            str(registry_root),
            "--release",
            str(release_root),
        ],
        capsys,
    )
    reference = published["reference"]
    assert reference == "example_provider@2026.08.25"

    resolved = _run_json(
        [
            "provider",
            "registry-resolve",
            "--root",
            str(registry_root),
            "--reference",
            str(reference),
        ],
        capsys,
    )
    assert resolved["manifest_sha256"] == published["manifest_sha256"]

    provider_set_path = tmp_path / "provider-set.json"
    selected = _run_json(
        [
            "rollout",
            "provider-set-v2",
            "--registry",
            str(registry_root),
            "--provider",
            str(reference),
            "default",
            "--out",
            str(provider_set_path),
        ],
        capsys,
    )
    assert selected["providers"] == ["example_provider"]

    materialized_root = tmp_path / "materialized"
    materialized = _run_json(
        [
            "rollout",
            "materialize-provider-set",
            "--registry",
            str(registry_root),
            "--provider-set",
            str(provider_set_path),
            "--out",
            str(materialized_root),
        ],
        capsys,
    )
    assert Path(str(materialized["provider_set"])).is_file()
    assert Path(str(materialized["controller_mapping"])).is_file()

    binding = load_materialized_rollout_provider_set_v2(materialized_root).bindings[0]
    run_root = tmp_path / "admitted-run"
    prepared = _run_json(
        [
            "intercept",
            "prepare-admitted",
            "--bundle",
            str(binding.bundle_dir),
            "--admission",
            str(binding.admission_path),
            "--release-config",
            str(binding.release_config_path),
            "--run",
            str(run_root),
            "--trust-dir",
            str(tmp_path / "trust"),
        ],
        capsys,
    )
    assert prepared == {
        "admitted": True,
        "prepared": str(run_root / "prepared.json"),
    }


def test_admitted_interception_cli_rejects_misaligned_bindings(
    tmp_path: Path, capsys: object
) -> None:
    with patch.object(
        sys,
        "argv",
        [
            "datalox-gate",
            "intercept",
            "prepare-admitted",
            "--bundle",
            str(tmp_path / "one"),
            "--bundle",
            str(tmp_path / "two"),
            "--admission",
            str(tmp_path / "admission"),
            "--release-config",
            str(tmp_path / "release-config"),
            "--run",
            str(tmp_path / "run"),
            "--json",
        ],
    ):
        assert main() == 1
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out)["error"]["message"] == (
        "--bundle, --admission, and --release-config must be supplied the same number of times"
    )
