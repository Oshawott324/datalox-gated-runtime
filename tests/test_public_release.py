from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts.public_release import (
    PUBLIC_MANIFEST_NAME,
    PublicReleaseError,
    _verification_environment,
    build,
    check,
    verify_built,
)


ROOT = Path(__file__).resolve().parents[1]


def test_release_check_classifies_every_data_artifact() -> None:
    result = check()

    assert result["passed"] is True
    assert result["file_counts"]["public"] > 0
    assert result["data_file_counts"]["public"] > 0
    assert set(result["data_file_counts"]) == {"private", "public", "restricted"}


def test_public_build_contains_safe_reference_world_but_not_private_sources(
    tmp_path: Path,
) -> None:
    out = tmp_path / "public-source"
    result = build(out)

    assert result["passed"] is True
    assert (out / PUBLIC_MANIFEST_NAME).is_file()
    assert (out / "envs/commerce_support_ops_v0/world/manifest.json").is_file()
    assert not (out / "runs").exists()
    assert not (out / "documented_sources").exists()
    assert not (out / "docs/reports").exists()
    public_classification_path = out / "release/data-classification.json"
    assert public_classification_path.is_file()

    manifest = json.loads((out / PUBLIC_MANIFEST_NAME).read_text(encoding="utf-8"))
    paths = {entry["path"] for entry in manifest["files"]}
    public_classification = json.loads(public_classification_path.read_text(encoding="utf-8"))
    assert {entry["distribution"] for entry in public_classification["artifacts"]} == {"public"}
    assert "envs/commerce_support_ops_v0/world_admission.json" not in paths
    assert not any(path.startswith("envs/stripe_billing_ops_v0/") for path in paths)


def test_public_build_refuses_nonempty_output(tmp_path: Path) -> None:
    out = tmp_path / "public-source"
    out.mkdir()
    (out / "unexpected").write_text("present", encoding="utf-8")

    with pytest.raises(PublicReleaseError) as raised:
        build(out)

    assert raised.value.code == "public_release_output_not_empty"


def test_built_manifest_detects_undeclared_file(tmp_path: Path) -> None:
    out = tmp_path / "public-source"
    build(out)
    (out / "undeclared.txt").write_text("not in manifest", encoding="utf-8")

    with pytest.raises(PublicReleaseError) as raised:
        verify_built(out)

    assert raised.value.code == "public_source_file_set_mismatch"


def test_committed_public_tree_can_export_itself_again(tmp_path: Path) -> None:
    public_repo = tmp_path / "public-repo"
    build(public_repo)
    subprocess.run(["git", "init", "-b", "main"], cwd=public_repo, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Public Release Test"], cwd=public_repo, check=True
    )
    subprocess.run(
        ["git", "config", "user.email", "public-release-test@localhost"],
        cwd=public_repo,
        check=True,
    )
    subprocess.run(["git", "add", "--all"], cwd=public_repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial public source"],
        cwd=public_repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    rebuilt = public_repo / ".tmp/rebuilt"
    completed = subprocess.run(
        [sys.executable, "scripts/public_release.py", "build", "--out", str(rebuilt)],
        cwd=public_repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((rebuilt / PUBLIC_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert PUBLIC_MANIFEST_NAME not in {entry["path"] for entry in manifest["files"]}


def test_verification_environment_routes_loopback_around_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NO_PROXY", "internal.example")
    monkeypatch.delenv("no_proxy", raising=False)

    env = _verification_environment(tmp_path)

    assert env["NO_PROXY"].split(",") == ["internal.example", "127.0.0.1", "localhost", "::1"]
    assert env["no_proxy"].split(",") == ["127.0.0.1", "localhost", "::1"]
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["PYTHONPATH"] == str(tmp_path / "src")
