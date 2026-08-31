#!/usr/bin/env python3
"""Verify the exact THUDM/slime source contract reviewed by this adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "integrations" / "slime" / "upstream-contract.json"


class ContractError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _contract() -> dict[str, object]:
    value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema_version", "commit", "files"}:
        raise ContractError("upstream contract manifest fields are invalid")
    if value["schema_version"] != "datalox_slime_upstream_contract_v1":
        raise ContractError("upstream contract schema_version is invalid")
    if not isinstance(value["commit"], str) or len(value["commit"]) != 40:
        raise ContractError("upstream contract commit is invalid")
    files = value["files"]
    if not isinstance(files, dict) or not files:
        raise ContractError("upstream contract files are invalid")
    if any(
        not isinstance(path, str) or not isinstance(digest, str) or not digest.startswith("sha256:")
        for path, digest in files.items()
    ):
        raise ContractError("upstream contract file entries are invalid")
    return value


def check(source: Path) -> dict[str, object]:
    source = source.resolve()
    if not (source / ".git").exists():
        raise ContractError("source must be a THUDM/slime Git checkout")
    contract = _contract()
    completed = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ContractError("could not read the THUDM/slime checkout commit")
    commit = completed.stdout.strip()
    if commit != contract["commit"]:
        raise ContractError(
            f"THUDM/slime commit mismatch: expected {contract['commit']}, observed {commit}"
        )

    checked: list[dict[str, str]] = []
    files = contract["files"]
    assert isinstance(files, dict)
    for relative_path, expected_digest in sorted(files.items()):
        assert isinstance(relative_path, str) and isinstance(expected_digest, str)
        path = source / relative_path
        if not path.is_file() or path.is_symlink():
            raise ContractError(f"required upstream file is missing or symbolic: {relative_path}")
        observed_digest = _sha256(path)
        if observed_digest != expected_digest:
            raise ContractError(
                f"upstream file digest mismatch for {relative_path}: "
                f"expected {expected_digest}, observed {observed_digest}"
            )
        checked.append({"path": relative_path, "sha256": observed_digest})

    return {
        "schema_version": "datalox_slime_upstream_check_v1",
        "passed": True,
        "commit": commit,
        "files": checked,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(args.source)
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
