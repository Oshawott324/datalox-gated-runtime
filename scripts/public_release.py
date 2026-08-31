#!/usr/bin/env python3
"""Build and validate the deterministic public Datalox source tree."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "release/public-release.json"
CLASSIFICATION_PATH = ROOT / "release/data-classification.json"
PUBLIC_MANIFEST_NAME = "PUBLIC_SOURCE_MANIFEST.json"
VALID_DISTRIBUTIONS = {"public", "restricted", "private"}
DATA_REQUIRED_FIELDS = {
    "captured_at",
    "contains_provider_payload",
    "distribution",
    "grounding_level",
    "origin",
    "path",
    "redistribution_basis",
    "sanitization",
    "sensitivity",
    "sha256",
    "source_license",
}


class PublicReleaseError(RuntimeError):
    """A stable, agent-readable public release failure."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicReleaseError(
            "public_release_json_invalid",
            f"Could not load required JSON file {path.relative_to(ROOT).as_posix()!r}.",
            path=path.relative_to(ROOT).as_posix(),
            error=str(exc),
        ) from exc


def _policy() -> dict[str, Any]:
    raw = _load_json(POLICY_PATH)
    required = {
        "schema_version",
        "data_roots",
        "public_overrides",
        "restricted_patterns",
        "internal_patterns",
        "required_public_paths",
        "forbidden_public_markers",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise PublicReleaseError(
            "public_release_policy_invalid",
            "Public release policy must contain exactly the declared v1 fields.",
            expected=sorted(required),
            actual=sorted(raw) if isinstance(raw, dict) else type(raw).__name__,
        )
    if raw["schema_version"] != "datalox_public_release_policy_v1":
        raise PublicReleaseError(
            "public_release_policy_version_unsupported",
            "Public release policy schema version is unsupported.",
            actual=raw["schema_version"],
        )
    for field in required - {"schema_version"}:
        values = raw[field]
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
            or len(set(values)) != len(values)
        ):
            raise PublicReleaseError(
                "public_release_policy_invalid",
                f"Policy field {field!r} must be a non-empty unique string array.",
                field=field,
            )
    overlap = set(raw["restricted_patterns"]) & set(raw["internal_patterns"])
    if overlap:
        raise PublicReleaseError(
            "public_release_policy_conflict",
            "Restricted and internal patterns must not overlap exactly.",
            patterns=sorted(overlap),
        )
    return raw


def _workspace_files() -> tuple[str, ...]:
    git_root = _git_root()
    if git_root == ROOT:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        paths = tuple(sorted(path for path in result.stdout.decode("utf-8").split("\0") if path))
    else:
        excluded_parts = {".git", ".pytest_cache", ".ruff_cache", ".tmp", "__pycache__"}
        paths = tuple(
            sorted(
                path.relative_to(ROOT).as_posix()
                for path in ROOT.rglob("*")
                if path.is_file()
                and path.name != PUBLIC_MANIFEST_NAME
                and not any(part in excluded_parts for part in path.relative_to(ROOT).parts)
                and not any(part.endswith(".egg-info") for part in path.relative_to(ROOT).parts)
                and path.relative_to(ROOT).parts[0] not in {"build", "dist"}
            )
        )
    paths = tuple(path for path in paths if path != PUBLIC_MANIFEST_NAME)
    if not paths:
        raise PublicReleaseError(
            "public_release_workspace_empty",
            "No source files were found in the Git workspace.",
        )
    return paths


def _git_root() -> Path | None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return Path(result.stdout.strip()).resolve()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _matches(path: str, patterns: Iterable[str]) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if fnmatch.fnmatchcase(path, pattern))


def _is_data_path(path: str, policy: Mapping[str, Any]) -> bool:
    return any(path.startswith(root) for root in policy["data_roots"])


def _classification_entries(
    workspace_files: Sequence[str], policy: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    raw = _load_json(CLASSIFICATION_PATH)
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "artifacts"}:
        raise PublicReleaseError(
            "data_classification_manifest_invalid",
            "Data classification manifest must contain schema_version and artifacts.",
        )
    if raw["schema_version"] != "datalox_data_classification_v1":
        raise PublicReleaseError(
            "data_classification_version_unsupported",
            "Data classification schema version is unsupported.",
            actual=raw["schema_version"],
        )
    artifacts = raw["artifacts"]
    if not isinstance(artifacts, list):
        raise PublicReleaseError(
            "data_classification_manifest_invalid",
            "Data classification artifacts must be an array.",
        )
    entries: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict) or set(entry) != DATA_REQUIRED_FIELDS:
            raise PublicReleaseError(
                "data_classification_entry_invalid",
                "Each data classification entry must contain exactly the v1 fields.",
                index=index,
                expected=sorted(DATA_REQUIRED_FIELDS),
                actual=sorted(entry) if isinstance(entry, dict) else type(entry).__name__,
            )
        path = entry["path"]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            raise PublicReleaseError(
                "data_classification_entry_invalid",
                "Classified paths must be canonical repository-relative paths.",
                index=index,
                path=path,
            )
        if path in entries:
            raise PublicReleaseError(
                "data_classification_path_duplicate",
                "A data path is classified more than once.",
                path=path,
            )
        distribution = entry["distribution"]
        if distribution not in VALID_DISTRIBUTIONS:
            raise PublicReleaseError(
                "data_classification_distribution_invalid",
                "Data distribution must be public, restricted, or private.",
                path=path,
                distribution=distribution,
            )
        if not isinstance(entry["sha256"], str) or not entry["sha256"].startswith("sha256:"):
            raise PublicReleaseError(
                "data_classification_digest_invalid",
                "Every classified data artifact must declare a SHA-256 digest.",
                path=path,
            )
        if distribution == "public":
            for field in (
                "origin",
                "redistribution_basis",
                "sanitization",
                "sensitivity",
                "source_license",
            ):
                if not isinstance(entry[field], str) or not entry[field].strip():
                    raise PublicReleaseError(
                        "public_data_metadata_incomplete",
                        "Public data requires complete release metadata.",
                        path=path,
                        field=field,
                    )
            if entry["contains_provider_payload"] is not False:
                raise PublicReleaseError(
                    "public_provider_payload_forbidden",
                    "The v1 public lane permits only artifacts declared free of provider payload bytes.",
                    path=path,
                )
        entries[path] = entry

    data_paths = {path for path in workspace_files if _is_data_path(path, policy)}
    classified_paths = set(entries)
    if data_paths != classified_paths:
        raise PublicReleaseError(
            "data_classification_coverage_mismatch",
            "Every and only workspace data artifacts must have an explicit classification.",
            missing=sorted(data_paths - classified_paths),
            stale=sorted(classified_paths - data_paths),
        )
    for path, entry in entries.items():
        actual = _sha256(ROOT / path)
        if actual != entry["sha256"]:
            raise PublicReleaseError(
                "data_classification_digest_mismatch",
                "A classified data artifact changed without classification review.",
                path=path,
                expected=entry["sha256"],
                actual=actual,
            )
    return entries


def _distribution_for_non_data(path: str, policy: Mapping[str, Any]) -> str:
    public_matches = _matches(path, policy["public_overrides"])
    restricted_matches = _matches(path, policy["restricted_patterns"])
    internal_matches = _matches(path, policy["internal_patterns"])
    if restricted_matches and internal_matches:
        raise PublicReleaseError(
            "public_release_path_conflict",
            "A non-data path matches both restricted and internal rules.",
            path=path,
            restricted_patterns=restricted_matches,
            internal_patterns=internal_matches,
        )
    if public_matches:
        return "public"
    if internal_matches:
        return "private"
    if restricted_matches:
        return "restricted"
    return "public"


def _release_inventory() -> tuple[dict[str, str], dict[str, dict[str, Any]], dict[str, Any]]:
    policy = _policy()
    workspace_files = _workspace_files()
    data_entries = _classification_entries(workspace_files, policy)
    inventory: dict[str, str] = {}
    for path in workspace_files:
        if path in data_entries:
            distribution = data_entries[path]["distribution"]
            if _matches(path, policy["public_overrides"]):
                distribution = "public"
                if data_entries[path]["distribution"] != "public":
                    raise PublicReleaseError(
                        "public_release_override_unapproved",
                        "A public data override must also be classified public.",
                        path=path,
                    )
            inventory[path] = distribution
        else:
            inventory[path] = _distribution_for_non_data(path, policy)

    public_paths = {path for path, distribution in inventory.items() if distribution == "public"}
    missing_required = set(policy["required_public_paths"]) - public_paths
    if missing_required:
        raise PublicReleaseError(
            "public_release_required_path_missing",
            "Required public release files are missing or not classified public.",
            paths=sorted(missing_required),
        )
    return inventory, data_entries, policy


def _validate_public_contents(public_paths: Iterable[str], policy: Mapping[str, Any]) -> None:
    failures: list[dict[str, str]] = []
    local_path_patterns = (
        re.compile("/" + r"Users/[^/\s]+/"),
        re.compile("/" + r"home/[^/\s]+/"),
        re.compile(r"[A-Za-z]:\\" + r"Users\\[^\\\s]+\\"),
    )
    for path in sorted(public_paths):
        absolute = ROOT / path
        if not absolute.is_file() or absolute.is_symlink():
            raise PublicReleaseError(
                "public_release_file_invalid",
                "Public source entries must be regular non-symlink files.",
                path=path,
            )
        payload = absolute.read_bytes()
        if b"\0" in payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if path == POLICY_PATH.relative_to(ROOT).as_posix():
            parsed_policy = json.loads(text)
            parsed_policy["forbidden_public_markers"] = []
            text = json.dumps(parsed_policy, sort_keys=True)
        for marker in policy["forbidden_public_markers"]:
            if marker in text:
                failures.append({"path": path, "marker": marker})
        for pattern in local_path_patterns:
            match = pattern.search(text)
            if match:
                failures.append({"path": path, "marker": match.group(0)})
    if failures:
        raise PublicReleaseError(
            "public_release_forbidden_marker",
            "Public files contain local-machine or secret markers.",
            findings=failures,
        )


def _validate_markdown_links(public_paths: Iterable[str]) -> None:
    public_set = set(public_paths)
    failures: list[dict[str, str]] = []
    link_pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for path in sorted(public_set):
        if not path.endswith(".md"):
            continue
        text = (ROOT / path).read_text(encoding="utf-8")
        for raw_target in link_pattern.findall(text):
            target = raw_target.strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            target = target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            target = unquote(target)
            candidate = ((ROOT / path).parent / target).resolve()
            try:
                relative = candidate.relative_to(ROOT).as_posix()
            except ValueError:
                failures.append({"path": path, "target": raw_target})
                continue
            if relative not in public_set and not any(
                public_path.startswith(relative.rstrip("/") + "/") for public_path in public_set
            ):
                failures.append({"path": path, "target": raw_target})
    if failures:
        raise PublicReleaseError(
            "public_release_markdown_link_missing",
            "Public Markdown links must resolve inside the public source tree.",
            findings=failures,
        )


def check() -> dict[str, Any]:
    inventory, data_entries, policy = _release_inventory()
    public_paths = [path for path, distribution in inventory.items() if distribution == "public"]
    _validate_public_contents(public_paths, policy)
    _validate_markdown_links(public_paths)
    counts = {
        distribution: sum(1 for value in inventory.values() if value == distribution)
        for distribution in sorted(VALID_DISTRIBUTIONS)
    }
    data_counts = {
        distribution: sum(
            1 for entry in data_entries.values() if entry["distribution"] == distribution
        )
        for distribution in sorted(VALID_DISTRIBUTIONS)
    }
    return {
        "schema_version": "datalox_public_release_check_v1",
        "passed": True,
        "file_counts": counts,
        "data_file_counts": data_counts,
    }


def _source_revision() -> str:
    if _git_root() == ROOT:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return result.stdout.strip()
    existing_manifest = ROOT / PUBLIC_MANIFEST_NAME
    if existing_manifest.is_file():
        raw = _load_json_external(existing_manifest)
        revision = raw.get("source_revision") if isinstance(raw, dict) else None
        if isinstance(revision, str) and revision:
            return revision
    raise PublicReleaseError(
        "public_release_source_revision_missing",
        "The source revision is unavailable from Git and the source manifest.",
    )


def build(out: Path) -> dict[str, Any]:
    inventory, data_entries, policy = _release_inventory()
    public_paths = sorted(path for path, value in inventory.items() if value == "public")
    _validate_public_contents(public_paths, policy)
    _validate_markdown_links(public_paths)
    resolved_out = out.expanduser().resolve()
    if resolved_out == ROOT or ROOT in resolved_out.parents and ".tmp" not in resolved_out.parts:
        raise PublicReleaseError(
            "public_release_output_unsafe",
            "Output inside the source repository is allowed only below an ignored .tmp directory.",
            out=str(resolved_out),
        )
    if resolved_out.exists():
        if any(resolved_out.iterdir()):
            raise PublicReleaseError(
                "public_release_output_not_empty",
                "Public release output directory must be absent or empty.",
                out=str(resolved_out),
            )
    else:
        resolved_out.mkdir(parents=True)

    file_entries: list[dict[str, Any]] = []
    for path in public_paths:
        source = ROOT / path
        destination = resolved_out / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)
        file_entries.append(
            {"path": path, "sha256": _sha256(destination), "size": destination.stat().st_size}
        )
    public_classification_path = "release/data-classification.json"
    public_classification = {
        "schema_version": "datalox_data_classification_v1",
        "artifacts": [
            data_entries[path]
            for path in sorted(data_entries)
            if data_entries[path]["distribution"] == "public"
        ],
    }
    classification_destination = resolved_out / public_classification_path
    classification_destination.parent.mkdir(parents=True, exist_ok=True)
    classification_destination.write_text(
        json.dumps(public_classification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    file_entries.append(
        {
            "path": public_classification_path,
            "sha256": _sha256(classification_destination),
            "size": classification_destination.stat().st_size,
        }
    )
    file_entries.sort(key=lambda entry: entry["path"])
    manifest = {
        "schema_version": "datalox_public_source_manifest_v1",
        "source_revision": _source_revision(),
        "files": file_entries,
    }
    manifest_path = resolved_out / PUBLIC_MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "schema_version": "datalox_public_release_build_v1",
        "passed": True,
        "out": str(resolved_out),
        "file_count": len(file_entries),
        "manifest_sha256": _sha256(manifest_path),
    }


def verify_built(source: Path) -> dict[str, Any]:
    root = source.expanduser().resolve()
    manifest_path = root / PUBLIC_MANIFEST_NAME
    raw = _load_json_external(manifest_path)
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "source_revision", "files"}:
        raise PublicReleaseError(
            "public_source_manifest_invalid",
            "Built public source manifest has an invalid shape.",
            path=str(manifest_path),
        )
    if raw["schema_version"] != "datalox_public_source_manifest_v1":
        raise PublicReleaseError(
            "public_source_manifest_version_unsupported",
            "Built public source manifest schema version is unsupported.",
            actual=raw["schema_version"],
        )
    expected: dict[str, str] = {}
    for entry in raw["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise PublicReleaseError(
                "public_source_manifest_invalid",
                "Built public source file entries have an invalid shape.",
            )
        path = entry["path"]
        if path in expected:
            raise PublicReleaseError(
                "public_source_manifest_duplicate",
                "Built public source manifest contains a duplicate path.",
                path=path,
            )
        expected[path] = entry["sha256"]
        absolute = root / path
        if not absolute.is_file() or absolute.is_symlink():
            raise PublicReleaseError(
                "public_source_file_missing",
                "A declared public source file is absent or not regular.",
                path=path,
            )
        if absolute.stat().st_size != entry["size"] or _sha256(absolute) != entry["sha256"]:
            raise PublicReleaseError(
                "public_source_file_digest_mismatch",
                "A built public source file does not match its manifest.",
                path=path,
            )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != PUBLIC_MANIFEST_NAME
    }
    if actual != set(expected):
        raise PublicReleaseError(
            "public_source_file_set_mismatch",
            "Built public source contains missing or undeclared files.",
            missing=sorted(set(expected) - actual),
            extra=sorted(actual - set(expected)),
        )
    commands = (
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            ".",
            "--no-cache",
            "--select",
            "E4,E7,E9,F",
        ],
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--check",
            "--exclude",
            "documented_sources/**",
            "--exclude",
            "envs/**",
            "--exclude",
            "examples/**",
            "--exclude",
            "integrations/harbor/**",
            "--exclude",
            "integrations/mastra/**",
            "--exclude",
            "runs/**",
            ".",
        ],
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        [sys.executable, "scripts/demo/offline-world-smoke.py"],
        [sys.executable, "-m", "build"],
    )
    with tempfile.TemporaryDirectory(prefix="datalox-public-verify-") as temporary:
        verification_root = Path(temporary) / "source"
        shutil.copytree(root, verification_root)
        for command in commands:
            env = _verification_environment(verification_root)
            completed = subprocess.run(command, cwd=verification_root, env=env, check=False)
            if completed.returncode != 0:
                raise PublicReleaseError(
                    "public_source_verification_failed",
                    "A built public source verification command failed.",
                    command=command,
                    returncode=completed.returncode,
                )
    return {
        "schema_version": "datalox_public_source_verification_v1",
        "passed": True,
        "file_count": len(expected),
        "commands": commands,
    }


def _load_json_external(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicReleaseError(
            "public_source_manifest_invalid",
            "Could not load built public source manifest.",
            path=str(path),
            error=str(exc),
        ) from exc


def _verification_environment(root: Path) -> dict[str, str]:
    env = dict(os.environ)
    for key in ("NO_PROXY", "no_proxy"):
        bypasses = [item.strip() for item in env.get(key, "").split(",") if item.strip()]
        for loopback in ("127.0.0.1", "localhost", "::1"):
            if loopback not in bypasses:
                bypasses.append(loopback)
        env[key] = ",".join(bypasses)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(root / "src")
    return env


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check", help="Validate classification and the public allowlist.")
    build_parser = subcommands.add_parser("build", help="Build the public source tree.")
    build_parser.add_argument("--out", type=Path, required=True)
    verify_parser = subcommands.add_parser(
        "verify-built",
        help="Verify hashes, quality, tests, demo, and package build in a public tree.",
    )
    verify_parser.add_argument("--source", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            result = check()
        elif args.command == "build":
            result = build(args.out)
        else:
            result = verify_built(args.source)
    except PublicReleaseError as exc:
        print(json.dumps({"passed": False, "error": exc.to_dict()}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
