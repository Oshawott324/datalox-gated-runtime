#!/usr/bin/env python3
"""Fail-closed checks for the pinned Medusa Store pagination evidence lane."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE = ROOT / "envs" / "medusa_store_pagination_v0" / "evidence"
EXPECTED_SEQUENCE = (
    ("10", "0"),
    ("10", "0"),
    ("10", "10"),
    ("10", "20"),
    ("10", "30"),
    ("10", "40"),
    ("10", "45"),
    ("10", "50"),
    ("10", "60"),
    ("1", "0"),
    ("100", "0"),
    ("0", "0"),
    ("-1", "0"),
    ("invalid", "0"),
    ("10", "-1"),
    ("10", "invalid"),
)


class EvidenceError(ValueError):
    pass


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load JSON: {path}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _page(row: dict[str, Any], *, expected_limit: int, expected_offset: int) -> list[str]:
    _require(row.get("status_code") == 200, f"expected 200 for offset {expected_offset}")
    response = row.get("response")
    _require(isinstance(response, dict), f"response for offset {expected_offset} is not an object")
    _require(
        response.get("top_level_fields") == ["products", "count", "offset", "limit"],
        f"envelope changed for offset {expected_offset}",
    )
    _require(response.get("count") == 50, f"count mismatch for offset {expected_offset}")
    _require(
        response.get("limit") == expected_limit, f"limit mismatch for offset {expected_offset}"
    )
    _require(
        response.get("offset") == expected_offset, f"offset mismatch for offset {expected_offset}"
    )
    handles = response.get("product_handles")
    _require(
        isinstance(handles, list), f"product handles is not a list for offset {expected_offset}"
    )
    _require(
        all(isinstance(handle, str) and handle for handle in handles),
        "captured product handle is invalid",
    )
    _require(
        len(handles) == len(set(handles)), f"duplicate product within offset {expected_offset}"
    )
    return handles


def check(evidence_dir: Path) -> dict[str, Any]:
    provenance = _load_json(evidence_dir / "provenance.json")
    _require(
        provenance.get("schema_version") == "datalox_medusa_pagination_evidence_v1",
        "wrong provenance schema",
    )
    _require(provenance.get("provider") == "medusa", "wrong provider")
    _require(
        provenance.get("provider_version") == "2.16.0", "Medusa version is not pinned to 2.16.0"
    )
    _require(provenance.get("grounding_level") == "G2", "grounding level must be G2")
    _require(
        provenance.get("distribution") == "public",
        "identifier-free factual evidence must be public",
    )

    static_inputs = provenance.get("static_inputs")
    _require(isinstance(static_inputs, list) and static_inputs, "static_inputs is empty")
    for item in static_inputs:
        _require(isinstance(item, dict), "static input entry is invalid")
        relative = item.get("path")
        expected = item.get("sha256")
        _require(
            isinstance(relative, str) and relative and not relative.startswith("/"),
            "static input path must be repository-relative",
        )
        _require(
            isinstance(expected, str) and expected.startswith("sha256:"),
            "static input digest is invalid",
        )
        _require(_sha256(ROOT / relative) == expected, f"static input digest mismatch: {relative}")

    observation_artifact = _load_json(evidence_dir / "observations.json")
    _require(
        observation_artifact.get("schema_version") == "datalox_medusa_pagination_observations_v2",
        "wrong observations schema",
    )
    probe_config_path = ROOT / "probes" / "medusa_pagination.json"
    probe_config = _load_json(probe_config_path)
    _require(probe_config.get("provider_id") == "medusa", "pinned probe provider changed")
    probe_requests = probe_config.get("probe_requests")
    _require(isinstance(probe_requests, list), "pinned probe request sequence is invalid")
    _require(
        observation_artifact.get("capture_path_projection")
        == {
            "gate_path_template": "/{provider_id}{upstream_path}",
            "provider_id": "medusa",
            "probe_config_path": "probes/medusa_pagination.json",
            "probe_config_sha256": _sha256(probe_config_path),
            "upstream_path_source": "probe_requests[*].path",
            "upstream_projection": "strip_first_gate_path_segment_v1",
        },
        "capture path projection is not bound to the pinned probe config",
    )
    _require(
        observation_artifact.get("payload_policy")
        == "provider-generated IDs and response text removed; self-authored product handles and factual measurements retained",
        "payload policy changed",
    )
    captures = observation_artifact.get("observations")
    _require(isinstance(captures, list), "observations is not an array")
    _require(
        len(captures) == len(EXPECTED_SEQUENCE),
        "capture count does not match declared request sequence",
    )
    _require(len(probe_requests) == len(captures), "pinned probe request count changed")
    observed_sequence = tuple(
        (str(row.get("query", {}).get("limit")), str(row.get("query", {}).get("offset")))
        for row in captures
    )
    _require(observed_sequence == EXPECTED_SEQUENCE, "captured request sequence changed")
    for index, (row, probe_request) in enumerate(zip(captures, probe_requests, strict=True)):
        _require(isinstance(probe_request, dict), f"pinned probe request {index} is invalid")
        upstream_path = probe_request.get("path")
        _require(upstream_path == "/store/products", f"upstream path changed at capture {index}")
        _require(row.get("method") == probe_request.get("method") == "GET", "non-GET capture")
        _require(
            row.get("query") == probe_request.get("query"),
            f"capture query does not match pinned probe at capture {index}",
        )
        _require(
            row.get("gate_path") == f"/medusa{upstream_path}",
            f"gate path changed at capture {index}",
        )
        _require(
            row.get("upstream_path") == upstream_path,
            f"upstream path projection changed at capture {index}",
        )
        _require("path" not in row, f"ambiguous path field present at capture {index}")

    first_ids = _page(captures[0], expected_limit=10, expected_offset=0)
    repeated_ids = _page(captures[1], expected_limit=10, expected_offset=0)
    _require(
        captures[0].get("canonical_body_sha256") == captures[1].get("canonical_body_sha256"),
        "identical request did not return an identical body",
    )
    _require(first_ids == repeated_ids, "identical request changed product order")

    complete_ids: list[str] = []
    for index, offset in enumerate((0, 10, 20, 30, 40)):
        capture_index = index + 1 if offset else 0
        complete_ids.extend(
            _page(captures[capture_index], expected_limit=10, expected_offset=offset)
        )
    _require(
        len(complete_ids) == 50 and len(set(complete_ids)) == 50,
        "five pages do not cover 50 unique products",
    )

    terminal_ids = _page(captures[6], expected_limit=10, expected_offset=45)
    _require(
        terminal_ids == complete_ids[45:50], "terminal partial page does not match full ordering"
    )
    _require(
        _page(captures[7], expected_limit=10, expected_offset=50) == [],
        "terminal empty page is not empty",
    )
    _require(
        _page(captures[8], expected_limit=10, expected_offset=60) == [],
        "beyond-terminal page is not empty",
    )
    _require(
        _page(captures[9], expected_limit=1, expected_offset=0) == complete_ids[:1],
        "limit=1 boundary changed ordering",
    )
    _require(
        _page(captures[10], expected_limit=100, expected_offset=0) == complete_ids,
        "limit=100 page disagrees with ten-item pages",
    )

    _require(
        _page(captures[11], expected_limit=0, expected_offset=0) == [],
        "limit=0 boundary is not empty",
    )
    expected_invalid = (
        (12, 500, "unknown_error"),
        (13, 400, "invalid_data"),
        (14, 500, "unknown_error"),
        (15, 400, "invalid_data"),
    )
    invalid_statuses: list[int] = []
    for index, expected_status, expected_type in expected_invalid:
        row = captures[index]
        _require(
            row.get("status_code") == expected_status,
            f"invalid pagination status changed at capture {index}",
        )
        response = row.get("response")
        _require(
            isinstance(response, dict),
            f"invalid pagination body is not an object at capture {index}",
        )
        _require(
            response.get("type") == expected_type,
            f"invalid pagination error type changed at capture {index}",
        )
        _require(
            response.get("message_present") is True,
            f"invalid pagination error message was absent at capture {index}",
        )
        _require(
            isinstance(response.get("message_sha256"), str)
            and response["message_sha256"].startswith("sha256:"),
            f"invalid pagination message digest missing at capture {index}",
        )
        invalid_statuses.append(expected_status)

    return {
        "status": "passed",
        "provider": "medusa",
        "provider_version": "2.16.0",
        "grounding_level": "G2",
        "operation": "GET /store/products",
        "observed_records": len(complete_ids),
        "observed_requests": len(captures),
        "repeat_body_sha256": captures[0].get("canonical_body_sha256"),
        "invalid_statuses": invalid_statuses,
        "coverage": [
            "first_page",
            "middle_pages",
            "terminal_partial_page",
            "terminal_empty_page",
            "beyond_terminal_page",
            "identical_repeat",
            "limit_boundaries",
            "invalid_limit",
            "invalid_offset",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = check(args.evidence.resolve())
    except EvidenceError as exc:
        report = {"status": "failed", "error": str(exc)}
        print(json.dumps(report, indent=2, sort_keys=True) if args.json else report["error"])
        return 1
    print(
        json.dumps(report, indent=2, sort_keys=True)
        if args.json
        else "Medusa pagination evidence passed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
