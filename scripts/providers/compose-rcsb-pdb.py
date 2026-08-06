#!/usr/bin/env python3
"""Compose the multi-host RCSB PDB captures into one replay-only environment."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "envs" / "probed_rcsb_pdb_v0"

CAPTURE_SOURCES = (
    {
        "provider_id": "rcsb_pdb",
        "upstream": "https://data.rcsb.org",
        "probe_config": ROOT / "probes" / "rcsb_pdb.json",
        "run": ROOT / "runs" / "probes" / "rcsb_pdb",
    },
    {
        "provider_id": "rcsb_pdb_modelserver",
        "upstream": "https://models.rcsb.org",
        "probe_config": ROOT / "probes" / "rcsb_pdb_modelserver.json",
        "run": ROOT / "runs" / "probes" / "rcsb_pdb_modelserver",
    },
    {
        "provider_id": "rcsb_pdb_files",
        "upstream": "https://www.rcsb.org",
        "probe_config": ROOT / "probes" / "rcsb_pdb_files.json",
        "run": ROOT / "runs" / "probes" / "rcsb_pdb_files",
    },
)

FAMILY_CASE_IDS = {
    "entry_and_assembly_metadata": [
        "cap_2a0b6695849a45cfbe81106fa538508c",
        "cap_732068d9852b4a0683617238511219e7",
        "cap_bb1bcf06f1d245d9bb8bf04ebc34fb33",
    ],
    "polymer_entities_and_instances": [
        "cap_4697501d7d0146b484d869624ae91f4b",
        "cap_9248470b4a214ebbb76da83730c558c2",
    ],
    "nonpolymer_entities_and_instances": [
        "cap_9e0362e0f9e04a7bb1577b745d8a5162",
        "cap_d9be4b44b2384fdc8ef7a03ef82f623b",
    ],
    "branched_entities_and_instances": [
        "cap_c1b58cd61ec84d9f92da24312586f844",
        "cap_02420ac38fd94fb3835592651e750b37",
    ],
    "chemical_components": ["cap_9c1d8af02ab947079e3fbc5e33734dfc"],
    "integrated_external_annotations": [
        "cap_54d7beb82c9043fbafe14340936fabee",
        "cap_3fa0020810f147afb39e9754d2c39df7",
        "cap_5174aa71b41a4f70a4d2da16f525a220",
    ],
    "repository_holdings": [
        "cap_42315c6ca2c847698703c7dc206e8c68",
        "cap_e2b049030bdd4b4ba1af79f867a0a077",
    ],
    "data_graphql_projection": ["cap_9e5276d503ff48ffbbf440586e4c8bde"],
    "schema_discovery": [
        "cap_e1dd59135cfb4b2ab5fe713f6d0754a7",
        "cap_0d5e32ec9bd142c1b3984fccfa0775c2",
    ],
    "model_full_and_assembly_coordinates": [
        "cap_be778753443347b3982e17f57b978ebc",
        "cap_84387071f5d740cf85f488798e93a184",
    ],
    "model_atom_selection": ["cap_2f1cba12473c4583b3b1d92eb18d2852"],
    "model_residue_neighborhood": ["cap_976ab554eb1b4b4fb830931f458a073e"],
    "model_ligand_coordinates": ["cap_32ff2c3c9c144e10a94dcbeb22cc6fe4"],
    "fasta_sequence_downloads": [
        "cap_8afc70b9f7574347ac490da5b5d06d47",
        "cap_67b2071b8cbb4440927c7a8c00ae624d",
        "cap_cc2b0aa3ec434dc88cf6d4b2c9344d2c",
    ],
    "missing_resource_errors": [
        "cap_d95e1dcdae19403ba15e1fc46f0f01f9",
        "cap_0e4a0d2204ed47d3becdac913eb1c9e3",
    ],
}

KNOWN_GAPS = [
    "This is a point-in-time capture of public RCSB PDB production APIs. Entry annotations, holdings, schemas, integrated mappings, and coordinate files can change after the capture window.",
    "The RCSB PDB Search API's released query endpoint requires POST, so it is deliberately not represented in this GET-only live-capture pack.",
    "The current RCSB PDB Sequence Coordinates API accepts POST requests, so sequence-coordinate mappings are deliberately not represented. Credential-free FASTA GET downloads are captured separately.",
    "One bounded Data API GraphQL query is captured through the documented GET query parameter. General GraphQL POST execution and arbitrary query documents are outside this pack.",
    "ModelServer coverage is limited to five credential-free GET operations returning exact CIF or SDF text: full model, assembly, atom selection, residue surroundings, and ligand coordinates. POST forms and binary BCIF responses are not captured.",
    "The pack does not cover every Data API object, query combination, static coordinate-file format, VolumeServer operation, alignment endpoint, archive member, or computed model provider.",
    "The probe observed two authentic HTTP 404 missing-resource responses and no throttling, provider outage, malformed-query family, 5xx recovery, or authentication failure semantics.",
    "All replay-time POST, PUT, PATCH, and DELETE calls under the three RCSB logical prefixes are denied. No live or shadow mutation behavior is represented.",
]

OFFICIAL_SOURCES = [
    "https://www.rcsb.org/docs/programmatic-access/web-apis-overview",
    "https://data.rcsb.org/index.html",
    "https://data.rcsb.org/redoc/index.html",
    "https://search.rcsb.org/redoc/index.html",
    "https://models.rcsb.org/openapi.json",
    "https://sequence-coordinates.rcsb.org/migration/migration-guide.html",
    "https://www.rcsb.org/docs/programmatic-access/file-download-services",
]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def capture_timestamp(case: dict[str, Any]) -> str:
    prefix = "live:"
    evidence_ref = case["evidence_ref"]
    if not evidence_ref.startswith(prefix) or evidence_ref.count(":") < 3:
        raise ValueError(f"unexpected live evidence_ref: {evidence_ref}")
    return evidence_ref.split(":", 2)[2]


def failure_code(path: str) -> str:
    slug = "".join(char.lower() if char.isalnum() else "_" for char in path)
    return f"missing_read_{slug.strip('_')}"


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    response_cases: list[dict[str, Any]] = []
    capture_sources: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()

    for source in CAPTURE_SOURCES:
        report = load_json(source["run"] / "probe_report.json")
        cases = load_jsonl(source["run"] / "captures.jsonl")
        if report["status"] != "completed" or report["blocker"] is not None:
            raise ValueError(f"incomplete probe run: {relative(source['run'])}")
        if report["auth_schema"] != "none" or not report["hygiene"]["secret_scan_passed"]:
            raise ValueError(f"unsafe probe run: {relative(source['run'])}")
        if report["counts"]["captured"] != len(cases):
            raise ValueError(f"capture count mismatch: {relative(source['run'])}")
        if any(case["method"] != "GET" for case in cases):
            raise ValueError(f"non-GET capture found: {relative(source['run'])}")

        timestamps = [capture_timestamp(case) for case in cases]
        response_cases.extend(cases)
        status_counts.update(str(case["status_code"]) for case in cases)
        capture_sources.append(
            {
                "auth_schema": report["auth_schema"],
                "captured_from": min(timestamps),
                "captured_through": max(timestamps),
                "grounding_level": "G3_PUBLIC_LIVE_CAPTURE",
                "probe_config": {
                    "path": relative(source["probe_config"]),
                    "sha256": sha256(source["probe_config"]),
                },
                "provider_id": source["provider_id"],
                "request_count": len(cases),
                "run": relative(source["run"]),
                "status_counts": dict(
                    sorted(Counter(str(case["status_code"]) for case in cases).items())
                ),
                "upstream": source["upstream"],
            }
        )

    case_by_id = {case["case_id"]: case for case in response_cases}
    if len(case_by_id) != len(response_cases):
        raise ValueError("duplicate RCSB capture case_id")
    mapped_ids = [case_id for ids in FAMILY_CASE_IDS.values() for case_id in ids]
    if len(mapped_ids) != len(set(mapped_ids)):
        raise ValueError("a capture case is assigned to more than one family")
    if set(mapped_ids) != set(case_by_id):
        missing = sorted(set(case_by_id) - set(mapped_ids))
        unknown = sorted(set(mapped_ids) - set(case_by_id))
        raise ValueError(f"family mapping mismatch: missing={missing}, unknown={unknown}")
    if len(response_cases) != 28 or status_counts != Counter({"200": 26, "404": 2}):
        raise ValueError(
            f"unexpected aggregate capture shape: cases={len(response_cases)}, statuses={status_counts}"
        )

    case_family = {
        case_id: family for family, case_ids in FAMILY_CASE_IDS.items() for case_id in case_ids
    }
    family_paths = {
        family: sorted({case_by_id[case_id]["path"] for case_id in case_ids})
        for family, case_ids in FAMILY_CASE_IDS.items()
    }
    coverage = {
        "case_count": len(response_cases),
        "families": list(FAMILY_CASE_IDS),
        "family_case_ids": FAMILY_CASE_IDS,
        "case_family": case_family,
        "family_paths": family_paths,
        "known_gaps": KNOWN_GAPS,
    }
    capture = {
        "auth_schema": "none",
        "captured_from": min(source["captured_from"] for source in capture_sources),
        "captured_through": max(source["captured_through"] for source in capture_sources),
        "grounding_level": "G3_PUBLIC_LIVE_CAPTURE",
        "request_count": len(response_cases),
        "status_counts": dict(sorted(status_counts.items())),
        "sources": capture_sources,
    }
    provenance = {
        "capture": capture,
        "coverage": coverage,
        "display_name": "RCSB Protein Data Bank APIs",
        "domain": "structural_biology_and_bioinformatics",
        "promoted_from": "runs/probes/rcsb_pdb",
        "composed_from": [source["run"] for source in capture_sources],
        "provenance": {
            "capture_kind": "real_public_api_traffic",
            "level": "G3",
            "sources": OFFICIAL_SOURCES,
        },
        "provider": "rcsb_pdb",
        "verifier_type": "config_post_run_audit",
    }

    audit_rules = [
        {
            "draft": False,
            "failure_code": failure_code(case["path"]),
            "method": "GET",
            "path": case["path"],
            "type": "require_call",
        }
        for case in response_cases
    ]
    prefixes = ("/rcsb_pdb/", "/rcsb_pdb_modelserver/", "/rcsb_pdb_files/")
    deny_rules = [
        {
            "message": "The RCSB PDB public capture is GET-only replay evidence; writes and POST-only query surfaces are unavailable.",
            "method": method,
            "path_prefix": prefix,
            "reason_code": "rcsb_pdb_replay_only",
        }
        for prefix in prefixes
        for method in ("POST", "PUT", "PATCH", "DELETE")
    ]
    gate_config = {
        "audit_rules": audit_rules,
        "config_id": "probe_rcsb_pdb_promoted",
        "metadata": provenance,
        "policy": {"deny": deny_rules, "live_capture": [], "shadow_write": []},
        "response_cases": response_cases,
    }
    replay_script = [
        {
            "body": None,
            "method": case["method"],
            "path": case["path"],
            "query": case.get("query", {}),
            "surface": "http",
        }
        for case in response_cases
    ]
    task = {
        "instructions": (
            "Use the exact replay of public RCSB PDB responses to investigate structural-biology "
            "records, entity hierarchies, external annotations, archive holdings, schemas, bounded "
            "GraphQL projection, coordinate selections, ligand structure, and FASTA sequences. "
            "Preserve the three logical API prefixes and the captured query parameters. Treat the "
            "responses as capture-time evidence rather than current archive state. Writes and "
            "POST-only Search or Sequence Coordinates operations are unavailable."
        ),
        "success_criteria": [
            "Replay all twenty-eight captured RCSB response cases with zero misses and a passing post-run audit.",
            "Use all fifteen coherent operation families and keep every response case assigned to exactly one family.",
            "Preserve exact JSON, CIF, SDF, FASTA, HTTP status, and authentic missing-resource response bodies when citing evidence.",
            "Do not present the point-in-time records as current live archive state or attempt POST, PUT, PATCH, or DELETE calls.",
        ],
        "task_id": "probe_rcsb_pdb_promoted",
        "title": "Investigate public RCSB PDB structural biology APIs",
    }

    OUT.mkdir(parents=True, exist_ok=True)
    write_json(OUT / "gate_config.json", gate_config)
    write_json(OUT / "provenance.json", provenance)
    write_json(OUT / "replay_script.json", replay_script)
    write_json(OUT / "task.json", task)


if __name__ == "__main__":
    main()
