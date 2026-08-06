#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from datalox_gated_runtime.capture import LiveCaptureClient, LiveCaptureError
from datalox_gated_runtime.models import CallRequest, LiveGateConfig, LiveUpstream


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_capture.json"
EXCLUSIONS_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/tested_exclusions.json"
BASE = "https://rest.ensembl.org"
HOST = "rest.ensembl.org"
JSON_HEADERS = {"accept": "application/json", "content-type": "application/json"}


def request(
    capture_id: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    status: int = 200,
    exclude_on_timeout: bool = False,
    exclude_response: bool = False,
) -> dict[str, Any]:
    return {
        "id": capture_id,
        "path": path,
        "query": query or {},
        "expected_status": status,
        "exclude_on_timeout": exclude_on_timeout,
        "exclude_response": exclude_response,
    }


REQUESTS = (
    request("info_ping", "/info/ping"),
    request("info_rest", "/info/rest"),
    request("info_software", "/info/software"),
    request("info_data", "/info/data"),
    request("info_species", "/info/species"),
    request("info_assembly_human", "/info/assembly/homo_sapiens"),
    request("info_assembly_region_7", "/info/assembly/homo_sapiens/7"),
    request("info_comparas", "/info/comparas"),
    request("info_compara_methods", "/info/compara/methods"),
    request("info_compara_epo_species_sets", "/info/compara/species_sets/EPO"),
    request("info_external_dbs", "/info/external_dbs/homo_sapiens"),
    request("info_variation", "/info/variation/homo_sapiens"),
    request(
        "info_variation_populations_ld",
        "/info/variation/populations/homo_sapiens",
        query={"filter": "LD"},
    ),
    request("info_consequence_types", "/info/variation/consequence_types"),
    request("archive_braf", "/archive/id/ENSG00000157764"),
    request("archive_missing", "/archive/id/ENSG_NOT_REAL", status=400),
    request("lookup_braf_expanded", "/lookup/id/ENSG00000157764", query={"expand": "1"}),
    request("lookup_braf_symbol", "/lookup/symbol/homo_sapiens/BRAF", query={"expand": "0"}),
    request("lookup_egfr_off_chain", "/lookup/id/ENSG00000146648"),
    request("lookup_tp53_off_chain", "/lookup/id/ENSG00000141510"),
    request("lookup_missing", "/lookup/id/ENSG_NOT_REAL", status=400),
    request(
        "xrefs_braf_id",
        "/xrefs/id/ENSG00000157764",
        query={"external_db": "Uniprot_gn"},
    ),
    request(
        "xrefs_braf_symbol",
        "/xrefs/symbol/homo_sapiens/BRAF",
        query={"external_db": "HGNC"},
    ),
    request(
        "xrefs_braf_name",
        "/xrefs/name/homo_sapiens/BRAF",
        query={"external_db": "HGNC"},
    ),
    request("sequence_braf_protein", "/sequence/id/ENSP00000493543", query={"type": "protein"}),
    request(
        "sequence_braf_cdna",
        "/sequence/id/ENST00000646891",
        query={"type": "cdna"},
        exclude_on_timeout=True,
    ),
    request("sequence_braf_region", "/sequence/region/homo_sapiens/7:140753336..140753436:1"),
    request("sequence_missing", "/sequence/id/ENSG_NOT_REAL", status=400),
    request(
        "overlap_braf_transcripts", "/overlap/id/ENSG00000157764", query={"feature": "transcript"}
    ),
    request(
        "overlap_braf_variants",
        "/overlap/region/homo_sapiens/7:140753336-140753436",
        query={"feature": "variation"},
    ),
    request(
        "overlap_braf_regulatory",
        "/overlap/region/homo_sapiens/7:140719327-140925199",
        query={"feature": "regulatory"},
    ),
    request(
        "overlap_braf_translation",
        "/overlap/translation/ENSP00000493543",
        query={"db_type": "core"},
    ),
    request(
        "variation_braf_v600e",
        "/variation/homo_sapiens/rs113488022",
        query={"phenotypes": "1"},
    ),
    request("variation_missing", "/variation/homo_sapiens/not-a-real-variant", status=400),
    request(
        "variation_pmids_wrong_identifier",
        "/variation/homo_sapiens/pmids/rs113488022",
        status=400,
        exclude_response=True,
    ),
    request("variation_publication_official_example", "/variation/homo_sapiens/pmid/26318936"),
    request("variant_recoder_braf_v600e", "/variant_recoder/homo_sapiens/rs113488022"),
    request("phenotype_braf_gene", "/phenotype/gene/homo_sapiens/ENSG00000157764"),
    request(
        "phenotype_braf_region",
        "/phenotype/region/homo_sapiens/7:140753300-140753400",
        query={"feature_type": "Variation"},
    ),
    request("phenotype_braf_accession", "/phenotype/accession/homo_sapiens/EFO:0000272"),
    request(
        "phenotype_term_observed_timeout",
        "/phenotype/term/homo_sapiens/not-a-real-phenotype-term",
        exclude_on_timeout=True,
        exclude_response=True,
    ),
    request(
        "homology_braf_mouse",
        "/homology/id/homo_sapiens/ENSG00000157764",
        query={"type": "orthologues", "target_species": "mus_musculus", "aligned": "0"},
    ),
    request(
        "genetree_braf",
        "/genetree/member/id/homo_sapiens/ENSG00000157764",
        exclude_on_timeout=True,
    ),
    request(
        "cafe_official_example",
        "/cafe/genetree/id/ENSGT00390000003602",
        exclude_on_timeout=True,
    ),
    request(
        "alignment_braf_observed_failure",
        "/alignment/region/homo_sapiens/7:140753336-140753436",
        query={"species_set": "mus_musculus", "method": "EPO"},
        status=400,
        exclude_response=True,
    ),
    request("map_braf_to_grch37", "/map/homo_sapiens/GRCh38/7:140753336..140753436:1/GRCh37"),
    request("map_braf_cdna", "/map/cdna/ENST00000646891/1..100"),
    request("map_braf_cds", "/map/cds/ENST00000646891/1..100"),
    request("map_braf_translation", "/map/translation/ENSP00000493543/1..100"),
    request("ontology_melanoma", "/ontology/id/EFO:0002618"),
    request("ontology_melanoma_ancestors", "/ontology/ancestors/EFO:0002618"),
    request(
        "ontology_melanoma_descendants",
        "/ontology/descendants/EFO:0002618",
        query={"closest_term": "1"},
    ),
    request("ontology_melanoma_name", "/ontology/name/melanoma", exclude_on_timeout=True),
    request("taxonomy_human", "/taxonomy/id/9606"),
    request("taxonomy_human_name", "/taxonomy/name/human"),
    request("taxonomy_human_classification", "/taxonomy/classification/9606"),
    request(
        "regulatory_legacy_route",
        "/regulatory/species/homo_sapiens/id/ENSR00001222813",
        status=404,
        exclude_response=True,
    ),
    request(
        "regulatory_binding_matrix",
        "/species/homo_sapiens/binding_matrix/ENSPFM0001",
        query={"unit": "frequencies"},
    ),
    request("transcript_haplotypes_braf", "/transcript_haplotypes/homo_sapiens/ENST00000646891"),
    request("vep_braf_id", "/vep/homo_sapiens/id/rs113488022"),
    request("vep_braf_hgvs", "/vep/homo_sapiens/hgvs/7:g.140753336A>T"),
    request("vep_braf_region", "/vep/homo_sapiens/region/7:140753336-140753336/T"),
    request(
        "ld_braf_empty",
        "/ld/homo_sapiens/rs113488022/1000GENOMES:phase_3:CEU",
        query={"d_prime": "0.8"},
    ),
    request(
        "ld_rs699_observed",
        "/ld/homo_sapiens/rs699/1000GENOMES:phase_3:CEU",
        query={"d_prime": "0.8"},
    ),
    request(
        "ld_pairwise_official_example",
        "/ld/homo_sapiens/pairwise/rs6792369/rs1042779",
        query={"population_name": "1000GENOMES:phase_3:KHV"},
    ),
    request(
        "ld_region_official_example",
        "/ld/homo_sapiens/region/6:25837556..25843455/1000GENOMES:phase_3:KHV",
    ),
    request(
        "ga4gh_variants_obsolete", "/ga4gh/variants/not-real", status=400, exclude_response=True
    ),
    request("ga4gh_features_empty_remnant", "/ga4gh/features/not-real", exclude_response=True),
    request(
        "ga4gh_reference_sets_obsolete",
        "/ga4gh/referencesets/not-real",
        status=404,
        exclude_response=True,
    ),
)


TESTED_EXCLUSION_REASONS = {
    "variation_pmids_wrong_identifier": "invalid_nonofficial_probe",
    "sequence_braf_cdna": "bounded_timeout_if_unavailable",
    "phenotype_term_observed_timeout": "bounded_timeout",
    "genetree_braf": "bounded_timeout_if_unavailable",
    "cafe_official_example": "bounded_timeout_if_unavailable",
    "ontology_melanoma_name": "bounded_timeout_if_unavailable",
    "alignment_braf_observed_failure": "provider_rejected_bounded_alignment",
    "regulatory_legacy_route": "obsolete_legacy_route",
    "ga4gh_variants_obsolete": "obsolete_ga4gh_route",
    "ga4gh_features_empty_remnant": "obsolete_ga4gh_remnant",
    "ga4gh_reference_sets_obsolete": "obsolete_ga4gh_route",
}


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.last_request: dict[str, Any] | None = None
        self.last_response: dict[str, Any] | None = None

    def handle_request(self, request_: httpx.Request) -> httpx.Response:
        if request_.method != "GET":
            raise ValueError("Ensembl evidence capture may issue only GET requests")
        parsed = urlparse(str(request_.url))
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"Ensembl evidence request escaped the exact HTTPS host: {request_.url}"
            )
        self.last_request = {
            "method": request_.method,
            "url": str(request_.url),
            "accept": request_.headers.get("accept"),
            "content_type": request_.headers.get("content-type"),
            "authorization_present": "authorization" in request_.headers,
            "cookie_present": "cookie" in request_.headers,
        }
        response = self._transport.handle_request(request_)
        self.last_response = {
            "status": response.status_code,
            "headers": {
                name: response.headers[name]
                for name in (
                    "content-type",
                    "content-length",
                    "date",
                    "x-ratelimit-limit",
                    "x-ratelimit-period",
                    "x-ratelimit-remaining",
                    "x-ratelimit-reset",
                    "retry-after",
                )
                if response.headers.get(name) is not None
            },
        }
        return response

    def close(self) -> None:
        self._transport.close()


def body_bytes(body: Any) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def capture(spec: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    transport = RecordingTransport()
    live = LiveGateConfig(
        upstreams={
            "ensembl": LiveUpstream(
                base_url=BASE,
                static_headers={
                    **JSON_HEADERS,
                    "user-agent": "datalox-ensembl-public-evidence/1.0",
                },
            )
        }
    )
    client = LiveCaptureClient(live, timeout=timeout_seconds, transport=transport)
    try:
        response = client.fetch(CallRequest("GET", f"/ensembl{spec['path']}", query=spec["query"]))
    finally:
        client.close()
    if response.status_code != spec["expected_status"]:
        raise ValueError(
            f"unexpected status for {spec['id']}: {response.status_code}; "
            f"expected {spec['expected_status']}; body={str(response.body)[:500]}"
        )
    if transport.last_request is None or transport.last_response is None:
        raise ValueError(f"transport evidence missing for {spec['id']}")
    if transport.last_request["authorization_present"] or transport.last_request["cookie_present"]:
        raise ValueError(f"secret-bearing request header observed for {spec['id']}")
    serialized = body_bytes(response.body)
    query = urlencode(spec["query"])
    url = f"{BASE}{spec['path']}" + (f"?{query}" if query else "")
    return {
        "id": spec["id"],
        "method": "GET",
        "path": spec["path"],
        "query": dict(spec["query"]),
        "url": url,
        "final_url": transport.last_request["url"],
        "status": response.status_code,
        "request_headers": {
            "accept": JSON_HEADERS["accept"],
            "content-type": JSON_HEADERS["content-type"],
        },
        "response_headers": transport.last_response["headers"],
        "body": response.body,
        "body_representation": "text" if isinstance(response.body, str) else "json",
        "body_bytes": len(serialized),
        "body_sha256": f"sha256:{hashlib.sha256(serialized).hexdigest()}",
        "captured_at": datetime.now(UTC).isoformat(),
        "provenance": {
            "authentication": "credential_free",
            "environment": "public_production_read",
            "grounding_level": "G3_PUBLIC_PRODUCTION",
            "sandbox": False,
        },
        "redaction": {"agent_auth_cookie_or_secret_headers_forwarded": False},
    }


def payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider_id": "ensembl",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": "GET",
        "capture_count": len(records),
        "secret_headers_forwarded": False,
        "checkpointed_per_capture": True,
        "captures": records,
    }


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def checkpoint(records: list[dict[str, Any]]) -> None:
    atomic_write_json(OUTPUT, payload(records))


def exclusion_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider_id": "ensembl",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": "GET",
        "tested_exclusion_count": len(records),
        "checkpointed_per_attempt": True,
        "tested_exclusions": records,
    }


def checkpoint_exclusions(records: list[dict[str, Any]]) -> None:
    atomic_write_json(EXCLUSIONS_OUTPUT, exclusion_payload(records))


def load_checkpoint() -> list[dict[str, Any]]:
    if not OUTPUT.exists():
        return []
    existing = json.loads(OUTPUT.read_text(encoding="utf-8"))
    records = list(existing.get("captures", []))
    known_ids = {spec["id"] for spec in REQUESTS}
    completed_ids = [record.get("id") for record in records]
    if len(completed_ids) != len(set(completed_ids)):
        raise ValueError("Ensembl evidence checkpoint contains duplicate capture IDs")
    unknown_ids = sorted(set(completed_ids) - known_ids)
    if unknown_ids:
        raise ValueError(f"Ensembl evidence checkpoint contains unknown capture IDs: {unknown_ids}")
    return records


def load_exclusions() -> list[dict[str, Any]]:
    if not EXCLUSIONS_OUTPUT.exists():
        return []
    existing = json.loads(EXCLUSIONS_OUTPUT.read_text(encoding="utf-8"))
    records = list(existing.get("tested_exclusions", []))
    ids = [record.get("id") for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("Ensembl tested exclusions contain duplicate capture IDs")
    unknown_ids = sorted(set(ids) - TESTED_EXCLUSION_REASONS.keys())
    if unknown_ids:
        raise ValueError(f"Ensembl tested exclusions contain unknown capture IDs: {unknown_ids}")
    return records


def tested_exclusion_from_capture(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "reason_code": TESTED_EXCLUSION_REASONS[record["id"]],
        "observed_outcome": "http_response",
        "method": record["method"],
        "path": record["path"],
        "query": record["query"],
        "status": record["status"],
        "body": record["body"],
        "body_sha256": record["body_sha256"],
        "response_headers": record["response_headers"],
        "observed_at": record["captured_at"],
        "grounding_level": "G3_PUBLIC_PRODUCTION",
        "promoted_as_tool": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    args = parser.parse_args()
    records = [] if args.restart else load_checkpoint()
    exclusions = [] if args.restart else load_exclusions()
    excluded = {item["id"] for item in exclusions}
    specs_by_id = {spec["id"]: spec for spec in REQUESTS}
    for record in records:
        if specs_by_id[record["id"]]["exclude_response"] and record["id"] not in excluded:
            exclusions.append(tested_exclusion_from_capture(record))
            excluded.add(record["id"])
            checkpoint_exclusions(exclusions)
    completed = {item["id"] for item in records}
    for spec in REQUESTS:
        if spec["id"] in completed or spec["id"] in excluded:
            continue
        try:
            record = capture(spec, timeout_seconds=args.timeout_seconds)
        except (httpx.TimeoutException, LiveCaptureError) as exc:
            is_timeout = isinstance(exc, httpx.TimeoutException) or (
                isinstance(exc, LiveCaptureError) and exc.code == "live_upstream_unreachable"
            )
            if not spec["exclude_on_timeout"] or not is_timeout:
                raise
            exclusion = {
                "id": spec["id"],
                "reason_code": TESTED_EXCLUSION_REASONS[spec["id"]],
                "observed_outcome": "bounded_timeout",
                "method": "GET",
                "path": spec["path"],
                "query": dict(spec["query"]),
                "timeout_seconds": args.timeout_seconds,
                "exception_type": type(exc).__name__,
                "observed_at": datetime.now(UTC).isoformat(),
                "grounding_level": "G3_PUBLIC_PRODUCTION_PROBE",
                "promoted_as_tool": False,
            }
            exclusions.append(exclusion)
            checkpoint_exclusions(exclusions)
            print(f"excluded {spec['id']}: bounded timeout", flush=True)
            continue
        records.append(record)
        checkpoint(records)
        if spec["exclude_response"]:
            exclusions.append(tested_exclusion_from_capture(record))
            checkpoint_exclusions(exclusions)
        print(
            f"captured {spec['id']}: {record['status']} ({record['body_bytes']} bytes)", flush=True
        )
    accounted = {record["id"] for record in records} | {record["id"] for record in exclusions}
    if accounted != {spec["id"] for spec in REQUESTS}:
        raise ValueError("Ensembl evidence does not account for every requested capture ID")
    checkpoint(records)
    checkpoint_exclusions(exclusions)
    print(f"wrote {len(records)} captures and {len(exclusions)} tested exclusions")


if __name__ == "__main__":
    main()
