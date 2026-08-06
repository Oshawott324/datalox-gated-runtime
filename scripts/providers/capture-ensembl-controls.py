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
OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_control_capture.json"
CORE_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_core_capture.json"
CLOSURE_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_closure_capture.json"
SUPPLEMENT_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_supplement_capture.json"
VARIATION_DEFAULT_OUTPUT = (
    ROOT / "envs/ensembl_public_v0/evidence/public_get_variation_default_capture.json"
)
GAP_RETRY_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_gap_retry_capture.json"
ONTOLOGY_SUCCESS_OUTPUT = (
    ROOT / "envs/ensembl_public_v0/evidence/public_get_ontology_success_capture.json"
)
SYMBOL_SUCCESS_OUTPUT = (
    ROOT / "envs/ensembl_public_v0/evidence/public_get_symbol_success_capture.json"
)
GA4GH_DATASET_OUTPUT = (
    ROOT / "envs/ensembl_public_v0/evidence/public_get_ga4gh_dataset_capture.json"
)
BASE = "https://rest.ensembl.org"
HOST = "rest.ensembl.org"
HEADERS = {"accept": "application/json", "content-type": "application/json"}


CASES = (
    ("lookup_braf_unexpanded", "/lookup/id/ENSG00000157764", {"expand": "0"}),
    ("lookup_braf_condensed", "/lookup/id/ENSG00000157764", {"format": "condensed"}),
    (
        "sequence_protein_start_10",
        "/sequence/id/ENSP00000493543",
        {"type": "protein", "start": "10"},
    ),
    ("sequence_protein_end_10", "/sequence/id/ENSP00000493543", {"type": "protein", "end": "10"}),
    ("sequence_gene_genomic", "/sequence/id/ENSG00000157764", {"type": "genomic"}),
    (
        "sequence_gene_expand_5prime_10",
        "/sequence/id/ENSG00000157764",
        {"type": "genomic", "expand_5prime": "10"},
    ),
    (
        "sequence_gene_expand_3prime_10",
        "/sequence/id/ENSG00000157764",
        {"type": "genomic", "expand_3prime": "10"},
    ),
    ("sequence_repeat_region", "/sequence/region/homo_sapiens/1:1000000..1001000:1", {}),
    (
        "sequence_repeat_region_hard",
        "/sequence/region/homo_sapiens/1:1000000..1001000:1",
        {"mask": "hard"},
    ),
    (
        "sequence_repeat_region_soft",
        "/sequence/region/homo_sapiens/1:1000000..1001000:1",
        {"mask": "soft"},
    ),
    (
        "sequence_cdna_mask_feature",
        "/sequence/id/ENST00000646891",
        {"type": "cdna", "mask_feature": "1"},
    ),
    (
        "vep_braf_core_controls",
        "/vep/homo_sapiens/id/rs113488022",
        {
            "pick": "1",
            "canonical": "1",
            "hgvs": "1",
            "variant_class": "1",
            "minimal": "1",
            "mane": "1",
        },
    ),
    (
        "recoder_braf_core_controls",
        "/variant_recoder/homo_sapiens/rs113488022",
        {
            "fields": "id,hgvsg,spdi",
            "minimal": "1",
            "vcf_string": "1",
            "var_synonyms": "1",
            "ga4gh_vrs": "1",
        },
    ),
    (
        "variation_braf_core_controls",
        "/variation/homo_sapiens/rs113488022",
        {"genotypes": "1", "phenotypes": "1", "pops": "1", "population_genotypes": "1"},
    ),
)

CLOSURE_CASES = (
    ("core_cafe_member_symbol", "/cafe/genetree/member/symbol/homo_sapiens/BRAF", {}),
    ("core_cafe_member_id", "/cafe/genetree/member/id/homo_sapiens/ENSG00000173786", {}),
    ("core_genetree_id", "/genetree/id/ENSGT00390000003602", {}),
    ("core_genetree_member_symbol", "/genetree/member/symbol/homo_sapiens/BRAF", {}),
    (
        "core_homology_symbol",
        "/homology/symbol/homo_sapiens/BRAF",
        {"target_species": "mus_musculus", "type": "orthologues", "aligned": "0"},
    ),
    ("core_analysis", "/info/analysis/homo_sapiens", {}),
    ("core_biotypes", "/info/biotypes/homo_sapiens", {}),
    ("core_biotypes_group", "/info/biotypes/groups/coding/gene", {}),
    ("core_biotypes_name", "/info/biotypes/name/protein_coding/gene", {}),
    ("core_eg_version", "/info/eg_version", {}),
    ("core_divisions", "/info/divisions", {}),
    ("core_genome", "/info/genomes/homo_sapiens", {}),
    ("core_genomes_accession", "/info/genomes/accession/GCA_000001405.29", {}),
    ("core_genomes_assembly", "/info/genomes/assembly/GRCh38", {}),
    ("core_genomes_division", "/info/genomes/division/EnsemblVertebrates", {}),
    ("core_genomes_taxonomy", "/info/genomes/taxonomy/Primates", {}),
    (
        "core_variation_population",
        "/info/variation/populations/homo_sapiens/1000GENOMES:phase_3:CEU",
        {},
    ),
    ("core_ontology_chart", "/ontology/ancestors/chart/EFO:0002618", {}),
    ("core_ontology_name", "/ontology/name/melanoma", {}),
    ("core_phenotype_term", "/phenotype/term/homo_sapiens/melanoma", {}),
    ("core_variation_pmcid", "/variation/homo_sapiens/pmcid/PMC5002951", {}),
    ("ga4gh_feature", "/ga4gh/features/ENSG00000176515.1", {}),
)

CORE_CASES = (
    ("ga4gh_beacon", "/ga4gh/beacon", {}),
    (
        "ga4gh_beacon_hit",
        "/ga4gh/beacon/query",
        {
            "assemblyId": "GRCh38",
            "referenceBases": "G",
            "alternateBases": "C",
            "start": "22125503",
            "referenceName": "9",
        },
    ),
    (
        "ga4gh_beacon_miss",
        "/ga4gh/beacon/query",
        {
            "assemblyId": "GRCh38",
            "referenceBases": "G",
            "alternateBases": "C",
            "start": "22125504",
            "referenceName": "9",
        },
    ),
    ("ga4gh_callset", "/ga4gh/callsets/1:NA19777", {}),
    ("ga4gh_dataset", "/ga4gh/datasets/6e340c4d1e333c7a676b1710d2e3953c", {}),
    ("ga4gh_featureset", "/ga4gh/featuresets/Ensembl", {}),
    ("ga4gh_variant", "/ga4gh/variants/1:rs1333049", {}),
    ("ga4gh_variantset", "/ga4gh/variantsets/1", {}),
    ("ga4gh_reference", "/ga4gh/references/9489ae7581e14efcad134f02afafe26c", {}),
    ("ga4gh_referenceset", "/ga4gh/referencesets/GRCh38", {}),
    ("ga4gh_variantannotationset", "/ga4gh/variantannotationsets/Ensembl", {}),
    (
        "alignment_epo_mammals",
        "/alignment/region/homo_sapiens/7:140753336-140753436",
        {"species_set_group": "mammals", "method": "EPO"},
    ),
)

SUPPLEMENT_CASES = (
    ("supplement_biotypes", "/info/biotypes/homo_sapiens", {}),
    ("supplement_ga4gh_feature", "/ga4gh/features/ENSG00000176515.1", {}),
    ("supplement_genomes_assembly", "/info/genomes/assembly/GCA_000001405.29", {}),
    ("supplement_genomes_accession", "/info/genomes/accession/KI270757.1", {}),
    ("supplement_cafe_symbol", "/cafe/genetree/member/symbol/homo_sapiens/BRCA2", {}),
    ("supplement_genetree_symbol", "/genetree/member/symbol/homo_sapiens/BRAF", {}),
    (
        "supplement_homology_symbol",
        "/homology/symbol/homo_sapiens/BRAF",
        {"target_species": "mus_musculus", "type": "orthologues", "aligned": "0"},
    ),
    ("supplement_ontology_name", "/ontology/name/melanoma", {}),
    ("supplement_phenotype_term", "/phenotype/term/homo_sapiens/melanoma", {}),
)
VARIATION_DEFAULT_CASES = (("variation_braf_default", "/variation/homo_sapiens/rs113488022", {}),)
GAP_RETRY_CASES = (("gap_biotypes", "/info/biotypes/homo_sapiens", {}),)
ONTOLOGY_SUCCESS_CASES = (
    (
        "ontology_name_pancreatic_carcinoma",
        "/ontology/name/pancreatic%20carcinoma",
        {"ontology": "EFO", "simple": "1"},
    ),
)
SYMBOL_SUCCESS_CASES = (
    (
        "genetree_symbol_arhgap11b",
        "/genetree/member/symbol/homo_sapiens/ARHGAP11B",
        {"prune_species": "homo_sapiens", "sequence": "none"},
    ),
    (
        "homology_symbol_tp53",
        "/homology/symbol/homo_sapiens/TP53",
        {
            "aligned": "0",
            "format": "condensed",
            "sequence": "none",
            "target_species": "mus_musculus",
            "type": "orthologues",
        },
    ),
    (
        "homology_symbol_arhgap11b",
        "/homology/symbol/homo_sapiens/ARHGAP11B",
        {
            "aligned": "0",
            "format": "condensed",
            "sequence": "none",
            "target_species": "mus_musculus",
            "type": "orthologues",
        },
    ),
)
GA4GH_DATASET_CASES = (("ga4gh_dataset_ensembl", "/ga4gh/datasets/Ensembl", {}),)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.request: dict[str, Any] | None = None
        self.response_headers: dict[str, str] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        parsed = urlparse(str(request.url))
        if request.method != "GET" or parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"control evidence escaped the GET-only Ensembl boundary: {request.method} {request.url}"
            )
        self.request = {
            "method": request.method,
            "url": str(request.url),
            "authorization_present": "authorization" in request.headers,
            "cookie_present": "cookie" in request.headers,
        }
        response = self._transport.handle_request(request)
        self.response_headers = {
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
        }
        return response

    def close(self) -> None:
        self._transport.close()


def capture(case: tuple[str, str, dict[str, str]]) -> dict[str, Any]:
    identifier, path, query = case
    transport = RecordingTransport()
    live = LiveGateConfig(
        upstreams={
            "ensembl": LiveUpstream(
                base_url=BASE,
                static_headers={**HEADERS, "user-agent": "datalox-ensembl-control-evidence/1.0"},
            )
        }
    )
    timeout = (
        240 if identifier.startswith("gap_") else 90 if identifier.startswith("supplement_") else 45
    )
    client = LiveCaptureClient(live, timeout=timeout, transport=transport)
    try:
        response = client.fetch(CallRequest("GET", f"/ensembl{path}", query=query))
    finally:
        client.close()
    if transport.request is None or transport.response_headers is None:
        raise ValueError(f"unexpected control response for {identifier}: {response.status_code}")
    if transport.request["authorization_present"] or transport.request["cookie_present"]:
        raise ValueError(f"secret-bearing request observed for {identifier}")
    serialized = (
        response.body.encode()
        if isinstance(response.body, str)
        else json.dumps(response.body, sort_keys=True, separators=(",", ":")).encode()
    )
    return {
        "id": identifier,
        "method": "GET",
        "path": path,
        "query": query,
        "url": BASE + path + (f"?{urlencode(query)}" if query else ""),
        "final_url": transport.request["url"],
        "status": response.status_code,
        "request_headers": HEADERS,
        "response_headers": transport.response_headers,
        "body": response.body,
        "body_representation": "text" if isinstance(response.body, str) else "json",
        "body_bytes": len(serialized),
        "body_sha256": "sha256:" + hashlib.sha256(serialized).hexdigest(),
        "captured_at": datetime.now(UTC).isoformat(),
        "provenance": {
            "authentication": "credential_free",
            "environment": "public_production_read",
            "grounding_level": "G3_PUBLIC_PRODUCTION",
            "sandbox": False,
        },
        "redaction": {"agent_auth_cookie_or_secret_headers_forwarded": False},
    }


def payload(
    records: list[dict[str, Any]], timeouts: list[dict[str, Any]], *, include_outcomes: bool
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "provider_id": "ensembl",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": "GET",
        "capture_count": len(records),
        "secret_headers_forwarded": False,
        "captures": records,
    }
    if include_outcomes:
        value["bounded_timeout_count"] = len(timeouts)
        value["tested_outcomes"] = timeouts
    return value


def write_fsynced(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def run_capture(
    output: Path,
    cases: tuple[tuple[str, str, dict[str, str]], ...],
    *,
    include_outcomes: bool,
    resume: bool = False,
) -> None:
    lock = output.with_suffix(output.suffix + ".lock")
    partial = output.with_suffix(output.suffix + ".partial")
    lock_descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(lock_descriptor)
    try:
        if output.exists() or (partial.exists() and not resume):
            raise FileExistsError(f"refusing concurrent or overwrite capture: {output}")
        saved = json.loads(partial.read_text(encoding="utf-8")) if partial.exists() else {}
        records: list[dict[str, Any]] = list(saved.get("captures", []))
        timeouts: list[dict[str, Any]] = list(saved.get("tested_outcomes", []))
        completed = {item["id"] for item in (*records, *timeouts)}
        expected = {case[0] for case in cases}
        if not completed.issubset(expected):
            raise ValueError(
                f"partial capture contains unexpected cases: {sorted(completed - expected)}"
            )
        for case in cases:
            if case[0] in completed:
                continue
            print(f"capturing {case[0]}", flush=True)
            try:
                records.append(capture(case))
            except LiveCaptureError as error:
                if error.code != "live_upstream_unreachable":
                    raise
                identifier, path, query = case
                timeouts.append(
                    {
                        "id": identifier,
                        "method": "GET",
                        "path": path,
                        "query": query,
                        "observed_outcome": "bounded_timeout",
                        "error_code": error.code,
                        "error_message": error.message,
                        "captured_at": datetime.now(UTC).isoformat(),
                        "provenance": {
                            "authentication": "credential_free",
                            "environment": "public_production_read",
                            "grounding_level": "G3_PUBLIC_PRODUCTION_PROBE",
                            "sandbox": False,
                        },
                        "redaction": {"agent_auth_cookie_or_secret_headers_forwarded": False},
                    }
                )
                print(f"bounded timeout {identifier}: {error.code}", flush=True)
            write_fsynced(partial, payload(records, timeouts, include_outcomes=include_outcomes))
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp"
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            write_fsynced(temporary, payload(records, timeouts, include_outcomes=include_outcomes))
            os.link(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
        partial.unlink()
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture exact Ensembl GET control transformations."
    )
    parser.add_argument(
        "--write", action="store_true", help="Write once; immutable evidence is never overwritten."
    )
    parser.add_argument(
        "--core",
        action="store_true",
        help="Capture bounded GA4GH/alignment core GETs instead of control deltas.",
    )
    parser.add_argument(
        "--closure", action="store_true", help="Capture the remaining official GET operation gaps."
    )
    parser.add_argument(
        "--supplement",
        action="store_true",
        help="Retry bounded closure gaps without overwriting prior evidence.",
    )
    parser.add_argument(
        "--variation-default",
        action="store_true",
        help="Capture the exact default variation JSON baseline.",
    )
    parser.add_argument(
        "--gap-retry",
        action="store_true",
        help="Retry the four remaining GET gaps with a longer bounded window.",
    )
    parser.add_argument(
        "--ontology-success",
        action="store_true",
        help="Capture a fast exact successful ontology-name context.",
    )
    parser.add_argument(
        "--symbol-success",
        action="store_true",
        help="Capture fast exact successful gene-tree and homology symbol contexts.",
    )
    parser.add_argument(
        "--ga4gh-dataset",
        action="store_true",
        help="Capture the second source-defined GA4GH dataset.",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Resume a validated fsynced partial capture."
    )
    args = parser.parse_args()
    if not args.write:
        parser.error("capture is explicit: pass --write")
    if (
        sum(
            (
                args.core,
                args.closure,
                args.supplement,
                args.variation_default,
                args.gap_retry,
                args.ontology_success,
                args.symbol_success,
                args.ga4gh_dataset,
            )
        )
        > 1
    ):
        parser.error("choose only one capture mode")
    output = (
        GA4GH_DATASET_OUTPUT
        if args.ga4gh_dataset
        else SYMBOL_SUCCESS_OUTPUT
        if args.symbol_success
        else ONTOLOGY_SUCCESS_OUTPUT
        if args.ontology_success
        else GAP_RETRY_OUTPUT
        if args.gap_retry
        else VARIATION_DEFAULT_OUTPUT
        if args.variation_default
        else SUPPLEMENT_OUTPUT
        if args.supplement
        else CLOSURE_OUTPUT
        if args.closure
        else CORE_OUTPUT
        if args.core
        else OUTPUT
    )
    cases = (
        GA4GH_DATASET_CASES
        if args.ga4gh_dataset
        else SYMBOL_SUCCESS_CASES
        if args.symbol_success
        else ONTOLOGY_SUCCESS_CASES
        if args.ontology_success
        else GAP_RETRY_CASES
        if args.gap_retry
        else VARIATION_DEFAULT_CASES
        if args.variation_default
        else SUPPLEMENT_CASES
        if args.supplement
        else CLOSURE_CASES
        if args.closure
        else CORE_CASES
        if args.core
        else CASES
    )
    run_capture(
        output,
        cases,
        include_outcomes=args.closure or args.supplement or args.gap_retry or args.symbol_success,
        resume=args.resume,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
