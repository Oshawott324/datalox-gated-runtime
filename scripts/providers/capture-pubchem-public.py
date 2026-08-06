#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from datalox_gated_runtime.capture import LiveCaptureClient
from datalox_gated_runtime.models import CallRequest, LiveGateConfig, LiveUpstream


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/pubchem_public_v0/evidence/public_get_capture.json"
EXCLUSIONS_OUTPUT = ROOT / "envs/pubchem_public_v0/evidence/tested_exclusions.json"
BASE = "https://pubchem.ncbi.nlm.nih.gov"
HOST = "pubchem.ncbi.nlm.nih.gov"
JSON_HEADERS = {"accept": "application/json"}
MIN_INTERVAL_SECONDS = 0.35
TESTED_EXCLUSION_IDS = (
    "substance_description",
    "substance_classification",
    "substance_classification_control",
    "pugview_annotations_page_2",
)


def request(
    capture_id: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    status: int = 200,
    accept: str = "application/json",
) -> dict[str, Any]:
    exact_query = query or {}
    if not all(
        isinstance(key, str) and isinstance(value, str) for key, value in exact_query.items()
    ):
        raise TypeError(f"{capture_id} query must be an exact dict[str, str]")
    return {
        "id": capture_id,
        "path": path,
        "query": exact_query,
        "expected_status": status,
        "accept": accept,
    }


REQUESTS = (
    # Practical compound resolution and one real off-chain compound.
    request("compound_name_aspirin_cids", "/rest/pug/compound/name/aspirin/cids/JSON"),
    request(
        "compound_inchikey_aspirin_cids",
        "/rest/pug/compound/inchikey/BSYNRYMUTXBXSQ-UHFFFAOYSA-N/cids/JSON",
    ),
    request(
        "compound_smiles_aspirin_cids",
        "/rest/pug/compound/smiles/CC(=O)OC1=CC=CC=C1C(=O)O/cids/JSON",
    ),
    request(
        "compound_formula_aspirin_cids", "/rest/pug/compound/formula/C9H8O4/cids/JSON", status=202
    ),
    request(
        "compound_identifier_kegg_cids",
        "/rest/pug/compound/identifier/C01405/cids/JSON",
        query={"identifier_type": "KEGG ID"},
    ),
    request("compound_name_ibuprofen_off_chain", "/rest/pug/compound/name/ibuprofen/cids/JSON"),
    request(
        "compound_name_missing",
        "/rest/pug/compound/name/datalox-not-a-real-compound-20260722/cids/JSON",
        status=404,
    ),
    request(
        "compound_invalid_cid",
        "/rest/pug/compound/cid/not-a-cid/property/MolecularFormula/JSON",
        status=400,
    ),
    # A bounded, real server-side listkey lifecycle and pagination.
    request(
        "compound_listkey_create",
        "/rest/pug/compound/cid/2244,3672/cids/JSON",
        query={"list_return": "listkey"},
    ),
    # Compound record, structure, computed properties, joins, and identifiers.
    request(
        "compound_record_2d", "/rest/pug/compound/cid/2244/record/JSON", query={"record_type": "2d"}
    ),
    request(
        "compound_record_3d", "/rest/pug/compound/cid/2244/record/JSON", query={"record_type": "3d"}
    ),
    request(
        "compound_properties",
        "/rest/pug/compound/cid/2244/property/MolecularFormula,MolecularWeight,CanonicalSMILES,IsomericSMILES,InChI,InChIKey,XLogP,TPSA,Complexity/JSON",
    ),
    request("compound_synonyms", "/rest/pug/compound/cid/2244/synonyms/JSON"),
    request("compound_description", "/rest/pug/compound/cid/2244/description/JSON"),
    request(
        "compound_sids",
        "/rest/pug/compound/cid/2244/sids/JSON",
        query={"sids_type": "standardized", "list_return": "flat"},
    ),
    request(
        "compound_active_aids",
        "/rest/pug/compound/cid/2244/aids/JSON",
        query={"aids_type": "active", "list_return": "flat"},
    ),
    request("compound_assay_summary", "/rest/pug/compound/cid/2244/assaysummary/JSON"),
    request("compound_conformers", "/rest/pug/compound/cid/2244/conformers/JSON"),
    request("compound_identifiers", "/rest/pug/compound/cid/2244/identifiers/JSON"),
    request(
        "compound_dates", "/rest/pug/compound/cid/2244/dates/JSON", query={"dates_type": "creation"}
    ),
    request(
        "compound_record_sdf_2d",
        "/rest/pug/compound/cid/2244/record/SDF",
        query={"record_type": "2d"},
        accept="chemical/x-mdl-sdfile",
    ),
    request(
        "compound_record_sdf_3d",
        "/rest/pug/compound/cid/2244/record/SDF",
        query={"record_type": "3d"},
        accept="chemical/x-mdl-sdfile",
    ),
    # Substance and depositor/source-id semantics selected from the aspirin assay row.
    request("substance_record", "/rest/pug/substance/sid/103164874/record/JSON"),
    request("substance_synonyms", "/rest/pug/substance/sid/103164874/synonyms/JSON"),
    request(
        "substance_cids",
        "/rest/pug/substance/sid/103164874/cids/JSON",
        query={"cids_type": "standardized"},
    ),
    request(
        "substance_aids",
        "/rest/pug/substance/sid/103164874/aids/JSON",
        query={"aids_type": "active"},
    ),
    request("substance_assay_summary", "/rest/pug/substance/sid/103164874/assaysummary/JSON"),
    request(
        "substance_description", "/rest/pug/substance/sid/103164874/description/JSON", status=501
    ),
    request(
        "substance_classification",
        "/rest/pug/substance/sid/103164874/classification/JSON",
        status=500,
    ),
    request(
        "substance_classification_control",
        "/rest/pug/substance/sid/1917/classification/JSON",
        status=500,
    ),
    request(
        "substance_xrefs",
        "/rest/pug/substance/sid/103164874/xrefs/RegistryID,DBURL,SBURL,SourceName,SourceCategory/JSON",
    ),
    request(
        "substance_dates",
        "/rest/pug/substance/sid/103164874/dates/JSON",
        query={"dates_type": "modification,deposition,hold"},
    ),
    request(
        "substance_source_id",
        "/rest/pug/substance/sourceid/ChEMBL/CHEMBL25/sids/JSON",
        query={"list_return": "flat"},
    ),
    # Assay 92967 is directly present in aspirin's active-AID response and summary rows.
    request("assay_record", "/rest/pug/assay/aid/92967/record/JSON"),
    request("assay_description", "/rest/pug/assay/aid/92967/description/JSON"),
    request("assay_summary", "/rest/pug/assay/aid/92967/summary/JSON"),
    request(
        "assay_targets",
        "/rest/pug/assay/aid/92967/targets/ProteinGI,ProteinName,GeneID,GeneSymbol/JSON",
    ),
    request("assay_concise", "/rest/pug/assay/aid/92967/concise/JSON"),
    request(
        "assay_cids",
        "/rest/pug/assay/aid/92967/cids/JSON",
        query={"cids_type": "active", "list_return": "flat"},
    ),
    request(
        "assay_sids",
        "/rest/pug/assay/aid/92967/sids/JSON",
        query={"sids_type": "active", "list_return": "flat"},
    ),
    request("assay_classification", "/rest/pug/assay/aid/92967/classification/JSON", status=200),
    request(
        "assay_dates",
        "/rest/pug/assay/aid/92967/dates/JSON",
        query={"dates_type": "deposition,hold"},
    ),
    request(
        "assay_target_gene_search",
        "/rest/pug/assay/target/geneid/3690/aids/JSON",
        query={"list_return": "flat"},
    ),
    # Current gene, protein, pathway, taxonomy, and cell GET domains.
    request("gene_summary", "/rest/pug/gene/geneid/3690/summary/JSON"),
    request("gene_symbol_summary", "/rest/pug/gene/genesymbol/ITGB3/summary/JSON"),
    request("gene_aids", "/rest/pug/gene/geneid/3690/aids/JSON"),
    request("gene_concise", "/rest/pug/gene/geneid/3690/concise/JSON"),
    request("gene_pathways", "/rest/pug/gene/geneid/3690/pwaccs/JSON"),
    request("protein_summary", "/rest/pug/protein/accession/P05106/summary/JSON"),
    request("protein_aids", "/rest/pug/protein/accession/P05106/aids/JSON"),
    request("protein_concise", "/rest/pug/protein/accession/P05106/concise/JSON"),
    request("protein_pathways", "/rest/pug/protein/accession/P05106/pwaccs/JSON"),
    request("pathway_summary", "/rest/pug/pathway/pwacc/Reactome:R-HSA-109582/summary/JSON"),
    request("pathway_cids", "/rest/pug/pathway/pwacc/Reactome:R-HSA-109582/cids/JSON"),
    request("pathway_geneids", "/rest/pug/pathway/pwacc/Reactome:R-HSA-109582/geneids/JSON"),
    request("pathway_accessions", "/rest/pug/pathway/pwacc/Reactome:R-HSA-109582/accessions/JSON"),
    request("taxonomy_summary", "/rest/pug/taxonomy/taxid/9606/summary/JSON"),
    request("taxonomy_aids", "/rest/pug/taxonomy/taxid/9606/aids/JSON"),
    request("cell_summary", "/rest/pug/cell/cellacc/CVCL_0030/summary/JSON"),
    request("cell_synonym_summary", "/rest/pug/cell/synonym/HeLa/summary/JSON"),
    request("cell_aids", "/rest/pug/cell/cellacc/CVCL_0030/aids/JSON"),
    # Fast structure and formula search families (bounded result sets).
    request(
        "search_fast_identity",
        "/rest/pug/compound/fastidentity/cid/2244/cids/JSON",
        query={"identity_type": "same_connectivity", "MaxRecords": "10"},
    ),
    request(
        "search_fast_similarity_2d",
        "/rest/pug/compound/fastsimilarity_2d/cid/2244/cids/JSON",
        query={"Threshold": "99", "MaxRecords": "10"},
    ),
    request(
        "search_fast_similarity_3d",
        "/rest/pug/compound/fastsimilarity_3d/cid/2244/cids/JSON",
        query={"MaxRecords": "10"},
    ),
    request(
        "search_fast_substructure",
        "/rest/pug/compound/fastsubstructure/cid/2244/cids/JSON",
        query={"StripHydrogen": "true", "MaxRecords": "10"},
    ),
    request(
        "search_fast_superstructure",
        "/rest/pug/compound/fastsuperstructure/cid/2244/cids/JSON",
        query={"MaxRecords": "10"},
    ),
    request(
        "search_fast_formula",
        "/rest/pug/compound/fastformula/C9H8O4/cids/JSON",
        query={"AllowOtherElements": "false", "MaxRecords": "10"},
    ),
    request(
        "search_mass_range",
        "/rest/pug/compound/molecular_weight/range/180.15/180.17/cids/JSON",
        query={"list_return": "flat"},
    ),
    # Public service metadata and other stable GET inputs.
    request("metadata_annotation_headings", "/rest/pug/annotations/headings/JSON"),
    request("metadata_sources_substance", "/rest/pug/sources/substance/JSON"),
    request("metadata_sources_assay", "/rest/pug/sources/assay/JSON"),
    request("metadata_source_table_substance", "/rest/pug/sourcetable/substance/JSON"),
    request(
        "metadata_identifier_types", "/rest/pug/IdentifierTypes/compound/TXT", accept="text/plain"
    ),
    request("metadata_periodic_table", "/rest/pug/periodictable/JSON"),
    request(
        "standardize_smiles",
        "/rest/pug/standardize/smiles/CC(=O)OC1=CC=CC=C1C(=O)O/JSON",
        query={"include_components": "false"},
    ),
    # PUG-View data/index/heading and special reports.
    request("pugview_compound_index", "/rest/pug_view/index/compound/2244/JSON"),
    request("pugview_compound_data", "/rest/pug_view/data/compound/2244/JSON"),
    request(
        "pugview_drug_heading",
        "/rest/pug_view/data/compound/2244/JSON",
        query={"heading": "Drug and Medication Information"},
    ),
    request(
        "pugview_safety_heading",
        "/rest/pug_view/data/compound/2244/JSON",
        query={"heading": "Safety and Hazards"},
    ),
    request(
        "pugview_biological_heading",
        "/rest/pug_view/data/compound/2244/JSON",
        query={"heading": "Biological Test Results"},
    ),
    request("pugview_substance_data", "/rest/pug_view/data/substance/103164874/JSON"),
    request("pugview_assay_data", "/rest/pug_view/data/assay/92967/JSON"),
    request("pugview_gene_data", "/rest/pug_view/data/gene/3690/JSON"),
    request("pugview_protein_data", "/rest/pug_view/data/protein/P05106/JSON"),
    request("pugview_pathway_data", "/rest/pug_view/data/pathway/Reactome:R-HSA-109582/JSON"),
    request("pugview_taxonomy_data", "/rest/pug_view/data/taxonomy/9606/JSON"),
    request("pugview_cell_data", "/rest/pug_view/data/cell/HeLa/JSON"),
    request("pugview_element_data", "/rest/pug_view/data/element/8/JSON"),
    request("pugview_categories", "/rest/pug_view/categories/compound/2244/JSON"),
    request("pugview_literature", "/rest/pug_view/literature/compound/2244/JSON"),
    request("pugview_linkout", "/rest/pug_view/linkout/compound/2244/JSON"),
    request("pugview_structure_links", "/rest/pug_view/structure/compound/2244/JSON"),
    request(
        "pugview_annotations_page_1",
        "/rest/pug_view/annotations/heading/Viscosity/JSON",
        query={"heading_type": "Compound", "page": "1"},
    ),
    request(
        "pugview_annotations_page_2",
        "/rest/pug_view/annotations/heading/Viscosity/JSON",
        query={"heading_type": "Compound", "page": "2"},
        status=500,
    ),
    request("pugview_missing_compound", "/rest/pug_view/data/compound/999999999/JSON", status=404),
)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=0)
        self.last_request: dict[str, Any] | None = None
        self.last_response: dict[str, Any] | None = None

    def handle_request(self, request_: httpx.Request) -> httpx.Response:
        if request_.method != "GET":
            raise ValueError("PubChem evidence capture may issue only GET requests")
        parsed = urlparse(str(request_.url))
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"PubChem evidence request escaped the exact HTTPS host: {request_.url}"
            )
        self.last_request = {
            "method": request_.method,
            "url": str(request_.url),
            "accept": request_.headers.get("accept"),
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
                    "cache-control",
                    "x-throttling-control",
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
            "pubchem": LiveUpstream(
                base_url=BASE,
                static_headers={
                    "accept": spec["accept"],
                    "user-agent": "datalox-pubchem-public-evidence/1.0",
                },
            )
        }
    )
    client = LiveCaptureClient(live, timeout=timeout_seconds, transport=transport)
    try:
        response = client.fetch(
            CallRequest("GET", f"/pubchem{spec['path']}", query=dict(spec["query"]))
        )
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
        "request_headers": {"accept": spec["accept"]},
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
        "provider_id": "pubchem",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": "GET",
        "capture_count": len(records),
        "secret_headers_forwarded": False,
        "checkpointed_per_capture": True,
        "minimum_interval_seconds": MIN_INTERVAL_SECONDS,
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
    exclusions = [record for record in records if record["id"] in TESTED_EXCLUSION_IDS]
    atomic_write_json(
        EXCLUSIONS_OUTPUT,
        {
            "provider_id": "pubchem",
            "provider_base_url": BASE,
            "allowed_host": HOST,
            "allowed_method": "GET",
            "tested_exclusion_count": len(exclusions),
            "complete": len(exclusions) == len(TESTED_EXCLUSION_IDS),
            "tested_exclusions": exclusions,
        },
    )


def load_checkpoint() -> list[dict[str, Any]]:
    if not OUTPUT.exists():
        return []
    records = list(json.loads(OUTPUT.read_text(encoding="utf-8")).get("captures", []))
    ids = [record.get("id") for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("PubChem evidence checkpoint contains duplicate capture IDs")
    known = {spec["id"] for spec in REQUESTS} | {
        "compound_formula_listkey_results",
        "compound_listkey_results",
        "compound_listkey_page",
    }
    unknown = sorted(set(ids) - known)
    if unknown:
        raise ValueError(f"PubChem evidence checkpoint contains unknown capture IDs: {unknown}")
    return records


def listkey_from(record: dict[str, Any]) -> str:
    body = record["body"]
    if not isinstance(body, dict):
        raise ValueError("compound_listkey_create did not return JSON")
    values = body.get("IdentifierList", {})
    waiting = body.get("Waiting", {})
    key = values.get("ListKey") or values.get("CacheKey") or waiting.get("ListKey")
    if not isinstance(key, str) or not key:
        raise ValueError(f"compound_listkey_create returned no ListKey: {body}")
    return key


def dynamic_list_specs(record: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    key = listkey_from(record)
    return (
        request("compound_listkey_results", f"/rest/pug/compound/listkey/{key}/cids/JSON"),
        request(
            "compound_listkey_page",
            f"/rest/pug/compound/listkey/{key}/cids/JSON",
            query={"listkey_start": "1", "listkey_count": "1"},
        ),
    )


def dynamic_formula_spec(record: dict[str, Any]) -> dict[str, Any]:
    key = listkey_from(record)
    return request(
        "compound_formula_listkey_results",
        f"/rest/pug/compound/listkey/{key}/cids/JSON",
        query={"listkey_start": "0", "listkey_count": "10"},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--interval", type=float, default=MIN_INTERVAL_SECONDS)
    args = parser.parse_args()
    if args.interval < MIN_INTERVAL_SECONDS:
        raise SystemExit(f"--interval must be at least {MIN_INTERVAL_SECONDS}")

    records = load_checkpoint()
    completed = {record["id"] for record in records}
    listkey_create = next(
        (record for record in records if record["id"] == "compound_listkey_create"),
        None,
    )
    formula_create = next(
        (record for record in records if record["id"] == "compound_formula_aspirin_cids"),
        None,
    )
    for spec in REQUESTS:
        if spec["id"] not in completed:
            record = capture(spec, timeout_seconds=args.timeout)
            records.append(record)
            completed.add(spec["id"])
            checkpoint(records)
            print(
                f"captured {spec['id']} status={record['status']} bytes={record['body_bytes']}",
                flush=True,
            )
            if spec["id"] == "compound_listkey_create":
                listkey_create = record
            if spec["id"] == "compound_formula_aspirin_cids":
                formula_create = record
            time.sleep(args.interval)
        if spec["id"] == "compound_formula_aspirin_cids":
            if formula_create is None:
                raise ValueError("formula listkey creation checkpoint is missing")
            dynamic = dynamic_formula_spec(formula_create)
            if dynamic["id"] not in completed:
                # One bounded grace period; never poll or retry indefinitely.
                time.sleep(1.5)
                record = capture(dynamic, timeout_seconds=args.timeout)
                records.append(record)
                completed.add(dynamic["id"])
                checkpoint(records)
                print(
                    f"captured {dynamic['id']} status={record['status']} bytes={record['body_bytes']}",
                    flush=True,
                )
                time.sleep(args.interval)
        if spec["id"] == "compound_listkey_create":
            if listkey_create is None:
                raise ValueError("listkey creation checkpoint is missing")
            for dynamic in dynamic_list_specs(listkey_create):
                if dynamic["id"] in completed:
                    continue
                record = capture(dynamic, timeout_seconds=args.timeout)
                records.append(record)
                completed.add(dynamic["id"])
                checkpoint(records)
                print(
                    f"captured {dynamic['id']} status={record['status']} bytes={record['body_bytes']}",
                    flush=True,
                )
                time.sleep(args.interval)
    checkpoint(records)
    print(f"PubChem evidence complete: {len(records)} captures at {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
