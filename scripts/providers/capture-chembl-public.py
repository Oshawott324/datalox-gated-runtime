#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/chembl_public_v0/evidence/public_get_capture.json"
HOST = "www.ebi.ac.uk"
BASE = f"https://{HOST}/chembl/api/data/"
REQUESTS = (
    ("status", "status.json", 200),
    ("molecule_list", "molecule.json?molecule_chembl_id=CHEMBL1503&limit=2&offset=0", 200),
    ("molecule_detail", "molecule/CHEMBL1503.json", 200),
    (
        "molecule_exact_structure",
        "molecule.json?molecule_structures__canonical_smiles__flexmatch=COc1ccc2%5BnH%5Dc%28%5BS%2B%5D%28%5BO-%5D%29Cc3ncc%28C%29c%28OC%29c3C%29nc2c1&limit=2&offset=0",
        200,
    ),
    ("molecule_similarity", "similarity/CHEMBL1503/80.json?limit=2&offset=0", 200),
    ("molecule_substructure", "substructure/CHEMBL1503.json?limit=2&offset=0", 200),
    ("target_list", "target.json?target_chembl_id=CHEMBL2095173&limit=2&offset=0", 200),
    ("target_detail", "target/CHEMBL2095173.json", 200),
    (
        "target_component_list",
        "target_component.json?component_id__in=96%2C3508&limit=2&offset=0&order_by=component_id",
        200,
    ),
    ("target_component_detail", "target_component/96.json", 200),
    ("assay_list", "assay.json?assay_chembl_id=CHEMBL690674&limit=2&offset=0", 200),
    ("assay_detail", "assay/CHEMBL690674.json", 200),
    (
        "activity_list",
        "activity.json?molecule_chembl_id=CHEMBL1503&target_chembl_id=CHEMBL2095173&limit=2&offset=0&order_by=activity_id",
        200,
    ),
    ("activity_detail", "activity/218931.json", 200),
    ("mechanism_list", "mechanism.json?molecule_chembl_id=CHEMBL1503&limit=2&offset=0", 200),
    ("mechanism_detail", "mechanism/1080.json", 200),
    (
        "drug_indication_list",
        "drug_indication.json?molecule_chembl_id=CHEMBL1503&mesh_heading__iexact=Gastroesophageal%20Reflux&limit=2&offset=0",
        200,
    ),
    ("drug_indication_detail", "drug_indication/23615.json", 200),
    ("document_list", "document.json?document_chembl_id=CHEMBL1130895&limit=2&offset=0", 200),
    ("document_detail", "document/CHEMBL1130895.json", 200),
    ("source_list", "source.json?src_id=1&limit=2&offset=0", 200),
    ("source_detail", "source/1.json", 200),
    (
        "molecule_form_list",
        "molecule_form.json?molecule_chembl_id=CHEMBL1503&limit=2&offset=0",
        200,
    ),
    ("molecule_form_relationships", "molecule_form/CHEMBL1503.json", 200),
    ("binding_site_list", "binding_site.json?site_id=2651&limit=2&offset=0", 200),
    ("binding_site_detail", "binding_site/2651.json", 200),
    ("molecule_not_found", "molecule/CHEMBL999999999.json", 404),
    ("similarity_cutoff_invalid", "similarity/CHEMBL1503/101.json?limit=1&offset=0", 400),
)
SAFE_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "server",
    "x-frame-options",
)


def capture() -> dict[str, object]:
    requested_at = datetime.now(UTC).isoformat()
    records: list[dict[str, object]] = []
    for capture_id, relative, expected_status in REQUESTS:
        url = BASE + relative
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(f"capture URL is outside the exact ChEMBL host: {url}")
        request = Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "datalox-gated-runtime-public-evidence/1.0",
            },
        )
        try:
            response = urlopen(request, timeout=90)
        except HTTPError as error:
            response = error
        with response:
            body_bytes = response.read()
            final_url = response.geturl()
            if urlparse(final_url).hostname != HOST:
                raise ValueError(f"capture redirected outside the exact ChEMBL host: {final_url}")
            if response.status != expected_status:
                raise ValueError(
                    f"unexpected ChEMBL status for {capture_id}: {response.status}; expected {expected_status}"
                )
            body = json.loads(body_bytes) if body_bytes else None
            headers = {
                name.lower(): response.headers[name]
                for name in SAFE_RESPONSE_HEADERS
                if response.headers.get(name) is not None
            }
            records.append(
                {
                    "id": capture_id,
                    "method": "GET",
                    "url": url,
                    "final_url": final_url,
                    "status": response.status,
                    "response_headers": headers,
                    "captured_at": datetime.now(UTC).isoformat(),
                    "body_sha256": f"sha256:{hashlib.sha256(body_bytes).hexdigest()}",
                    "body_bytes": len(body_bytes),
                    "body": body,
                    "redaction": {
                        "performed": False,
                        "reason": "Public ChEMBL JSON contains no credentials supplied by the agent or capture process.",
                        "agent_auth_cookie_or_secret_headers_forwarded": False,
                    },
                    "provenance": {
                        "grounding_level": "G3_PUBLIC_PRODUCTION",
                        "environment": "public_production_read",
                        "authentication": "credential_free",
                        "sandbox": False,
                    },
                }
            )
    return {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "chembl",
        "requested_at": requested_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "allowed_host": HOST,
        "allowed_method": "GET",
        "request_headers": {
            "Accept": "application/json",
            "User-Agent": "datalox-gated-runtime-public-evidence/1.0",
        },
        "secret_headers_forwarded": False,
        "capture_count": len(records),
        "captures": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    payload = capture()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(args.out), "capture_count": payload["capture_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
