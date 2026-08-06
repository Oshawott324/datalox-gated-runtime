#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from html import unescape
import json
from pathlib import Path
import re
import sys
from typing import Any

import httpx


ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "envs/ensembl_public_v0"
CATALOG = ENV / "evidence/official_endpoint_catalog.json"
PINS = ENV / "evidence/official_source_pins.json"
SOURCE_COMMIT = "45d2746e23ab43a6a2a9c1bbe726404c3ce003e1"
WIKI_COMMIT = "71b19abbf3c8d6b52e3476f50d3eb19018c3536e"
INDEX_URL = "https://rest.ensembl.org/"
SOURCE_RAW = f"https://raw.githubusercontent.com/Ensembl/ensembl-rest/{SOURCE_COMMIT}/"
# GitHub exposes wiki raw files only at the current wiki head. We pin every
# returned byte below and record the independently observed git head; the
# checker fails on either content drift or an updated generated artifact.
WIKI_RAW = "https://raw.githubusercontent.com/wiki/Ensembl/ensembl-rest/"
CONFIG_FILES = (
    "archive.conf",
    "assembly.conf",
    "compara.conf",
    "compara_grch37.conf",
    "gabeacon.conf",
    "gacallset.conf",
    "gadataset.conf",
    "gafeatures.conf",
    "gafeatureset.conf",
    "gareferences.conf",
    "gareferenceset.conf",
    "gavariant.conf",
    "gavariantannotation.conf",
    "gavariantannotationset.conf",
    "gavariantset.conf",
    "info.conf",
    "info_grch37.conf",
    "ld.conf",
    "lookup.conf",
    "map.conf",
    "ontology.conf",
    "overlap.conf",
    "phenotypefeatures.conf",
    "regulatory.conf",
    "sequence.conf",
    "taxonomy.conf",
    "transcripthaplotypes.conf",
    "variation.conf",
    "vep.conf",
    "xrefs.conf",
)
WIKI_FILES = (
    "HTTP-Response-Codes.md",
    "Output-formats.md",
    "POST-Requests.md",
    "Rate-Limits.md",
)
SUPPORT_FILES = (
    "ensembl_rest.conf.default",
    "lib/EnsEMBL/REST/Role/PostLimiter.pm",
    "lib/EnsEMBL/REST/Role/Content.pm",
    "lib/EnsEMBL/REST/Role/Sequence.pm",
    "lib/EnsEMBL/REST/View/FASTAText.pm",
    "lib/EnsEMBL/REST/View/SeqXML.pm",
    "lib/EnsEMBL/REST/View/SequenceText.pm",
    "lib/EnsEMBL/REST/Controller/Archive.pm",
    "lib/EnsEMBL/REST/Controller/Lookup.pm",
    "lib/EnsEMBL/REST/Controller/Sequence.pm",
    "lib/EnsEMBL/REST/Controller/VEP.pm",
    "lib/EnsEMBL/REST/Controller/VariantRecoder.pm",
    "lib/EnsEMBL/REST/Controller/Variation.pm",
    "lib/EnsEMBL/REST/Controller/GeneTree.pm",
    "lib/EnsEMBL/REST/Controller/Homology.pm",
    "lib/EnsEMBL/REST/Controller/Ontology.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/Beacon.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/annotationSets.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/callSet.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/datasets.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/featureSets.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/features.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/referenceSets.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/references.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/variantSet.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/variantannotations.pm",
    "lib/EnsEMBL/REST/Controller/ga4gh/variants.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/Beacon.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/annotationSets.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/callSet.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/datasets.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/featureSets.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/features.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/ga4gh_utils.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/referenceSets.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/references.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/variantSet.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/variantannotations.pm",
    "lib/EnsEMBL/REST/Model/ga4gh/variants.pm",
)
EVIDENCE_FILES = (
    "public_get_capture.json",
    "tested_exclusions.json",
    "public_get_format_capture.json",
    "public_get_control_capture.json",
    "public_get_core_capture.json",
    "public_get_closure_capture.json",
    "public_get_supplement_capture.json",
    "public_get_xml_shape_capture.json",
    "public_get_variation_default_capture.json",
    "public_get_variation_default_xml_capture.json",
    "public_get_gap_retry_capture.json",
    "public_get_ontology_success_capture.json",
    "public_get_symbol_success_capture.json",
    "public_get_ga4gh_dataset_capture.json",
    "public_nonmutating_process_capture.json",
)
FAMILY_IDS = {
    "Archive": "archive",
    "Comparative Genomics": "comparative_genomics",
    "Cross References": "cross_references",
    "Information": "information",
    "Linkage Disequilibrium": "linkage_disequilibrium",
    "Lookup": "lookup",
    "Mapping": "mapping",
    "Ontologies and Taxonomy": "ontologies_and_taxonomy",
    "Overlap": "overlap",
    "Phenotype annotations": "phenotype_annotations",
    "Regulation": "regulation",
    "Sequence": "sequence",
    "Transcript Haplotypes": "transcript_haplotypes",
    "VEP": "vep",
    "Variation": "variation",
    "Variation GA4GH": "variation_ga4gh",
}
POST_LIMITS = {
    "archive_id_post": 1000,
    "lookup_post": 1000,
    "symbol_post": 1000,
    "sequence_id_post": 50,
    "sequence_region_post": 50,
    "vep_hgvs_post": 200,
    "vep_id_post": 200,
    "vep_region_post": 200,
    "variant_recoder_post": 200,
    "variation_post": 200,
}
BODY_KEYS = {
    "archive_id_post": ("id",),
    "lookup_post": ("ids",),
    "symbol_post": ("symbols",),
    "sequence_id_post": ("ids",),
    "sequence_region_post": ("regions",),
    "vep_hgvs_post": ("hgvs_notations",),
    "vep_id_post": ("ids",),
    "vep_region_post": ("variants",),
    "variant_recoder_post": ("ids",),
    "variation_post": ("ids",),
}
BODY_OPTION_POSTS = {
    "lookup_post",
    "symbol_post",
    "sequence_id_post",
    "sequence_region_post",
    "vep_hgvs_post",
    "vep_id_post",
    "vep_region_post",
    "variant_recoder_post",
}


def fetch(url: str) -> bytes:
    last_error: Exception | None = None
    for _ in range(3):
        try:
            response = httpx.get(
                url,
                headers={"User-Agent": "datalox-ensembl-contract-audit/1"},
                timeout=45,
                follow_redirects=True,
            )
            response.raise_for_status()
            return response.content
        except httpx.HTTPError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text(value: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "", value)).strip().strip('"')


def index_operations(index: str) -> list[dict[str, Any]]:
    token = re.compile(
        r"<h3[^>]*>(?P<group>.*?)</h3>|"
        r"<a[^>]+href=[\"'](?P<href>[^\"']*/documentation/info/(?P<doc>[A-Za-z0-9_]+))[\"'][^>]*>"
        r"(?P<label>.*?)</a>",
        re.I | re.S,
    )
    group: str | None = None
    operations: list[dict[str, Any]] = []
    for match in token.finditer(index):
        if match.group("group") is not None:
            candidate = _text(match.group("group"))
            if candidate in FAMILY_IDS:
                group = candidate
            continue
        label = _text(match.group("label"))
        route = re.fullmatch(r"(GET|POST)\s+(.+)", label)
        if route is None or group is None:
            continue
        operations.append(
            {
                "id": match.group("doc"),
                "method": route.group(1),
                "endpoint": route.group(2).strip(),
                "family": FAMILY_IDS[group],
                "family_label": group,
                "documentation_url": f"https://rest.ensembl.org/documentation/info/{match.group('doc')}",
            }
        )
    if len(operations) != 106:
        raise ValueError(f"official index must contain 106 operations, found {len(operations)}")
    if sum(item["method"] == "GET" for item in operations) != 85:
        raise ValueError("official index GET count changed")
    if sum(item["method"] == "POST" for item in operations) != 21:
        raise ValueError("official index POST count changed")
    return operations


def sections(config: str) -> dict[str, str]:
    # Several official .conf files have one-space indentation or mismatched
    # closing-tag case. The next top-level section is the reliable delimiter.
    starts = list(re.finditer(r"^ {0,2}<([A-Za-z0-9_]+)>\s*$", config, re.M))
    result: dict[str, str] = {}
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(config)
        result[match.group(1)] = config[match.end() : end]
    return result


def source_details(operation: dict[str, Any], configs: dict[str, bytes]) -> dict[str, Any]:
    matches: list[tuple[str, str]] = []
    for name, raw in configs.items():
        if name.endswith("_grch37.conf"):
            continue
        body = sections(raw.decode("utf-8"))
        if operation["id"] in body:
            matches.append((name, body[operation["id"]]))
    if len(matches) != 1:
        raise ValueError(f"{operation['id']} source section count is {len(matches)}")
    source_file, body = matches[0]
    params_match = re.search(r"<params>\s*(.*?)</params>", body, re.S)
    params: dict[str, Any] = {}
    if params_match:
        param_starts = list(
            re.finditer(r"^[ \t]*<([A-Za-z0-9_]+)>[ \t]*$", params_match.group(1), re.M)
        )
        for index, match in enumerate(param_starts):
            end = (
                param_starts[index + 1].start()
                if index + 1 < len(param_starts)
                else len(params_match.group(1))
            )
            section = params_match.group(1)[match.end() : end]
            name = match.group(1)
            item: dict[str, Any] = {}
            for field in ("type", "default", "required", "description"):
                value = re.search(rf"^[ \t]+{field}=(.+)$", section, re.M)
                if value:
                    item[field] = _text(value.group(1))
            examples = [
                _text(value) for value in re.findall(r"^[ \t]+example=(.+)$", section, re.M)
            ]
            if examples:
                item["examples"] = examples
            if "multiple values" in item.get("description", "").lower():
                item["repeatable"] = True
            params[name] = item
    outputs = [_text(value) for value in re.findall(r"^[ \t]+output=(.+)$", body, re.M)]
    if "json" in outputs:
        outputs.append("jsonp")
        params.setdefault(
            "callback",
            {"type": "String", "required": "0", "source": "rendered documentation generator"},
        )
    description = re.search(r"^[ \t]+description=(.+)$", body, re.M)
    postformat = re.search(r"^\s*postformat=(.+)$", body, re.M)
    details = {
        "source_file": f"root/documentation/{source_file}",
        "description": _text(description.group(1)) if description else "",
        "params": params,
        "response_formats": outputs or ["json"],
    }
    if operation["method"] == "POST":
        details["max_post_items"] = POST_LIMITS.get(operation["id"])
        details["postformat"] = _text(postformat.group(1)) if postformat else None
        details["body_collection_keys"] = list(BODY_KEYS.get(operation["id"], ()))
    return details


def build() -> tuple[dict[str, Any], dict[str, Any]]:
    index_raw = fetch(INDEX_URL)
    configs = {name: fetch(SOURCE_RAW + "root/documentation/" + name) for name in CONFIG_FILES}
    support = {name: fetch(SOURCE_RAW + name) for name in SUPPORT_FILES}
    wiki = {name: fetch(WIKI_RAW + name) for name in WIKI_FILES}
    operations = index_operations(index_raw.decode("utf-8"))
    for operation in operations:
        operation.update(source_details(operation, configs))
    # Operational corrections are explicit, not silent repairs of malformed titles/config.
    by_id = {item["id"]: item for item in operations}
    by_id["symbol_post"]["canonical_endpoint"] = "lookup/symbol/:species"
    by_id["symbol_post"]["contract_note"] = (
        "Live example/controller omit the title's trailing :symbol for POST."
    )
    by_id["variation_population_name"]["canonical_endpoint"] = (
        "info/variation/populations/:species/:population_name"
    )
    by_id["variation_population_name"]["contract_note"] = (
        "Live index contains a stray colon after :species."
    )
    by_id["features_post"]["contract_note"] = (
        "Official GA4GH config has malformed indentation and a mismatched pageSize closing tag; "
        "the rendered live documentation supplies the operational fields."
    )
    by_id["beacon_query_post"]["body_constraints"] = {
        "required": ["referenceName", "referenceBases", "assemblyId"],
        "exclusive_branches": [
            {"required": ["start", "alternateBases"], "forbidden": ["end", "variantType"]},
            {"required": ["start", "end", "variantType"], "forbidden": ["alternateBases"]},
            {"required": ["start", "end"], "forbidden": ["alternateBases", "variantType"]},
        ],
        "note": "Pinned Beacon model supports alternate, structural-type, or range request shapes.",
    }
    by_id["beacon_query_get"]["query_constraints"] = dict(
        by_id["beacon_query_post"]["body_constraints"]
    )
    for identifier in ("beacon_query_get", "beacon_query_post"):
        by_id[identifier]["params"]["start"]["type"] = "IntOrPair"
        by_id[identifier]["params"]["end"]["type"] = "IntOrPair"
    raw_feature = by_id["features_post"]["params"].pop("featuresetId")
    by_id["features_post"]["params"]["featureSetId"] = raw_feature
    by_id["features_post"]["raw_parameter_aliases"] = {"featuresetId": "featureSetId"}
    by_id["features_post"]["contract_note"] += " Operational examples/controller use featureSetId."
    by_id["gavariants"]["params"]["callSetIds"]["type"] = "array of strings"
    by_id["gavariants"]["contract_note"] = (
        "Raw type label says String; postformat/controller require an array."
    )
    by_id["gavariantannotations"]["params"]["effects"]["type"] = "array of OntologyTerm objects"
    by_id["gavariantannotations"]["contract_note"] = (
        "Pinned GA4GH model accepts effect objects and dereferences each object's term field."
    )
    for identifier in ("gadataset", "gavariantset"):
        by_id[identifier]["params"]["pageToken"]["type"] = "String"
        by_id[identifier]["contract_note"] = by_id[identifier].get("contract_note", "") + (
            " The pinned model compares pageToken to provider ID strings; the rendered Int label is incorrect."
        )
    by_id["features_post"]["body_constraints"] = {
        "required": ["referenceName", "start", "end"],
        "one_of_required": ["parentId", "featureSetId"],
        "ordered_bounds": ["start", "end"],
    }
    by_id["gavariantannotations"]["body_constraints"] = {
        "required": ["variantAnnotationSetId", "start", "end"],
        "one_of_required": ["referenceName", "referenceId"],
        "strict_ordered_bounds": ["start", "end"],
    }
    by_id["gavariants"]["body_constraints"] = {
        "required": ["variantSetId", "referenceName", "start", "end"],
        "strict_ordered_bounds": ["start", "end"],
    }
    for identifier, controller_default in {
        "features_post": 200,
        "gadataset": 100,
        "references": 50,
        "gavariantannotations": 50,
    }.items():
        suffix = (
            f" Rendered 15.12 docs default pageSize=10; pinned controller default is {controller_default}. "
            "The local contract follows the rendered deployment documentation."
        )
        by_id[identifier]["contract_note"] = by_id[identifier].get("contract_note", "") + suffix
    for identifier in ("sequence_id", "sequence_id_post"):
        by_id[identifier]["argument_constraints"] = {
            "mutually_exclusive": [["mask", "mask_feature"]],
            "incompatible_groups": [["start", "end"], ["expand_5prime", "expand_3prime"]],
        }
    for identifier in ("sequence_region", "sequence_region_post"):
        by_id[identifier]["argument_constraints"] = {
            "mutually_exclusive": [["mask", "mask_feature"]],
        }
    by_id["genomic_alignment_region"]["argument_constraints"] = {
        "mutually_exclusive": [["species_set", "species_set_group"]],
    }
    for identifier, raw_name, path_name in (
        ("info_genome", "name", "genome_name"),
        ("info_genomes_division", "division", "division_name"),
        ("get_binding_matrix", "binding_matrix", "binding_matrix_stable_id"),
    ):
        metadata = by_id[identifier]["params"].pop(raw_name)
        by_id[identifier].setdefault("raw_parameter_aliases", {})[raw_name] = path_name
        by_id[identifier].setdefault("path_parameter_metadata", {})[path_name] = metadata
    for operation in operations:
        for name in ("d_prime", "r2"):
            if name in operation["params"]:
                operation["params"][name].update({"minimum": 0, "maximum": 1})
        if operation["family"] == "variation_ga4gh":
            for name in ("start", "end", "pageSize"):
                if name in operation["params"]:
                    operation["params"][name]["minimum"] = 0
            if "pageSize" in operation["params"]:
                operation["params"]["pageSize"]["maximum"] = 1000
    for identifier in ("beacon_query_get", "beacon_query_post"):
        params = by_id[identifier]["params"]
        params["referenceName"]["pattern"] = r"^(?:[1-9]|1[0-9]|2[0-2]|[Xx]|[Yy]|[Mm][Tt])$"
        params["referenceBases"]["pattern"] = r"^(?:[AaGgCcTt]+|[Nn])$"
        params["alternateBases"]["pattern"] = r"^(?:[AaGgCcTt]+|[Nn])$"
        params["assemblyId"]["pattern"] = r"^[Gg][Rr][Cc][Hh](?:37|38)$"
        params["variantType"]["pattern"] = (
            r"^(?:[Dd][Uu][Pp]|[Dd][Ee][Ll]|[Ii][Nn][Ss]|[Ii][Nn][Vv]|[Cc][Nn][Vv]|"
            r"[Dd][Uu][Pp]:[Tt][Aa][Nn][Dd][Ee][Mm]|[Ii][Nn][Ss]:[Mm][Ee]|[Dd][Ee][Ll]:[Mm][Ee])$"
        )
        params["includeResultsetResponses"]["enum"] = ["ALL", "HIT", "MISS", "NONE"]
        for name in ("start", "end", "datasetIds"):
            params[name]["serialization"] = "comma_delimited_single_query_value"
        by_id[identifier]["contract_note"] = by_id[identifier].get("contract_note", "") + (
            " Beacon IntOrPair coordinates and datasetIds arrays are consumed as one comma-delimited query value."
        )
    for identifier in ("vep_region_get", "variation_post"):
        by_id[identifier]["canonical_endpoint"] = by_id[identifier]["endpoint"].rstrip("/")
        by_id[identifier]["contract_note"] = (
            "Canonical local route omits an optional trailing slash."
        )
    for operation in operations:
        endpoint = operation.get("canonical_endpoint", operation["endpoint"])
        path_fields = list(dict.fromkeys(re.findall(r":([A-Za-z0-9_]+)", endpoint)))
        operation["path_fields"] = path_fields
        non_path = [name for name in operation["params"] if name not in path_fields]
        if operation["method"] == "GET":
            operation["query_fields"] = non_path
            continue
        if operation["family"] == "variation_ga4gh":
            operation["body_fields"] = [name for name in non_path if name != "callback"]
            operation["query_fields"] = ["callback"] if "callback" in non_path else []
        elif operation["id"] in BODY_OPTION_POSTS:
            operation["body_fields"] = list(
                dict.fromkeys(
                    (
                        *operation["body_collection_keys"],
                        *(name for name in non_path if name != "callback"),
                    )
                )
            )
            operation["query_fields"] = non_path
            operation["dual_location_fields"] = sorted(
                set(operation["body_fields"]) & set(operation["query_fields"])
            )
        else:
            operation["body_fields"] = list(operation["body_collection_keys"])
            operation["query_fields"] = [
                name for name in non_path if name not in operation["body_collection_keys"]
            ]
    catalog = {
        "schema_version": "datalox_ensembl_official_endpoint_catalog_v1",
        "provider_id": "ensembl",
        "deployment": "Ensembl REST 15.12 / Ensembl release 116",
        "source_commit": SOURCE_COMMIT,
        "route_count": 106,
        "get_count": 85,
        "post_count": 21,
        "family_count": 16,
        "families": FAMILY_IDS,
        "operations": operations,
    }
    pins = {
        "schema_version": "datalox_official_source_pins_v1",
        "provider_id": "ensembl",
        "checked_at": "2026-07-23",
        "live_index": {"url": INDEX_URL, "sha256": digest(index_raw)},
        "source": {
            "repository": "https://github.com/Ensembl/ensembl-rest",
            "ref": "release/116",
            "commit": SOURCE_COMMIT,
            "artifacts": {
                **{f"root/documentation/{name}": digest(raw) for name, raw in configs.items()},
                **{name: digest(raw) for name, raw in support.items()},
            },
        },
        "wiki": {
            "repository": "https://github.com/Ensembl/ensembl-rest.wiki",
            "observed_head_commit": WIKI_COMMIT,
            "retrieval": "current wiki raw bytes, individually SHA256-pinned",
            "artifacts": {name: digest(raw) for name, raw in wiki.items()},
        },
        "evidence_immutability": {
            name: digest((ENV / "evidence" / name).read_bytes()) for name in EVIDENCE_FILES
        },
    }
    return catalog, pins


def encoded(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the pinned Ensembl 15.12 endpoint contract without silently refreshing it."
    )
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--accept-drift", action="store_true")
    args = parser.parse_args()
    catalog, pins = build()
    if args.write:
        if not args.accept_drift and (CATALOG.exists() or PINS.exists()):
            print("refusing to overwrite Ensembl pins without --accept-drift", file=sys.stderr)
            return 2
        CATALOG.write_text(encoded(catalog), encoding="utf-8")
        PINS.write_text(encoded(pins), encoding="utf-8")
        return 0
    failures = []
    for path, expected in ((CATALOG, catalog), (PINS, pins)):
        if not path.exists() or path.read_text(encoding="utf-8") != encoded(expected):
            failures.append(str(path.relative_to(ROOT)))
    if failures:
        print("Ensembl official contract drift: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("Ensembl official contract pins and 106-route catalog are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
