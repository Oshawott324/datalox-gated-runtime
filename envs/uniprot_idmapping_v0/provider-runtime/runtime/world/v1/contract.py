from __future__ import annotations

from typing import Any


WORLD_ID = "uniprot_idmapping_v0"
DEFAULT_ROLE = "idmapping_client"
AUTHORITY = "rest.uniprot.org"

SUBMIT_MAPPING = "uniprot.idmapping.run"
GET_STATUS = "uniprot.idmapping.status"
GET_RESULTS = "uniprot.idmapping.uniref_results"


def schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        result["required"] = list(required)
    return result


STRING = {"type": "string", "minLength": 1}
TOOLS = (
    {
        "id": SUBMIT_MAPPING,
        "description": "Submit a UniProt ID Mapping job using the native form fields.",
        "input_schema": schema(
            {"from": STRING, "to": STRING, "ids": STRING}, ("from", "to", "ids")
        ),
        "operation_family": "id_mapping_job",
    },
    {
        "id": GET_STATUS,
        "description": "Read the current status of a provider-issued UniProt ID Mapping job.",
        "input_schema": schema({"job_id": STRING}, ("job_id",)),
        "operation_family": "id_mapping_job",
    },
    {
        "id": GET_RESULTS,
        "description": "Read UniRef results for a completed provider-issued UniProt ID Mapping job.",
        "input_schema": schema({"job_id": STRING}, ("job_id",)),
        "operation_family": "id_mapping_job",
    },
)
TOOLS_BY_ID = {item["id"]: item for item in TOOLS}


def tool_declaration(item: dict[str, Any]) -> dict[str, Any]:
    source_refs = ["uniprot_idmapping_public_production_2026_09_02"]
    if item["id"] == SUBMIT_MAPPING:
        source_refs.append("uniprot_authored_write_completeness_v1")
    return {
        **item,
        "list_roles": [DEFAULT_ROLE],
        "invoke_roles": [DEFAULT_ROLE],
        "source_refs": source_refs,
    }
