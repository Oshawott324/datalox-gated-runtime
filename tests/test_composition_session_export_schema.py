from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from test_composition_session import _session


ROOT = Path(__file__).resolve().parents[1]


def test_composition_session_export_matches_public_schema(tmp_path: Path) -> None:
    session, _, _ = _session(tmp_path)
    schema = json.loads(
        (ROOT / "schemas/composition-session-export-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    validator.validate(session.export())
    validator.validate(session.finalize())
