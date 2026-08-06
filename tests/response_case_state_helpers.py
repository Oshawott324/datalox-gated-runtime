from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable

from datalox_gated_runtime.session import create_session

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "response_case_state_v0"
EXAMPLE_ROOT = FIXTURE_ROOT / "example"


def configure_assignee_lookup(example: Path) -> None:
    episodes_path = example / "world" / "episodes.jsonl"
    episodes = [json.loads(line) for line in episodes_path.read_text(encoding="utf-8").splitlines()]
    for episode in episodes:
        assignee = episode["expected"]["assignee"]
        episode["state"]["assignee_directory"] = {
            "items": [{"display": f"Display for {assignee}", "id": assignee}]
        }
    episodes_path.write_text(
        "\n".join(json.dumps(episode) for episode in episodes) + "\n",
        encoding="utf-8",
    )

    transitions_path = example / "world" / "transitions.json"
    transitions = json.loads(transitions_path.read_text(encoding="utf-8"))
    transitions["operations"][0]["effects"].append(
        {
            "match_pointer": "/id",
            "operator": "set_from_state_lookup",
            "request_pointer": "/assignee",
            "source_pointer": "/items",
            "source_state_key": "assignee_directory",
            "state_key": "customer_ticket",
            "target": "/ticket/owner",
            "value_pointer": "/display",
        }
    )
    transitions_path.write_text(json.dumps(transitions), encoding="utf-8")


def create_world_session(
    tmp_path: Path,
    monkeypatch,
    *,
    name: str = "run",
    seed: int = 0,
    configure_example: Callable[[Path], None] | None = None,
) -> Path:
    examples = tmp_path / f"examples-{name}"
    example = examples / "example"
    shutil.copytree(EXAMPLE_ROOT, example)
    if configure_example is not None:
        configure_example(example)
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(examples))
    run_dir = tmp_path / name
    create_session(example="example", out_dir=run_dir, http_port=8765, seed=seed)
    return run_dir
