"""Fixed downstream task and admitted-provider artifact binding."""

from pathlib import Path

TASK_INSTRUCTIONS = """\
You are integrating with the Medusa Store API.

Collect every product from the paginated product collection. Successful list
responses contain `products`, `count`, `limit`, and `offset`. Call list_products
with limit 10 and offsets 0, 10, 20, and so on until the provider returns an
empty `products` array.

Then call submit_products exactly once with a JSON array containing each
product's `id` and `title` exactly once, plus `reported_count` as a JSON integer
representing the collection count.
"""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def provider_config_path() -> Path:
    return repository_root() / "envs" / "medusa_store_pagination_v0" / "gate_config.json"


def provider_admission_path() -> Path:
    return repository_root() / "envs" / "medusa_store_pagination_v0" / "provider-admission.json"


def provider_runtime_bundle_path() -> Path:
    return repository_root() / "envs" / "medusa_store_pagination_v0" / "provider-runtime"


def provider_release_path() -> Path:
    return repository_root() / "envs" / "medusa_store_pagination_v0" / "provider-release"
