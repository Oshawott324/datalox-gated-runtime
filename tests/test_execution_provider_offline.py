import ast
from pathlib import Path

from datalox_gated_runtime.models import CallRequest, PolicyConfig, RouteRule
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.runtime import GatedRuntime

ROOT = Path(__file__).resolve().parents[1]
EXECUTION_MODULES = (
    ROOT / "src/datalox_gated_runtime/runtime.py",
    ROOT / "src/datalox_gated_runtime/http_server.py",
    ROOT / "src/datalox_gated_runtime/data_plane.py",
    ROOT / "src/datalox_gated_runtime/mcp_runtime.py",
    ROOT / "src/datalox_gated_runtime/mcp_server.py",
    ROOT / "src/datalox_gated_runtime/wire.py",
    ROOT / "src/datalox_gated_runtime/provider_runtime/bundle.py",
    ROOT / "src/datalox_gated_runtime/provider_runtime/runtime.py",
    ROOT / "src/datalox_gated_runtime/interception/gateway.py",
)
FORBIDDEN_IMPORT_PREFIXES = (
    "datalox_gated_runtime.capture",
    "datalox_gated_runtime.mcp_upstream",
    "httpx",
    "requests",
    "socket",
    "subprocess",
    "urllib.request",
)


def test_execution_modules_cannot_import_provider_transport_clients() -> None:
    for path in EXECUTION_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.append(node.module)
        assert not {module for module in imports if module.startswith(FORBIDDEN_IMPORT_PREFIXES)}, (
            path
        )


def test_execution_runtime_denies_declared_provider_route_by_default() -> None:
    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/provider/", method="GET")]),
    )
    response = GatedRuntime(policy=policy).handle(
        CallRequest(method="GET", path="/provider/resource")
    )
    assert response.status_code == 403
    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "provider_access_forbidden"


def test_execution_cli_has_no_allow_live_flag() -> None:
    source = (ROOT / "src/datalox_gated_runtime/cli.py").read_text(encoding="utf-8")
    assert '"--allow-live"' not in source
