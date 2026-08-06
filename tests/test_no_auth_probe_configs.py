from pathlib import Path

from datalox_gated_runtime.provider_probe import load_probe_config


ROOT = Path(__file__).resolve().parents[1]
PROBES = ROOT / "probes"
CREDENTIAL_FREE_CONFIGS = {
    "cromwell": PROBES / "cromwell.json",
    "docker_engine": PROBES / "docker_engine.json",
    "grafana_oss": PROBES / "grafana_oss.json",
    "mlflow": PROBES / "mlflow.json",
    "opensearch": PROBES / "opensearch.json",
    "prometheus_alertmanager": PROBES / "prometheus_alertmanager.json",
}
AUTH_BACKED_LOCAL_FIXTURE_CONFIGS = {
    "mattermost": PROBES / "mattermost.json",
    "medusa": PROBES / "medusa.json",
    "openproject": PROBES / "openproject.json",
    "woocommerce": PROBES / "woocommerce.json",
}
NO_EXTERNAL_PROVIDER_CONFIGS = CREDENTIAL_FREE_CONFIGS | AUTH_BACKED_LOCAL_FIXTURE_CONFIGS


def test_no_external_auth_probe_configs_exist_and_parse() -> None:
    missing = [
        str(path.relative_to(ROOT))
        for path in NO_EXTERNAL_PROVIDER_CONFIGS.values()
        if not path.exists()
    ]

    assert missing == []

    for provider_id, path in NO_EXTERNAL_PROVIDER_CONFIGS.items():
        config = load_probe_config(path)

        assert config.provider_id == provider_id
        assert config.access_class in {"self_hosted", "open_public"}
        assert config.probe_status == "allowed"
        assert config.probe_requests
        assert config.rate_budget.max_requests >= len(config.probe_requests)


def test_no_external_auth_probe_configs_are_get_only_and_credential_free() -> None:
    for path in CREDENTIAL_FREE_CONFIGS.values():
        config = load_probe_config(path)

        assert config.auth_schema == "none"
        assert config.auth_profile is None
        assert config.auth_env is None
        assert config.extra_auth == []
        assert all(request.method == "GET" for request in config.probe_requests)
        assert all(request.path.startswith("/") for request in config.probe_requests)
        assert all(
            any(request.path.startswith(prefix) for prefix in config.safe_read_prefixes)
            for request in config.probe_requests
        )


def test_local_fixture_auth_probe_configs_are_get_only_and_auth_broker_backed() -> None:
    for path in AUTH_BACKED_LOCAL_FIXTURE_CONFIGS.values():
        config = load_probe_config(path)

        assert config.auth_schema == "auth_broker_v0"
        assert config.auth_profile is not None
        assert config.auth_env is None
        assert config.extra_auth == []
        assert all(request.method == "GET" for request in config.probe_requests)
        assert all(request.path.startswith("/") for request in config.probe_requests)
        assert all(
            any(request.path.startswith(prefix) for prefix in config.safe_read_prefixes)
            for request in config.probe_requests
        )
