"""Strict provider HTTPS dispatcher executed inside a Datalox rollout lease."""

from __future__ import annotations

import base64
import binascii
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

REQUEST_FIELDS = {"method", "url", "headers", "body_base64", "timeout_seconds"}
RESULT_FIELDS = {
    "schema_version",
    "transport_ok",
    "status_code",
    "headers",
    "body_base64",
    "error",
}
METHODS = {"DELETE", "GET", "PATCH", "POST", "PUT"}


class RequestContractError(ValueError):
    pass


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        request = _request(arguments)
    except RequestContractError as exc:
        print(f"invalid provider request: {exc}", file=sys.stderr)
        return 2

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    outbound = urllib.request.Request(
        request["url"],
        data=request["body"],
        headers=request["headers"],
        method=request["method"],
    )
    try:
        with opener.open(outbound, timeout=request["timeout_seconds"]) as response:
            result = _http_result(response.status, response.headers.items(), response.read())
    except urllib.error.HTTPError as response:
        # Provider HTTP failures are provider observations, not dispatcher failures.
        result = _http_result(response.code, response.headers.items(), response.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result = {
            "schema_version": "datalox_provider_https_result_v1",
            "transport_ok": False,
            "status_code": None,
            "headers": [],
            "body_base64": "",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
        _emit(result)
        return 1

    _emit(result)
    return 0


def _request(arguments: list[str]) -> dict[str, Any]:
    if len(arguments) != 1:
        raise RequestContractError("expected exactly one JSON argv value")
    try:
        value = json.loads(arguments[0])
    except json.JSONDecodeError as exc:
        raise RequestContractError("argv value must be valid JSON") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RequestContractError("request must be a JSON object")
    if set(value) != REQUEST_FIELDS:
        raise RequestContractError(f"request fields must be exactly {sorted(REQUEST_FIELDS)!r}")

    method = value["method"]
    if not isinstance(method, str) or method not in METHODS:
        raise RequestContractError(f"method must be one of {sorted(METHODS)!r}")
    url = value["url"]
    if not isinstance(url, str) or not url or url.strip() != url:
        raise RequestContractError("url must be a non-empty trimmed string")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RequestContractError("url must be an HTTPS URL without credentials or a fragment")

    headers = value["headers"]
    if not isinstance(headers, Mapping) or not all(
        isinstance(name, str)
        and name
        and isinstance(header_value, str)
        and "\r" not in name + header_value
        and "\n" not in name + header_value
        and "\x00" not in name + header_value
        for name, header_value in headers.items()
    ):
        raise RequestContractError("headers must map non-empty strings to safe string values")

    body_base64 = value["body_base64"]
    if not isinstance(body_base64, str):
        raise RequestContractError("body_base64 must be a string")
    try:
        body = base64.b64decode(body_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RequestContractError("body_base64 must be canonical base64") from exc
    if base64.b64encode(body).decode("ascii") != body_base64:
        raise RequestContractError("body_base64 must be canonical base64")

    timeout_seconds = value["timeout_seconds"]
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 300
    ):
        raise RequestContractError("timeout_seconds must be an integer from 1 through 300")

    return {
        "method": method,
        "url": url,
        "headers": dict(headers),
        "body": body or None,
        "timeout_seconds": timeout_seconds,
    }


def _http_result(status_code: int, headers: Any, body: bytes) -> dict[str, Any]:
    return {
        "schema_version": "datalox_provider_https_result_v1",
        "transport_ok": True,
        "status_code": status_code,
        "headers": [[str(name), str(value)] for name, value in headers],
        "body_base64": base64.b64encode(body).decode("ascii"),
        "error": None,
    }


def _emit(result: dict[str, Any]) -> None:
    if set(result) != RESULT_FIELDS:
        raise RuntimeError("internal result envelope does not match its contract")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    raise SystemExit(main())
