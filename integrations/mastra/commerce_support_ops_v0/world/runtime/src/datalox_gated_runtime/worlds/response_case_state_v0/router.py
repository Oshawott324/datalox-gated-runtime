from __future__ import annotations

import re
from dataclasses import dataclass

from datalox_gated_runtime.query import QueryParams
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import Route, WorldContractError

_PARAMETER = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")


@dataclass(frozen=True)
class RouteMatch:
    route: Route
    path_parameters: dict[str, str]


def validate_routes(routes: list[Route]) -> None:
    for route in routes:
        names = template_parameter_names(route.path_template)
        if names != set(route.path_parameters):
            raise WorldContractError(
                "invalid_path_parameter_bindings",
                f"Route {route.route_id} path parameters must exactly match its bindings.",
            )


def template_parameter_names(path_template: str) -> set[str]:
    segments = _segments(path_template, template=True)
    names: list[str] = []
    for segment in segments:
        match = _PARAMETER.fullmatch(segment)
        if match is not None:
            names.append(match.group(1))
        elif "{" in segment or "}" in segment:
            raise WorldContractError(
                "invalid_route_template",
                f"Invalid path template segment: {segment}.",
            )
    if len(names) != len(set(names)):
        raise WorldContractError(
            "invalid_route_template", "Path template parameter names must be unique."
        )
    return set(names)


def match_route(
    routes: list[Route],
    method: str,
    path: str,
    query: QueryParams,
) -> RouteMatch | None:
    actual_segments = _segments(path, template=False)
    normalized_method = method.upper()
    for route in routes:
        if route.method != normalized_method or route.query != query:
            continue
        template_segments = _segments(route.path_template, template=True)
        if len(template_segments) != len(actual_segments):
            continue
        parameters: dict[str, str] = {}
        matched = True
        for template_segment, actual_segment in zip(
            template_segments, actual_segments, strict=True
        ):
            parameter = _PARAMETER.fullmatch(template_segment)
            if parameter is not None:
                parameters[parameter.group(1)] = actual_segment
            elif template_segment != actual_segment:
                matched = False
                break
        if matched:
            return RouteMatch(route, parameters)
    return None


def render_path(route: Route, arguments: dict[str, object]) -> tuple[str, dict[str, object]]:
    segments: list[str] = []
    consumed: set[str] = set()
    for segment in _segments(route.path_template, template=True):
        parameter = _PARAMETER.fullmatch(segment)
        if parameter is None:
            segments.append(segment)
            continue
        name = parameter.group(1)
        value = arguments.get(name)
        if not isinstance(value, str) or not value or "/" in value:
            raise WorldContractError(
                "invalid_tool_arguments",
                f"Tool path parameter {name} must be a non-empty path segment.",
            )
        consumed.add(name)
        segments.append(value)
    return "/" + "/".join(segments), {
        key: value for key, value in arguments.items() if key not in consumed
    }


def _segments(path: str, *, template: bool) -> list[str]:
    if not isinstance(path, str) or not path.startswith("/"):
        code = "invalid_route_template" if template else "invalid_request_path"
        raise WorldContractError(code, "Paths must be absolute.")
    if path != "/" and path.endswith("/"):
        code = "invalid_route_template" if template else "invalid_request_path"
        raise WorldContractError(code, "Trailing slashes are not permitted.")
    if "//" in path:
        code = "invalid_route_template" if template else "invalid_request_path"
        raise WorldContractError(code, "Empty path segments are not permitted.")
    return [] if path == "/" else path[1:].split("/")
