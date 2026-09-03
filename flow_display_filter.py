from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import TypeAlias


class FlowDisplayFilterError(ValueError):
    """Raised when a flow display-filter expression is invalid or unsupported."""


FlowPredicate: TypeAlias = Callable[[dict[str, object]], bool]

_MAX_EXPRESSION_LENGTH = 1024
_ALLOWED_FIELDS = {
    "ip",
    "ip.addr",
    "ip.src",
    "ip.dst",
    "protocol",
    "proto",
    "service",
    "state",
    "conn_state",
    "packets",
    "bytes",
    "duration_ms",
    "flow_id",
    "uid",
    "community_id",
    "tcp.port",
    "tcp.srcport",
    "tcp.dstport",
    "udp.port",
    "udp.srcport",
    "udp.dstport",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
}
_NUMERIC_FIELDS = {
    "packets",
    "bytes",
    "duration_ms",
    "tcp.port",
    "tcp.srcport",
    "tcp.dstport",
    "udp.port",
    "udp.srcport",
    "udp.dstport",
    "id.orig_p",
    "id.resp_p",
}
_FORBIDDEN_KEY_MARKERS = (
    "payload",
    "raw",
    "body",
    "authorization",
    "cookie",
)
_TOKEN_RE = re.compile(
    r'"[^"\\]*(?:\\.[^"\\]*)*"|' r"'[^'\\]*(?:\\.[^'\\]*)*'|" r">=|<=|==|!=|>|<|\(|\)|[^\s()<>!=]+"
)


def _tokenize(expression: str) -> list[str]:
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise FlowDisplayFilterError("Flow display-filter expression is too long.")
    tokens = _TOKEN_RE.findall(expression)
    if not tokens and expression.strip():
        raise FlowDisplayFilterError("Invalid flow display-filter expression.")
    return tokens


def _text(value: object) -> str:
    return str(value or "").strip().lower()


def _number(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError):
        return 0


def _unquote(token: str) -> str:
    quoted = len(token) >= 2 and token[0] == token[-1]
    if quoted and token[0] in {"'", '"'}:
        return token[1:-1]
    return token


def _endpoint(flow: dict[str, object], role: str) -> dict[str, object]:
    value = flow.get(role)
    if isinstance(value, dict):
        return value
    return {}


def _endpoint_ips(flow: dict[str, object]) -> set[str]:
    values: set[str] = set()
    for key in ("originator", "responder", "endpoint_a", "endpoint_b"):
        endpoint = flow.get(key)
        if isinstance(endpoint, dict):
            value = str(endpoint.get("ip") or "").strip()
            if value:
                values.add(value)
    return values


def _endpoint_ports(flow: dict[str, object]) -> set[int]:
    values: set[int] = set()
    for key in ("originator", "responder", "endpoint_a", "endpoint_b"):
        endpoint = flow.get(key)
        if isinstance(endpoint, dict):
            port = _number(endpoint.get("port"))
            if port:
                values.add(port)
    return values


def _transport_matches(flow: dict[str, object], protocol: str) -> bool:
    return _text(flow.get("protocol")) == protocol


def _field_value(flow: dict[str, object], field: str) -> object:
    originator = _endpoint(flow, "originator")
    responder = _endpoint(flow, "responder")

    if field in {"ip", "ip.addr"}:
        return _endpoint_ips(flow)
    if field in {"ip.src", "id.orig_h"}:
        return originator.get("ip", "")
    if field in {"ip.dst", "id.resp_h"}:
        return responder.get("ip", "")
    if field in {"protocol", "proto"}:
        return flow.get("protocol", "")
    if field in {"state", "conn_state"}:
        return flow.get("tcp_state") or flow.get("state") or ""
    if field in {"flow_id", "uid"}:
        return flow.get("flow_id", "")
    if field == "id.orig_p":
        return originator.get("port", 0)
    if field == "id.resp_p":
        return responder.get("port", 0)

    if field.startswith("tcp."):
        if not _transport_matches(flow, "tcp"):
            return set()
        if field == "tcp.port":
            return _endpoint_ports(flow)
        if field == "tcp.srcport":
            return originator.get("port", 0)
        if field == "tcp.dstport":
            return responder.get("port", 0)

    if field.startswith("udp."):
        if not _transport_matches(flow, "udp"):
            return set()
        if field == "udp.port":
            return _endpoint_ports(flow)
        if field == "udp.srcport":
            return originator.get("port", 0)
        if field == "udp.dstport":
            return responder.get("port", 0)

    return flow.get(field, "")


def _compare_number(observed: int, operator: str, expected: int) -> bool:
    if operator == "==":
        return observed == expected
    if operator == "!=":
        return observed != expected
    if operator == ">":
        return observed > expected
    if operator == ">=":
        return observed >= expected
    if operator == "<":
        return observed < expected
    if operator == "<=":
        return observed <= expected
    return False


def _numeric_predicate(
    field: str,
    operator: str,
    expected: int,
) -> FlowPredicate:
    def predicate(flow: dict[str, object]) -> bool:
        observed = _field_value(flow, field)
        if isinstance(observed, set):
            values = [_number(value) for value in observed]
            if not values:
                return False
            if operator == "!=":
                return all(_compare_number(value, operator, expected) for value in values)
            return any(_compare_number(value, operator, expected) for value in values)
        return _compare_number(_number(observed), operator, expected)

    return predicate


def _text_predicate(
    field: str,
    operator: str,
    value: str,
) -> FlowPredicate:
    expected = _text(value)

    def predicate(flow: dict[str, object]) -> bool:
        observed = _field_value(flow, field)
        if isinstance(observed, set):
            matched = any(_text(item) == expected for item in observed)
        else:
            matched = _text(observed) == expected
        if operator == "==":
            return matched
        return not matched

    return predicate


def _comparison(field: str, operator: str, raw_value: str) -> FlowPredicate:
    if field not in _ALLOWED_FIELDS:
        raise FlowDisplayFilterError(f"Unsupported field: {field}.")
    value = _unquote(raw_value)

    if field in _NUMERIC_FIELDS:
        try:
            expected = int(value)
        except ValueError as exc:
            message = f"{field} requires an integer value."
            raise FlowDisplayFilterError(message) from exc
        return _numeric_predicate(field, operator, expected)

    if operator not in {"==", "!="}:
        message = f"Field {field} supports only == and != comparisons."
        raise FlowDisplayFilterError(message)
    return _text_predicate(field, operator, value)


def _combine_or(left: FlowPredicate, right: FlowPredicate) -> FlowPredicate:
    def predicate(flow: dict[str, object]) -> bool:
        return left(flow) or right(flow)

    return predicate


def _combine_and(left: FlowPredicate, right: FlowPredicate) -> FlowPredicate:
    def predicate(flow: dict[str, object]) -> bool:
        return left(flow) and right(flow)

    return predicate


def _negate(predicate: FlowPredicate) -> FlowPredicate:
    def negated(flow: dict[str, object]) -> bool:
        return not predicate(flow)

    return negated


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0

    def current(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def consume(self) -> str:
        token = self.current()
        if token is None:
            message = "Unexpected end of flow display-filter expression."
            raise FlowDisplayFilterError(message)
        self.index += 1
        return token

    def parse(self) -> FlowPredicate:
        if not self.tokens:
            return _always_true
        predicate = self.parse_or()
        if self.current() is not None:
            raise FlowDisplayFilterError(f"Unexpected token: {self.current()}.")
        return predicate

    def parse_or(self) -> FlowPredicate:
        left = self.parse_and()
        while _text(self.current()) == "or":
            self.consume()
            left = _combine_or(left, self.parse_and())
        return left

    def parse_and(self) -> FlowPredicate:
        left = self.parse_not()
        while _text(self.current()) == "and":
            self.consume()
            left = _combine_and(left, self.parse_not())
        return left

    def parse_not(self) -> FlowPredicate:
        if _text(self.current()) == "not":
            self.consume()
            return _negate(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> FlowPredicate:
        if self.current() == "(":
            self.consume()
            predicate = self.parse_or()
            if self.consume() != ")":
                raise FlowDisplayFilterError("Missing closing parenthesis.")
            return predicate

        field = _text(self.consume())
        operator = self.consume()
        if operator not in {"==", "!=", ">", ">=", "<", "<="}:
            message = f"Unsupported comparison operator: {operator}."
            raise FlowDisplayFilterError(message)
        return _comparison(field, operator, self.consume())


def _always_true(_: dict[str, object]) -> bool:
    return True


def compile_flow_filter(expression: str) -> FlowPredicate:
    """Compile a bounded metadata-only display-filter expression into a predicate.

    A small analyst-friendly alias set mirrors common Wireshark endpoint/transport
    names and Zeek connection-record names. Directional aliases map to NetWatch's
    stable originator/responder roles rather than individual packet direction.
    """
    normalized = str(expression or "").strip()
    return _Parser(_tokenize(normalized)).parse()


def _sanitize_mapping(value: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in _FORBIDDEN_KEY_MARKERS):
            continue
        if isinstance(item, dict):
            result[key] = _sanitize_mapping(item)
        elif isinstance(item, list):
            result[key] = [_sanitize_value(element) for element in item]
        else:
            result[key] = item
    return result


def _sanitize_value(value: object) -> object:
    if isinstance(value, dict):
        return _sanitize_mapping(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    return value


def filter_flows(
    flows: Iterable[dict[str, object]],
    expression: str,
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    """Return bounded flow records matching an analyst display filter.

    Only an allowlisted metadata schema is queryable. Python or arbitrary code is
    never evaluated, and returned records are scrubbed of payload/raw/body and
    credential-like fields.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("Flow display-filter limit must be between 1 and 1000.")

    predicate = compile_flow_filter(expression)
    matches: list[dict[str, object]] = []
    for flow in flows:
        if not predicate(flow):
            continue
        matches.append(_sanitize_mapping(flow))
        if len(matches) >= limit:
            break
    return matches
