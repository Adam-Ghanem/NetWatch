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
    "protocol",
    "service",
    "state",
    "packets",
    "bytes",
    "duration_ms",
    "flow_id",
}
_NUMERIC_FIELDS = {"packets", "bytes", "duration_ms"}
_FORBIDDEN_KEY_MARKERS = (
    "payload",
    "raw",
    "body",
    "authorization",
    "cookie",
)
_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'|>=|<=|==|!=|>|<|\(|\)|[^\s()<>!=]+')


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
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        return token[1:-1]
    return token


def _endpoint_ips(flow: dict[str, object]) -> set[str]:
    values: set[str] = set()
    for key in ("originator", "responder", "endpoint_a", "endpoint_b"):
        endpoint = flow.get(key)
        if isinstance(endpoint, dict):
            value = str(endpoint.get("ip") or "").strip()
            if value:
                values.add(value)
    return values


def _field_value(flow: dict[str, object], field: str) -> object:
    if field == "ip":
        return _endpoint_ips(flow)
    if field == "state":
        return flow.get("tcp_state") or flow.get("state") or ""
    return flow.get(field, "")


def _comparison(field: str, operator: str, raw_value: str) -> FlowPredicate:
    if field not in _ALLOWED_FIELDS:
        raise FlowDisplayFilterError(f"Unsupported field: {field}.")
    value = _unquote(raw_value)

    if field in _NUMERIC_FIELDS:
        try:
            expected = int(value)
        except ValueError as exc:
            raise FlowDisplayFilterError(f"{field} requires an integer value.") from exc

        def numeric(flow: dict[str, object]) -> bool:
            observed = _number(_field_value(flow, field))
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

        return numeric

    if operator not in {"==", "!="}:
        raise FlowDisplayFilterError(f"Field {field} supports only == and != comparisons.")

    expected_text = _text(value)

    def textual(flow: dict[str, object]) -> bool:
        observed = _field_value(flow, field)
        if field == "ip" and isinstance(observed, set):
            matched = value in observed
        else:
            matched = _text(observed) == expected_text
        return matched if operator == "==" else not matched

    return textual


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
            raise FlowDisplayFilterError("Unexpected end of flow display-filter expression.")
        self.index += 1
        return token

    def parse(self) -> FlowPredicate:
        if not self.tokens:
            return lambda _: True
        predicate = self.parse_or()
        if self.current() is not None:
            raise FlowDisplayFilterError(f"Unexpected token: {self.current()}.")
        return predicate

    def parse_or(self) -> FlowPredicate:
        left = self.parse_and()
        while _text(self.current()) == "or":
            self.consume()
            right = self.parse_and()
            previous = left
            left = lambda flow, previous=previous, right=right: previous(flow) or right(flow)
        return left

    def parse_and(self) -> FlowPredicate:
        left = self.parse_not()
        while _text(self.current()) == "and":
            self.consume()
            right = self.parse_not()
            previous = left
            left = lambda flow, previous=previous, right=right: previous(flow) and right(flow)
        return left

    def parse_not(self) -> FlowPredicate:
        if _text(self.current()) == "not":
            self.consume()
            predicate = self.parse_not()
            return lambda flow: not predicate(flow)
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
            raise FlowDisplayFilterError(f"Unsupported comparison operator: {operator}.")
        value = self.consume()
        return _comparison(field, operator, value)


def compile_flow_filter(expression: str) -> FlowPredicate:
    """Compile a bounded metadata-only display-filter expression into a predicate."""
    return _Parser(_tokenize(str(expression or "").strip())).parse()


def _sanitized(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _sanitized(item)
            for key, item in value.items()
            if not any(marker in str(key).lower() for marker in _FORBIDDEN_KEY_MARKERS)
        }
    if isinstance(value, list):
        return [_sanitized(item) for item in value]
    return value


def filter_flows(
    flows: Iterable[dict[str, object]],
    expression: str,
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    """Return bounded flow records matching an analyst display filter.

    The language deliberately supports only a small allowlisted metadata schema and
    never evaluates Python or arbitrary code. Returned records are copied and scrubbed
    of payload/raw/body/credential-like fields.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("Flow display-filter limit must be between 1 and 1000.")
    predicate = compile_flow_filter(expression)
    matches: list[dict[str, object]] = []
    for flow in flows:
        if predicate(flow):
            cleaned = _sanitized(flow)
            if isinstance(cleaned, dict):
                matches.append(cleaned)
            if len(matches) >= limit:
                break
    return matches
