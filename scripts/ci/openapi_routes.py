#!/usr/bin/env python3
"""Lab-only drift guard between the management-api services and their
OpenAPI contracts: every route a service registers is documented with the
same methods, and a contract documents no operation its service does not
serve. Each operation also documents the statuses every service returns
before its handler runs: 401 and 429 (token and request budget) unless the
operation is public (`security: []`), and 413 (64 KiB body limit) when it
takes a request body. Exit status 1 on any difference.

The contracts are read with a strict line parser (no YAML dependency): a
path is a two-space-indented key under the top-level `paths:` and an
operation a four-space-indented HTTP method under it. The routes are read
from the `.route("path", method(handler)...)` calls before the source's
test module."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = {
    "openapi/management-v1.yaml": "crates/management-api/src/main.rs",
    "openapi/revocation-v1.yaml": "crates/management-api/src/bin/revocation_api.rs",
    "openapi/ca-admin-v1.yaml": "crates/management-api/src/bin/ca_admin_api.rs",
}
METHODS = ("get", "post", "put", "patch", "delete")
ROUTE = re.compile(
    r'\.route\(\s*"([^"]+)"\s*,\s*((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)', re.S
)
METHOD = re.compile(r"\b(" + "|".join(METHODS) + r")\(")
PATH_KEY = re.compile(r"^  (/[^:\s]*):\s*$")
METHOD_KEY = re.compile(r"^    (" + "|".join(METHODS) + r"):\s*$")
OPERATION_KEY = re.compile(r"^      ([A-Za-z]+):\s*(.*?)\s*$")
STATUS_KEY = re.compile(r"""^        '?"?([0-9]{3})'?"?:""")
AUTHENTICATED = ("401", "429")
WITH_BODY = ("413",)


def code_routes(source: str, name: str) -> set[tuple[str, str]]:
    source = source.split("#[cfg(test)]", 1)[0]
    routes = set()
    for path, handlers in ROUTE.findall(source):
        methods = METHOD.findall(handlers)
        if not methods:
            raise ValueError(f"{name}: route {path} has no recognised method")
        routes.update((m.upper(), path) for m in methods)
    if source.count(".route(") != len(ROUTE.findall(source)):
        raise ValueError(f"{name}: a .route( call could not be parsed")
    return routes


def contract_operations(text: str, name: str) -> dict[tuple[str, str], dict]:
    """(METHOD, path) -> {"public": bool, "body": bool, "statuses": set}."""
    operations = {}
    in_paths = False
    path = None
    operation = None
    section = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            in_paths = line.rstrip() == "paths:"
            path = operation = None
            continue
        if not in_paths:
            continue
        if match := PATH_KEY.match(line):
            path, operation = match.group(1), None
        elif match := METHOD_KEY.match(line):
            if path is None:
                raise ValueError(f"{name}: operation outside a path: {line!r}")
            operation = {"public": False, "body": False, "statuses": set()}
            operations[(match.group(1).upper(), path)] = operation
        elif operation is not None and (match := OPERATION_KEY.match(line)):
            section = match.group(1)
            if section == "security" and match.group(2) == "[]":
                operation["public"] = True
            elif section == "requestBody":
                operation["body"] = True
        elif operation is not None and section == "responses" and (
            match := STATUS_KEY.match(line)
        ):
            operation["statuses"].add(match.group(1))
    return operations


def missing_statuses(operations: dict) -> list[str]:
    problems = []
    for (method, path), operation in sorted(operations.items()):
        required = () if operation["public"] else AUTHENTICATED
        if operation["body"]:
            required += WITH_BODY
        for status in required:
            if status not in operation["statuses"]:
                problems.append(f"{method} {path} does not document {status}")
    return problems


def main() -> int:
    failed = False
    for contract, source in SERVICES.items():
        try:
            code = code_routes((ROOT / source).read_text(), source)
            operations = contract_operations((ROOT / contract).read_text(), contract)
            spec = set(operations)
        except ValueError as error:
            print(f"FAIL: {error}")
            failed = True
            continue
        problems = []
        if not code:
            problems.append(f"{source}: no route found")
        if not spec:
            problems.append(f"{contract}: no operation found")
        problems += [
            f"{source} serves {method} {path}, missing from {contract}"
            for method, path in sorted(code - spec)
        ]
        problems += [
            f"{contract} documents {method} {path}, not served by {source}"
            for method, path in sorted(spec - code)
        ]
        problems += [f"{contract}: {p}" for p in missing_statuses(operations)]
        for problem in problems:
            print(f"FAIL: {problem}")
        if problems:
            failed = True
        else:
            print(f"ok: {contract} matches {source} ({len(code)} operations)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
