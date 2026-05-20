#!/usr/bin/env python3
# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Audit script — scans the SDK for ``structlog`` calls that might leak
credential material into log output.

Reports every ``structlog.*.{info,debug,warn,warning,error,critical}``
call in ``src/dns_aid/sdk/`` that mentions credential-shaped attribute
names. Each match is reported with file path, line number, and the
matching expression. A maintainer must manually review each finding to
confirm the credential value is NOT actually being logged (it may be
that the attribute name appears in a comment, docstring, or unrelated
context).

Zero findings in the current source — the audit is meant to catch
future regressions where a refactor accidentally introduces a leak.

Usage:
    uv run python scripts/audit_credential_handling.py

Exits 0 if no findings, 1 if any matches are found (suitable for use as
a CI safety gate).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Attribute names whose values are credential material. If any of these
# appear inside a structlog logging call, the maintainer must review.
_CREDENTIAL_ATTRIBUTE_NAMES = (
    "token",
    "client_secret",
    "private_key",
    "private_key_pem",
    "api_key",
    "access_key",
    "secret_key",
    "session_token",
    "password",
    "subject_token",
    "actor_token",
)

# structlog method names that emit log records.
_LOGGING_METHODS = ("info", "debug", "warn", "warning", "error", "critical", "log")

# Build a regex that matches structlog logging calls. We look for the
# pattern ``.method(`` (after any object reference like ``logger`` or
# ``log``) and then check whether the call body references any
# credential-shaped attribute name.
_LOG_CALL_REGEX = re.compile(
    r"""
    (?P<method>\.(?:"""
    + "|".join(_LOGGING_METHODS)
    + r"""))   # .info(, .debug(, ...
    \s*\(
    (?P<body>[^)]*?)                                            # call body up to first )
    \)
    """,
    re.VERBOSE | re.DOTALL,
)


def find_findings(src_root: Path) -> list[tuple[Path, int, str, str]]:
    """Scan all .py files under src_root for risky structlog calls.

    Returns a list of ``(file_path, line_number, matched_attribute,
    full_match_text)`` tuples. Empty list means clean.
    """
    findings: list[tuple[Path, int, str, str]] = []
    for py_file in sorted(src_root.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Track line numbers as we scan.
        for match in _LOG_CALL_REGEX.finditer(source):
            body = match.group("body")
            # Look for credential-shaped attribute keywords inside the call body.
            for attr in _CREDENTIAL_ATTRIBUTE_NAMES:
                # Match attr= (kwarg-style) or "attr": (dict-style).
                if re.search(rf"\b{re.escape(attr)}\s*=", body) or re.search(
                    rf"['\"]?\b{re.escape(attr)}\b['\"]?\s*:", body
                ):
                    # Find the line number of the match start.
                    line_no = source.count("\n", 0, match.start()) + 1
                    findings.append((py_file, line_no, attr, match.group(0).strip()))
                    break  # one finding per call site is sufficient
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--src",
        type=Path,
        default=Path(__file__).parent.parent / "src" / "dns_aid" / "sdk",
        help="Root directory to audit (default: src/dns_aid/sdk).",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Also audit tests/ — usually omitted because tests use sentinels.",
    )
    args = parser.parse_args()

    src_root: Path = args.src.resolve()
    if not src_root.is_dir():
        print(f"Error: {src_root} is not a directory.", file=sys.stderr)
        return 2

    print(f"Auditing {src_root} for structlog calls referencing credential attribute names...")
    print(f"Attribute names checked: {', '.join(_CREDENTIAL_ATTRIBUTE_NAMES)}")
    print()

    findings = find_findings(src_root)

    if args.include_tests:
        tests_root = src_root.parent.parent.parent / "tests"
        if tests_root.is_dir():
            print(f"Also auditing {tests_root}...")
            findings.extend(find_findings(tests_root))

    if not findings:
        print(
            "✅ No findings. Zero structlog calls reference credential-shaped attributes in SDK source."
        )
        return 0

    print(f"⚠️  {len(findings)} findings — manual review required:")
    print()
    for path, line_no, attr, match_text in findings:
        rel = (
            path.relative_to(src_root.parent)
            if str(path).startswith(str(src_root.parent))
            else path
        )
        print(f"  {rel}:{line_no}")
        print(f"    attribute: {attr}")
        print(f"    context:   {match_text}")
        print()

    print("Each finding must be reviewed to confirm the credential VALUE is not being logged.")
    print("The attribute name appearing in a comment or unrelated context is acceptable.")
    print("The attribute name appearing as a kwarg/dict-value of a logging call is NOT acceptable")
    print("unless the value passed is structurally guaranteed to be non-credential.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
