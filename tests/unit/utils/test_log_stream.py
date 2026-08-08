# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Diagnostics belong on stderr so machine-readable stdout stays parseable.

`discover --json` emitted structlog lines ahead of the document, so piping the
CLI to a parser failed. configure_logging already sent stdlib logging to stderr;
only the structlog factory defaulted to stdout, splitting one function's output
across two streams. mcp/server.py had already worked around this for JSON-RPC.
"""

import subprocess
import sys

import structlog


def test_structlog_writes_to_stderr():
    from dns_aid.utils.logging import configure_logging

    configure_logging(level="INFO")
    factory = structlog.get_config()["logger_factory"]

    assert factory()._file is sys.stderr, "structlog is writing diagnostics to stdout"


def test_cli_json_stdout_is_parseable_on_its_own():
    """The real failure: stdout must contain the document and nothing else."""
    code = (
        "from dns_aid.utils.logging import configure_logging;"
        "import structlog, json, sys;"
        "configure_logging(level='DEBUG');"
        "structlog.get_logger().info('diagnostic that used to land on stdout');"
        "print(json.dumps({'agents': []}))"
    )
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)

    import json

    json.loads(p.stdout)  # raises if a log line got in front of the document
    assert "diagnostic" in p.stderr, "the log line must still be emitted, just not on stdout"
