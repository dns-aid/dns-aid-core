# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
``dns_aid.doctor`` — structured environment diagnostics.

Provides :func:`run_checks` which returns a :class:`DiagnosticReport`
containing all check results.  Consumed by:

- **CLI** (``dns-aid doctor``) — renders with Rich
- **MCP** (``diagnose_environment`` tool) — returns as JSON dict
- **Python** — programmatic access via ``from dns_aid.doctor import run_checks``
"""

from __future__ import annotations

import importlib
import logging
import os
import platform
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

# ── data model ────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """Single diagnostic check outcome."""

    status: Literal["pass", "fail", "warn"]
    label: str
    detail: str = ""


@dataclass
class DiagnosticReport:
    """Structured output from :func:`run_checks`."""

    version: str
    sections: dict[str, list[CheckResult]] = field(default_factory=dict)

    @property
    def pass_count(self) -> int:
        return sum(1 for s in self.sections.values() for c in s if c.status == "pass")

    @property
    def fail_count(self) -> int:
        return sum(1 for s in self.sections.values() for c in s if c.status == "fail")

    @property
    def warn_count(self) -> int:
        return sum(1 for s in self.sections.values() for c in s if c.status == "warn")

    def to_dict(self) -> dict:
        """Serialize for JSON / MCP responses."""
        d = asdict(self)
        d["pass_count"] = self.pass_count
        d["fail_count"] = self.fail_count
        d["warn_count"] = self.warn_count
        return d


# ── helpers ───────────────────────────────────────────────────────


@contextmanager
def _suppress_logs():
    """Temporarily suppress all logging output (stdlib + structlog)."""
    import structlog

    logging.disable(logging.CRITICAL)
    prev_factory = structlog.get_config().get("logger_factory")
    structlog.configure(logger_factory=lambda *a, **kw: logging.getLogger("_null"))
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)
        if prev_factory:
            structlog.configure(logger_factory=prev_factory)
        else:
            structlog.reset_defaults()


def _get_module_version(module_name: str, dist_name: str = "") -> str:
    """Import a module and return its version string.

    Falls back to ``importlib.metadata`` for packages that don't
    expose ``__version__`` (e.g. rich).
    """
    mod = importlib.import_module(module_name)
    ver = getattr(mod, "__version__", getattr(mod, "version", ""))
    if callable(ver):
        ver = ver()
    if not ver and dist_name:
        from contextlib import suppress
        from importlib.metadata import PackageNotFoundError, version

        with suppress(PackageNotFoundError):
            ver = version(dist_name)
    return str(ver) if ver else ""


# ── individual checks ─────────────────────────────────────────────


def _check_core(current_version: str) -> list[CheckResult]:
    """Core: version, PyPI update, Python, required deps."""
    results: list[CheckResult] = []

    # dns-aid version + PyPI check
    try:
        import httpx
        from packaging.version import Version

        resp = httpx.get("https://pypi.org/pypi/dns-aid/json", timeout=3)
        if resp.status_code == 200:
            latest = resp.json()["info"]["version"]
            if Version(latest) > Version(current_version):
                results.append(
                    CheckResult(
                        "fail",
                        "dns-aid",
                        f"{current_version} → {latest} available  (pip install --upgrade dns-aid)",
                    )
                )
            else:
                results.append(CheckResult("pass", "dns-aid", f"{current_version} (latest)"))
        else:
            results.append(CheckResult("pass", "dns-aid", current_version))
    except Exception:
        # Network error — skip update check, just report version
        results.append(CheckResult("pass", "dns-aid", current_version))

    # Python version
    results.append(CheckResult("pass", "Python", platform.python_version()))

    # Required dependencies: (display_name, module_name, dist_name)
    deps = [
        ("dnspython", "dns", "dnspython"),
        ("httpx", "httpx", "httpx"),
        ("pydantic", "pydantic", "pydantic"),
        ("typer", "typer", "typer"),
        ("rich", "rich", "rich"),
        ("structlog", "structlog", "structlog"),
    ]
    for dep, pkg, dist in deps:
        try:
            ver = _get_module_version(pkg, dist)
            results.append(CheckResult("pass", dep, ver))
        except ImportError:
            results.append(CheckResult("fail", dep, "not installed"))

    return results


def _check_dns(domain: str | None = None) -> list[CheckResult]:
    """DNS: resolution, SVCB support, and agent discovery via TXT index."""
    results: list[CheckResult] = []

    # Basic resolution
    try:
        import dns.resolver

        dns.resolver.resolve("example.com", "A")
        results.append(CheckResult("pass", "Resolution", "DNS queries working"))
    except Exception as exc:
        results.append(CheckResult("fail", "Resolution", str(exc)))
        return results  # skip remaining DNS checks

    # SVCB record type support
    try:
        import dns.rdatatype

        dns.rdatatype.from_text("SVCB")
        results.append(CheckResult("pass", "SVCB support", "RFC 9460 record types available"))
    except Exception:
        results.append(CheckResult("warn", "SVCB support", "dnspython may not support SVCB"))

    # Agent discovery via lightweight TXT index check
    domain = domain or os.environ.get("DNS_AID_DOCTOR_DOMAIN")
    if not domain:
        results.append(
            CheckResult(
                "warn",
                "Agent discovery",
                "no domain specified (use --domain or DNS_AID_DOCTOR_DOMAIN)",
            )
        )
        return results

    try:
        import asyncio

        from dns_aid.core.indexer import read_index_via_dns

        start = time.perf_counter()
        with _suppress_logs():
            entries = asyncio.run(read_index_via_dns(domain))
        elapsed_ms = (time.perf_counter() - start) * 1000

        if entries:
            results.append(
                CheckResult(
                    "pass",
                    "Agent discovery",
                    f"{len(entries)} agent(s) indexed at {domain} ({elapsed_ms:.0f}ms)",
                )
            )
        else:
            results.append(CheckResult("warn", "Agent discovery", f"no agents indexed at {domain}"))
    except Exception as exc:
        results.append(CheckResult("warn", "Agent discovery", f"TXT index query failed: {exc}"))

    return results


def _check_backends() -> list[CheckResult]:
    """Backends: deps → env vars for each."""
    from dns_aid.cli.backends import BACKEND_REGISTRY, REAL_BACKEND_NAMES

    results: list[CheckResult] = []

    for name in REAL_BACKEND_NAMES:
        info = BACKEND_REGISTRY[name]

        # Check optional dependency
        dep_ok = True
        if info.optional_dep:
            try:
                if name == "route53":
                    importlib.import_module("boto3")
                elif name in ("cloudflare", "infoblox", "nios"):
                    importlib.import_module("httpx")
                elif name == "ddns":
                    importlib.import_module("dns.update")
                elif name == "akamai-edgedns":
                    importlib.import_module("akamai.edgegrid")
            except ImportError:
                dep_ok = False

        if not dep_ok:
            results.append(
                CheckResult(
                    "fail",
                    info.display_name,
                    f'pip install "dns-aid[{info.optional_dep}]"',
                )
            )
            continue

        # Check credentials
        if name == "route53":
            from dns_aid.cli.backends import _has_boto3_credentials

            if _has_boto3_credentials():
                results.append(CheckResult("pass", info.display_name, "credentials configured"))
            else:
                results.append(CheckResult("warn", info.display_name, "no AWS credentials found"))
        elif name == "akamai-edgedns":
            akamai_env = [
                "AKAMAI_HOST",
                "AKAMAI_CLIENT_TOKEN",
                "AKAMAI_CLIENT_SECRET",
                "AKAMAI_ACCESS_TOKEN",
            ]
            have_any = any(os.environ.get(v) for v in akamai_env)
            have_all = all(os.environ.get(v) for v in akamai_env)
            if have_any and not have_all:
                missing = [v for v in akamai_env if not os.environ.get(v)]
                results.append(
                    CheckResult(
                        "fail",
                        info.display_name,
                        f"partial credentials — {', '.join(missing)} not set",
                    )
                )
            elif have_all:
                results.append(
                    CheckResult("pass", info.display_name, "credentials configured (env vars)")
                )
            elif Path(os.path.expanduser(os.environ.get("AKAMAI_EDGERC", "~/.edgerc"))).exists():
                results.append(
                    CheckResult("pass", info.display_name, "credentials configured (~/.edgerc)")
                )
            else:
                results.append(
                    CheckResult(
                        "warn",
                        info.display_name,
                        "no credentials found (set AKAMAI_* vars or configure ~/.edgerc)",
                    )
                )
        else:
            missing = [v for v in info.required_env if not os.environ.get(v)]
            if missing:
                results.append(
                    CheckResult("warn", info.display_name, f"missing: {', '.join(missing)}")
                )
            else:
                results.append(CheckResult("pass", info.display_name, "credentials configured"))

    return results


def _check_optional() -> list[CheckResult]:
    """Optional features: MCP, JWS signing, OpenTelemetry."""
    results: list[CheckResult] = []

    checks = [
        ("mcp", "MCP server", "mcp package available", 'pip install "dns-aid[mcp]"'),
        ("cryptography", "JWS signing", "cryptography available", 'pip install "dns-aid[jws]"'),
        ("opentelemetry", "OpenTelemetry", "available", "pip install opentelemetry-api"),
    ]
    for mod_name, label, ok_detail, warn_detail in checks:
        try:
            importlib.import_module(mod_name)
            results.append(CheckResult("pass", label, ok_detail))
        except ImportError:
            results.append(CheckResult("warn", label, warn_detail))

    return results


def _check_dotenv() -> list[CheckResult]:
    """Check .env file."""
    results: list[CheckResult] = []

    env_path = Path.cwd() / ".env"
    if env_path.exists():
        lines = [
            ln
            for ln in env_path.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        results.append(CheckResult("pass", ".env file", f"{len(lines)} variable(s) set"))

        backend_val = os.environ.get("DNS_AID_BACKEND")
        if backend_val:
            results.append(CheckResult("pass", "DNS_AID_BACKEND", backend_val))
        else:
            results.append(
                CheckResult("warn", "DNS_AID_BACKEND", "not set (will auto-detect or default)")
            )
    else:
        results.append(
            CheckResult("warn", ".env file", "not found — copy .env.example to get started")
        )

    return results


# ── public API ────────────────────────────────────────────────────


def run_checks(*, domain: str | None = None) -> DiagnosticReport:
    """Run all environment diagnostics and return structured results.

    Args:
        domain: Domain to test agent discovery against.  Falls back to
            ``DNS_AID_DOCTOR_DOMAIN`` env var.  Skipped if neither is set.

    Example::

        from dns_aid.doctor import run_checks

        report = run_checks(domain="example.com")
        if report.fail_count:
            print(f"{report.fail_count} checks failed")
        for section, checks in report.sections.items():
            for check in checks:
                print(f"[{check.status}] {check.label}: {check.detail}")
    """
    from dns_aid import __version__

    report = DiagnosticReport(version=__version__)
    report.sections["Core"] = _check_core(__version__)
    report.sections["DNS"] = _check_dns(domain=domain)
    report.sections["Backends"] = _check_backends()
    report.sections["Optional Features"] = _check_optional()
    report.sections["Configuration"] = _check_dotenv()
    return report
