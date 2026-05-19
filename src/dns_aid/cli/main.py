# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Command Line Interface.

Usage:
    dns-aid init            Interactive setup wizard
    dns-aid doctor          Diagnose environment and backends
    dns-aid publish         Publish an agent to DNS
    dns-aid discover        Discover agents at a domain
    dns-aid verify          Verify agent DNS records
    dns-aid list            List DNS-AID records
    dns-aid zones           List available DNS zones
    dns-aid delete          Delete an agent from DNS
    dns-aid message         Send a message to an A2A agent
    dns-aid call            Call a tool on a remote MCP agent
    dns-aid list-tools      List tools on a remote MCP agent
    dns-aid index list      List agents in domain's index
    dns-aid index sync      Sync index with actual DNS records
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="dns-aid",
    help="DNS-based Agent Identification and Discovery",
    no_args_is_help=True,
)

console = Console()
error_console = Console(stderr=True)


def run_async(coro):
    """Run async function in sync context."""
    return asyncio.run(coro)


# ============================================================================
# PUBLISH COMMAND
# ============================================================================


@app.command()
def publish(
    name: Annotated[str, typer.Option("--name", "-n", help="Agent name (e.g., 'chat', 'network')")],
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain to publish under")],
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="Protocol: mcp or a2a")] = "mcp",
    endpoint: Annotated[
        str | None, typer.Option("--endpoint", "-e", help="Agent endpoint hostname")
    ] = None,
    port: Annotated[int, typer.Option("--port", help="Port number")] = 443,
    capability: Annotated[
        list[str] | None,
        typer.Option("--capability", "-c", help="Agent capability (repeatable)"),
    ] = None,
    version: Annotated[str, typer.Option("--version", "-v", help="Agent version")] = "1.0.0",
    description: Annotated[
        str | None,
        typer.Option("--description", help="Human-readable description of the agent"),
    ] = None,
    use_case: Annotated[
        list[str] | None,
        typer.Option("--use-case", "-u", help="Use case for this agent (repeatable)"),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Agent category (e.g., 'network', 'security', 'chat')"),
    ] = None,
    transport: Annotated[
        str | None,
        typer.Option(
            "--transport",
            help="Transport: streamable-http, https, ws, stdio, sse",
        ),
    ] = None,
    auth_type: Annotated[
        str | None,
        typer.Option(
            "--auth-type",
            help="Auth type: none, api_key, bearer, oauth2, mtls, http_msg_sig",
        ),
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="DNS TTL in seconds")] = 3600,
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    cap_uri: Annotated[
        str | None,
        typer.Option("--cap-uri", help="URI to capability document (DNS-AID draft-compliant)"),
    ] = None,
    cap_sha256: Annotated[
        str | None,
        typer.Option(
            "--cap-sha256",
            help="Base64url-encoded SHA-256 digest of the capability descriptor for integrity checks",
        ),
    ] = None,
    bap: Annotated[
        str | None,
        typer.Option(
            "--bap", help="Supported bulk agent protocols (comma-separated, e.g., 'mcp,a2a')"
        ),
    ] = None,
    policy_uri: Annotated[
        str | None,
        typer.Option("--policy-uri", help="URI to agent policy document"),
    ] = None,
    realm: Annotated[
        str | None,
        typer.Option("--realm", help="Multi-tenant scope identifier (e.g., 'production', 'demo')"),
    ] = None,
    connect_class: Annotated[
        str | None,
        typer.Option(
            "--connect-class",
            help="Connection mediation class (e.g., 'direct', 'lattice', 'apphub-psc')",
        ),
    ] = None,
    connect_meta: Annotated[
        str | None,
        typer.Option(
            "--connect-meta", help="Provider-specific connection metadata (e.g., service ARN)"
        ),
    ] = None,
    enroll_uri: Annotated[
        str | None,
        typer.Option(
            "--enroll-uri", help="Managed enrollment endpoint required before direct connection"
        ),
    ] = None,
    ipv4hint: Annotated[
        list[str] | None,
        typer.Option("--ipv4hint", help="IPv4 address hint for SVCB record (repeatable)"),
    ] = None,
    ipv6hint: Annotated[
        list[str] | None,
        typer.Option("--ipv6hint", help="IPv6 address hint for SVCB record (repeatable)"),
    ] = None,
    no_update_index: Annotated[
        bool,
        typer.Option("--no-update-index", help="Don't update the domain's agent index record"),
    ] = False,
    sign: Annotated[
        bool,
        typer.Option("--sign", help="Sign record with JWS (requires --private-key)"),
    ] = False,
    private_key: Annotated[
        str | None,
        typer.Option("--private-key", help="Path to EC P-256 private key PEM for signing"),
    ] = None,
):
    """
    Publish an agent to DNS using DNS-AID protocol.

    Creates SVCB and TXT records that allow other agents to discover this agent.

    Example:
        dns-aid publish -n network-specialist -d example.com -p mcp -e mcp.example.com -c ipam -c dns

        # With metadata:
        dns-aid publish -n billing -d example.com -p mcp \\
          --description "Handles invoicing and payments" \\
          --use-case "Generate invoices" --use-case "Process refunds" \\
          --category finance

        # With DNS-AID draft params:
        dns-aid publish -n booking -d example.com -p mcp \\
          --cap-uri https://mcp.example.com/.well-known/agent-cap.json \\
          --bap mcp --realm production

        # With address hints (skip extra A/AAAA lookup):
        dns-aid publish -n triage -d example.com -p a2a \\
          --ipv4hint 203.0.113.10 --ipv4hint 203.0.113.11

        # With JWS signing (alternative to DNSSEC):
        dns-aid publish -n booking -d example.com -p mcp \\
          --sign --private-key ./keys/private.pem
    """
    from dns_aid.core.publisher import publish as do_publish

    # Default endpoint to {protocol}.{domain}
    if endpoint is None:
        endpoint = f"{protocol}.{domain}"

    # Get backend
    dns_backend = _get_backend(backend)

    console.print("\n[bold]Publishing agent to DNS...[/bold]\n")

    # Parse bap comma-separated string into list
    bap_list = [b.strip() for b in bap.split(",") if b.strip()] if bap else None

    # Validate sign options
    if sign and not private_key:
        error_console.print("[red]✗ --sign requires --private-key[/red]")
        raise typer.Exit(1)

    result = run_async(
        do_publish(
            name=name,
            domain=domain,
            protocol=protocol,
            endpoint=endpoint,
            port=port,
            capabilities=capability or [],
            version=version,
            description=description,
            use_cases=use_case or [],
            category=category,
            ttl=ttl,
            backend=dns_backend,
            cap_uri=cap_uri,
            cap_sha256=cap_sha256,
            bap=bap_list,
            policy_uri=policy_uri,
            realm=realm,
            connect_class=connect_class,
            connect_meta=connect_meta,
            enroll_uri=enroll_uri,
            ipv4_hint=",".join(ipv4hint) if ipv4hint else None,
            ipv6_hint=",".join(ipv6hint) if ipv6hint else None,
            sign=sign,
            private_key_path=private_key,
        )
    )

    if result.success:
        console.print("[green]✓ Agent published successfully![/green]\n")
        console.print(f"  [bold]FQDN:[/bold] {result.agent.fqdn}")
        console.print(f"  [bold]Endpoint:[/bold] {result.agent.endpoint_url}")
        console.print("\n  [bold]Records created:[/bold]")
        for record in result.records_created:
            console.print(f"    • {record}")

        # Update the domain's agent index
        if not no_update_index:
            from dns_aid.core.indexer import IndexEntry, update_index

            index_result = run_async(
                update_index(
                    domain=domain,
                    backend=dns_backend,
                    add=[IndexEntry(name=name, protocol=protocol)],
                    ttl=ttl,
                )
            )
            if index_result.success:
                action = "Created" if index_result.created else "Updated"
                console.print(
                    f"\n[green]✓ {action} index at _index._agents.{domain} "
                    f"({len(index_result.entries)} agent(s))[/green]"
                )
            else:
                console.print(f"\n[yellow]⚠ Index update failed: {index_result.message}[/yellow]")

        console.print("\n[dim]Verify with:[/dim]")
        console.print(f"  dig {result.agent.fqdn} SVCB")
        console.print(f"  dig {result.agent.fqdn} TXT")
    else:
        error_console.print(f"[red]✗ Failed to publish: {result.message}[/red]")
        raise typer.Exit(1)


# ============================================================================
# DISCOVER COMMAND
# ============================================================================


@app.command()
def discover(
    domain: Annotated[str, typer.Argument(help="Domain to search for agents")],
    protocol: Annotated[
        str | None, typer.Option("--protocol", "-p", help="Filter by protocol")
    ] = None,
    name: Annotated[str | None, typer.Option("--name", "-n", help="Filter by agent name")] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
    use_http_index: Annotated[
        bool,
        typer.Option(
            "--use-http-index",
            "--http",
            help="Use HTTP index endpoint (https://_index._aiagents.{domain}/index-wellknown) instead of DNS-only discovery",
        ),
    ] = False,
    verify_signatures: Annotated[
        bool,
        typer.Option(
            "--verify-signatures",
            "--verify",
            help="Verify JWS signatures on agents (alternative to DNSSEC)",
        ),
    ] = False,
    capabilities: Annotated[
        list[str] | None,
        typer.Option(
            "--capabilities",
            help="Required capability (repeatable; all-of match).",
        ),
    ] = None,
    capabilities_any: Annotated[
        list[str] | None,
        typer.Option(
            "--capabilities-any",
            help="Any-of capability match (repeatable).",
        ),
    ] = None,
    auth_type: Annotated[
        str | None,
        typer.Option("--auth-type", help="Filter by auth type (oauth2, api_key, ...)."),
    ] = None,
    intent: Annotated[
        str | None,
        typer.Option(
            "--intent",
            help="Filter by intent (query / command / transaction / subscription).",
        ),
    ] = None,
    transport: Annotated[
        str | None,
        typer.Option("--transport", help="Filter by transport (Path A: matches protocol)."),
    ] = None,
    realm: Annotated[
        str | None,
        typer.Option("--realm", help="Filter by realm."),
    ] = None,
    min_dnssec: Annotated[
        bool,
        typer.Option(
            "--min-dnssec",
            help="Only return records whose DNS response was DNSSEC-validated.",
        ),
    ] = False,
    text_match: Annotated[
        str | None,
        typer.Option(
            "--text-match",
            help="Case-insensitive substring match across description, use_cases, capabilities.",
        ),
    ] = None,
    require_signed: Annotated[
        bool,
        typer.Option(
            "--require-signed",
            help="Only return records whose JWS signature verified (auto-enables --verify-signatures).",
        ),
    ] = False,
    require_signature_algorithm: Annotated[
        list[str] | None,
        typer.Option(
            "--require-signature-algorithm",
            help="Restrict --require-signed matches to records whose verified algorithm is in this allow-list (repeatable).",
        ),
    ] = None,
):
    """
    Discover agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records and returns agent endpoints.

    By default, uses pure DNS discovery. Use --use-http-index to fetch
    agent list from HTTP endpoint with richer metadata.

    Example:
        dns-aid discover example.com
        dns-aid discover example.com --protocol mcp
        dns-aid discover example.com --name chat --require-signed
        dns-aid discover example.com --capabilities payment-processing --auth-type oauth2
    """
    from dns_aid.core.discoverer import discover as do_discover

    method = "HTTP index" if use_http_index else "DNS"
    console.print(f"\n[bold]Discovering agents at {domain} via {method}...[/bold]\n")

    try:
        result = run_async(
            do_discover(
                domain=domain,
                protocol=protocol,
                name=name,
                use_http_index=use_http_index,
                verify_signatures=verify_signatures,
                capabilities=capabilities,
                capabilities_any=capabilities_any,
                auth_type=auth_type,
                intent=intent,
                transport=transport,
                realm=realm,
                min_dnssec=min_dnssec,
                text_match=text_match,
                require_signed=require_signed,
                require_signature_algorithm=require_signature_algorithm,
            )
        )
    except ValueError as exc:
        error_console.print(f"[red]Invalid filter combination:[/red] {exc}")
        raise typer.Exit(code=64) from exc

    if json_output:
        import json

        output = {
            "domain": result.domain,
            "query": result.query,
            "discovery_method": "http_index" if use_http_index else "dns",
            "agents": [
                {
                    "name": a.name,
                    "protocol": a.protocol.value,
                    "endpoint": a.endpoint_url,
                    "capabilities": a.capabilities,
                    "capability_source": a.capability_source,
                    "cap_uri": a.cap_uri,
                    "cap_sha256": a.cap_sha256,
                    "bap": a.bap if a.bap else None,
                    "policy_uri": a.policy_uri,
                    "realm": a.realm,
                    "description": a.description,
                }
                for a in result.agents
            ],
            "count": result.count,
            "query_time_ms": result.query_time_ms,
        }
        console.print_json(json.dumps(output))
        return

    if result.count == 0:
        console.print(f"[yellow]No agents found at {domain}[/yellow]")
        console.print(f"\n[dim]Query: {result.query}[/dim]")
        console.print(f"[dim]Time: {result.query_time_ms:.2f}ms[/dim]")
        return

    console.print(f"[green]Found {result.count} agent(s) at {domain}:[/green]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("Endpoint")
    table.add_column("Capabilities")
    table.add_column("Cap Source")

    for agent in result.agents:
        table.add_row(
            agent.name,
            agent.protocol.value,
            agent.endpoint_url,
            ", ".join(agent.capabilities) if agent.capabilities else "-",
            agent.capability_source or "-",
        )

    console.print(table)
    console.print(f"\n[dim]Query: {result.query}[/dim]")
    console.print(f"[dim]Time: {result.query_time_ms:.2f}ms[/dim]")


# ============================================================================
# SEARCH COMMAND (Path B — directory-backed cross-domain search)
# ============================================================================


# Exit codes mirror BSD ``sysexits.h`` so shell automation can dispatch on them.
_EXIT_TRANSIENT = 75  # EX_TEMPFAIL — directory unreachable / 5xx / timeout / 429
_EXIT_AUTH = 77  # EX_NOPERM — directory rejected credentials (401/403)
_EXIT_CONFIG = 78  # EX_CONFIG — directory_api_url not set


@app.command()
def search(
    query: Annotated[
        str | None,
        typer.Argument(help="Free-text query (omit to browse all matches)."),
    ] = None,
    protocol: Annotated[
        str | None,
        typer.Option("--protocol", "-p", help="Filter by protocol (mcp / a2a / https)."),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", help="Filter by domain."),
    ] = None,
    capabilities: Annotated[
        list[str] | None,
        typer.Option(
            "--capabilities",
            help="Required capability (repeatable; matches all-of).",
        ),
    ] = None,
    intent: Annotated[
        str | None,
        typer.Option(
            "--intent",
            help="Action intent (query / command / transaction / subscription).",
        ),
    ] = None,
    auth_type: Annotated[
        str | None,
        typer.Option("--auth-type", help="Filter by auth type (oauth2, api_key, bearer, ...)."),
    ] = None,
    transport: Annotated[
        str | None,
        typer.Option("--transport", help="Filter by transport (streamable-http, https, sse, ...)."),
    ] = None,
    realm: Annotated[
        str | None,
        typer.Option("--realm", help="Filter by realm (multi-tenant scope)."),
    ] = None,
    min_security_score: Annotated[
        int | None,
        typer.Option("--min-security-score", help="Minimum security score (0-100)."),
    ] = None,
    verified_only: Annotated[
        bool,
        typer.Option("--verified-only", help="Restrict to DCV-verified domains only."),
    ] = False,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Page size (1-10000).", min=1, max=10000),
    ] = 20,
    offset: Annotated[
        int,
        typer.Option("--offset", help="Pagination offset.", min=0),
    ] = 0,
    directory_url: Annotated[
        str | None,
        typer.Option(
            "--directory-url",
            help="Override the configured directory backend URL for this invocation.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Emit JSON output.")] = False,
) -> None:
    """
    Cross-domain agent search via the configured DNS-AID directory backend.

    Issues a single search call against the directory and prints ranked results with
    trust attestations. Requires ``directory_api_url`` configured (or pass
    ``--directory-url`` to override per invocation).

    Exit codes (sysexits.h):

    * 0  — success (including zero results)
    * 64 — usage error (Typer default)
    * 75 — transient failure (directory unreachable / 5xx / 429)
    * 77 — auth failure (401/403)
    * 78 — configuration error (no directory_api_url)

    Examples:
        dns-aid search "payment processing" --protocol mcp --capabilities payment-processing
        dns-aid search --intent transaction --auth-type oauth2 --min-security-score 70
        dns-aid search "fraud detection" --json
    """
    import json as _json

    from dns_aid.sdk import (
        AgentClient,
        DirectoryAuthError,
        DirectoryConfigError,
        DirectoryUnavailableError,
        SDKConfig,
    )
    from dns_aid.sdk.search import SearchResponse

    config = SDKConfig.from_env()
    if directory_url is not None:
        config = config.model_copy(update={"directory_api_url": directory_url})

    async def _run() -> SearchResponse:
        async with AgentClient(config=config) as client:
            return await client.search(
                q=query,
                protocol=protocol,  # type: ignore[arg-type]
                domain=domain,
                capabilities=capabilities,
                min_security_score=min_security_score,
                verified_only=verified_only,
                intent=intent,
                auth_type=auth_type,
                transport=transport,
                realm=realm,
                limit=limit,
                offset=offset,
            )

    try:
        response = run_async(_run())
    except DirectoryConfigError as exc:
        if json_output:
            error_console.print_json(
                _json.dumps(
                    {
                        "error": {
                            "class": "DirectoryConfigError",
                            "message": str(exc),
                            "details": exc.details,
                        }
                    }
                )
            )
        else:
            error_console.print(f"[red]Configuration error:[/red] {exc}")
            error_console.print(
                f"[dim]Set environment variable {exc.details.get('env_var')} or use --directory-url.[/dim]"
            )
        raise typer.Exit(code=_EXIT_CONFIG) from exc
    except DirectoryAuthError as exc:
        if json_output:
            error_console.print_json(
                _json.dumps(
                    {
                        "error": {
                            "class": "DirectoryAuthError",
                            "message": str(exc),
                            "details": exc.details,
                        }
                    }
                )
            )
        else:
            error_console.print(f"[red]Auth failed:[/red] {exc}")
        raise typer.Exit(code=_EXIT_AUTH) from exc
    except DirectoryUnavailableError as exc:
        if json_output:
            error_console.print_json(
                _json.dumps(
                    {
                        "error": {
                            "class": type(exc).__name__,
                            "message": str(exc),
                            "details": exc.details,
                        }
                    }
                )
            )
        else:
            error_console.print(f"[yellow]Directory unavailable:[/yellow] {exc}")
        raise typer.Exit(code=_EXIT_TRANSIENT) from exc

    if json_output:
        console.print_json(response.model_dump_json())
        return

    if not response.results:
        console.print(f"[yellow]No agents matched the query (total {response.total}).[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Score", justify="right")
    table.add_column("FQDN")
    table.add_column("Tier", justify="right")
    table.add_column("Sec", justify="right")
    table.add_column("Trust", justify="right")
    table.add_column("Capabilities")

    for result in response.results:
        agent = result.agent
        fqdn = f"_{agent.name}._{agent.protocol.value}._agents.{agent.domain}"
        table.add_row(
            f"{result.score:.2f}",
            fqdn,
            f"T{result.trust.trust_tier}",
            str(result.trust.security_score),
            str(result.trust.trust_score),
            ", ".join(agent.capabilities) if agent.capabilities else "-",
        )

    console.print(table)
    shown = len(response.results) + response.offset
    console.print(
        f"\n[dim]Showing {response.offset + 1}-{shown} of {response.total} results.[/dim]"
    )
    if response.has_more:
        console.print(f"[dim]Use --offset {response.next_offset} to see the next page.[/dim]")


# ============================================================================
# VERIFY COMMAND
# ============================================================================


@app.command()
def verify(
    fqdn: Annotated[
        str, typer.Argument(help="FQDN to verify (e.g., _chat._a2a._agents.example.com)")
    ],
):
    """
    Verify DNS-AID records for an agent.

    Checks DNS record existence, DNSSEC validation, and endpoint health.

    Example:
        dns-aid verify _chat._a2a._agents.example.com
    """
    from dns_aid.core.validator import verify as do_verify

    console.print(f"\n[bold]Verifying {fqdn}...[/bold]\n")

    result = run_async(do_verify(fqdn))

    # Display results
    def status(ok: bool | None) -> str:
        if ok is None:
            return "[yellow]○[/yellow]"
        return "[green]✓[/green]" if ok else "[red]✗[/red]"

    console.print(f"  {status(result.record_exists)} DNS record exists")
    console.print(f"  {status(result.svcb_valid)} SVCB record valid")
    console.print(f"  {status(result.dnssec_valid)} DNSSEC validated")
    console.print(f"  {status(result.dane_valid)} DANE/TLSA configured")
    console.print(f"  {status(result.endpoint_reachable)} Endpoint reachable")

    if result.endpoint_latency_ms:
        console.print(f"    [dim]Latency: {result.endpoint_latency_ms:.0f}ms[/dim]")

    console.print(
        f"\n[bold]Security Score:[/bold] {result.security_score}/100 ({result.security_rating})"
    )


# ============================================================================
# LIST COMMAND
# ============================================================================


@app.command("list")
def list_records(
    domain: Annotated[str, typer.Argument(help="Domain to list records from")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List DNS-AID records in a domain.

    Shows all _agents.* records in the specified zone.

    Example:
        dns-aid list example.com
    """
    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]DNS-AID records in {domain}:[/bold]\n")

    async def list_all():
        if not await dns_backend.zone_exists(domain):
            return None  # sentinel: zone not found
        records = []
        async for record in dns_backend.list_records(domain, name_pattern="_agents"):
            records.append(record)
        return records

    try:
        records = run_async(list_all())
    except Exception as e:
        error_console.print(f"[red]✗ Failed to list records in {domain}: {e}[/red]")
        raise typer.Exit(1) from None

    if records is None:
        error_console.print(f"[red]✗ Zone '{domain}' does not exist or is not accessible[/red]")
        raise typer.Exit(1)

    if not records:
        console.print(f"[yellow]No DNS-AID records found in {domain}[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("TTL")
    table.add_column("Value")

    for record in records:
        value = record.get("values", [])
        if isinstance(value, list):
            value = value[0] if value else "-"
        if len(str(value)) > 50:
            value = str(value)[:47] + "..."

        table.add_row(
            record["fqdn"],
            record["type"],
            str(record["ttl"]),
            str(value),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(records)} record(s)[/dim]")


# ============================================================================
# ZONES COMMAND
# ============================================================================


@app.command()
def zones(
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List available DNS zones.

    Shows all zones accessible with current credentials.

    Example:
        dns-aid zones
    """
    dns_backend = _get_backend(backend)

    from dns_aid.backends.route53 import Route53Backend

    if not isinstance(dns_backend, Route53Backend):
        error_console.print("[red]Zone listing only supported for route53 backend[/red]")
        raise typer.Exit(1)

    console.print("\n[bold]Available DNS zones (route53):[/bold]\n")

    zone_list = run_async(dns_backend.list_zones())

    table = Table(show_header=True, header_style="bold")
    table.add_column("Domain")
    table.add_column("Zone ID")
    table.add_column("Records")
    table.add_column("Type")

    for zone in zone_list:
        table.add_row(
            zone["name"],
            zone["id"],
            str(zone["record_count"]),
            "Private" if zone["private"] else "Public",
        )

    console.print(table)


# ============================================================================
# DELETE COMMAND
# ============================================================================


@app.command()
def delete(
    name: Annotated[str, typer.Option("--name", "-n", help="Agent name")],
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain")],
    protocol: Annotated[str, typer.Option("--protocol", "-p", help="Protocol")] = "mcp",
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
    no_update_index: Annotated[
        bool,
        typer.Option("--no-update-index", help="Don't update the domain's agent index record"),
    ] = False,
):
    """
    Delete an agent from DNS.

    Removes SVCB and TXT records for the specified agent.
    By default, also removes the agent from the domain's index record.

    Example:
        dns-aid delete -n chat -d example.com -p a2a
    """
    from dns_aid.core.publisher import unpublish

    fqdn = f"_{name}._{protocol}._agents.{domain}"

    if not force:
        confirm = typer.confirm(f"Delete {fqdn}?")
        if not confirm:
            raise typer.Abort()

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Deleting {fqdn}...[/bold]\n")

    try:
        result = run_async(
            unpublish(
                name=name,
                domain=domain,
                protocol=protocol,
                backend=dns_backend,
            )
        )
    except Exception as e:
        error_console.print(f"[red]✗ Failed to delete {fqdn}: {e}[/red]")
        raise typer.Exit(1) from None

    if result:
        console.print("[green]✓ Agent deleted successfully[/green]")

        # Update the domain's agent index
        if not no_update_index:
            from dns_aid.core.indexer import IndexEntry, update_index

            index_result = run_async(
                update_index(
                    domain=domain,
                    backend=dns_backend,
                    remove=[IndexEntry(name=name, protocol=protocol)],
                )
            )
            if index_result.success:
                console.print(
                    f"[green]✓ Updated index at _index._agents.{domain} "
                    f"({len(index_result.entries)} agent(s))[/green]"
                )
            else:
                console.print(f"[yellow]⚠ Index update failed: {index_result.message}[/yellow]")
    else:
        console.print("[yellow]No records found to delete[/yellow]")


# ============================================================================
# AGENT COMMUNICATION COMMANDS
# ============================================================================


@app.command()
def message(
    text: Annotated[str, typer.Argument(help="Message text to send")],
    endpoint: Annotated[
        str | None,
        typer.Option("--endpoint", "-e", help="A2A agent endpoint URL"),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", "-d", help="Domain to discover agent (use with --name)"),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Agent name to discover (use with --domain)"),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout in seconds")] = 30.0,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
):
    """
    Send a message to an A2A agent.

    Resolves the agent via DNS discovery + Agent Card, then sends a standard
    A2A JSON-RPC message/send request.

    Example:
        dns-aid message "What is DNS-AID?" -d ai.infoblox.com -n security-analyzer
        dns-aid message "Hello" -e https://chat.example.com
        dns-aid message "Analyze this" -e https://security-analyzer.ai.infoblox.com --json
    """
    import json

    from dns_aid.core.invoke import send_a2a_message

    if not endpoint and not (domain and name):
        error_console.print("[red]✗ Provide --endpoint URL or both --domain and --name[/red]")
        raise typer.Exit(1)

    if not text.strip():
        error_console.print("[red]✗ Message cannot be empty[/red]")
        raise typer.Exit(1)

    target = endpoint or f"{name} at {domain}"
    console.print(f"\n[bold]Sending message to {target}...[/bold]\n")

    result = run_async(
        send_a2a_message(
            endpoint, text, domain=domain, name=name, timeout=timeout, caller_id="dns-aid-cli"
        )
    )

    if not result.success:
        error_console.print(f"[red]✗ {result.error}[/red]")
        raise typer.Exit(1)

    # Show resolution info
    if isinstance(result.data, dict) and "agent_info" in result.data:
        info = result.data["agent_info"]
        if info.get("resolved_via") != "direct":
            console.print(f"[dim]Resolved via: {info['resolved_via']}[/dim]")
        if "canonical_endpoint" in info:
            console.print(f"[dim]Canonical URL: {info['canonical_endpoint']}[/dim]")
        if info.get("name"):
            console.print(f"[dim]Agent: {info['name']}[/dim]")
        console.print()

    if json_output:
        raw = result.data.get("raw", result.data) if isinstance(result.data, dict) else result.data
        console.print_json(json.dumps(raw))
        return

    # Display extracted text or raw response
    if isinstance(result.data, dict) and "response_text" in result.data:
        console.print(f"[green]Agent response:[/green]\n\n{result.data['response_text']}")
    else:
        console.print_json(json.dumps(result.data))


@app.command()
def call(
    endpoint: Annotated[str, typer.Argument(help="MCP agent endpoint URL")],
    tool_name: Annotated[str, typer.Argument(help="Name of the tool to call")],
    arguments: Annotated[
        str | None,
        typer.Option("--arguments", "-a", help="Tool arguments as JSON string"),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout in seconds")] = 30.0,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
):
    """
    Call a tool on a remote MCP agent.

    Sends an MCP JSON-RPC tools/call request to the agent's endpoint.
    Use 'dns-aid list-tools' first to see available tools.

    Example:
        dns-aid call https://mcp.example.com/mcp analyze_security --arguments '{"domain":"example.com"}'
        dns-aid list-tools https://mcp.example.com/mcp  # see available tools first
    """
    import json as json_mod

    from dns_aid.core.invoke import call_mcp_tool

    # Parse arguments
    tool_args = {}
    if arguments:
        try:
            tool_args = json_mod.loads(arguments)
        except json_mod.JSONDecodeError:
            error_console.print("[red]✗ Invalid JSON in --arguments[/red]")
            raise typer.Exit(1) from None

    console.print(f"\n[bold]Calling {tool_name} on {endpoint}...[/bold]\n")

    result = run_async(
        call_mcp_tool(endpoint, tool_name, tool_args, timeout=timeout, caller_id="dns-aid-cli")
    )

    if not result.success:
        error_console.print(f"[red]✗ {result.error}[/red]")
        raise typer.Exit(1)

    if json_output:
        console.print_json(json_mod.dumps(result.data))
        return

    # Display result — handle MCP content arrays
    data = result.data
    if isinstance(data, dict) and "content" in data:
        for item in data["content"]:
            if isinstance(item, dict) and "text" in item:
                console.print(f"[green]{item['text']}[/green]")
            else:
                console.print(str(item))
    elif isinstance(data, str):
        console.print(f"[green]{data}[/green]")
    else:
        console.print_json(json_mod.dumps(data))


@app.command("list-tools")
def list_tools(
    endpoint: Annotated[str, typer.Argument(help="MCP agent endpoint URL")],
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout in seconds")] = 30.0,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
):
    """
    List available tools on a remote MCP agent.

    Sends an MCP JSON-RPC tools/list request to discover what tools
    the agent exposes.

    Example:
        dns-aid list-tools https://mcp.example.com/mcp
        dns-aid list-tools https://mcp.example.com/mcp --json
    """
    import json

    from dns_aid.core.invoke import list_mcp_tools

    console.print(f"\n[bold]Listing tools on {endpoint}...[/bold]\n")

    result = run_async(list_mcp_tools(endpoint, timeout=timeout, caller_id="dns-aid-cli"))

    if not result.success:
        error_console.print(f"[red]✗ {result.error}[/red]")
        raise typer.Exit(1)

    tools_list = result.data if isinstance(result.data, list) else []

    if json_output:
        console.print_json(json.dumps(tools_list))
        return

    if not tools_list:
        console.print("[yellow]No tools found[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool Name")
    table.add_column("Description")

    for tool in tools_list:
        table.add_row(
            tool.get("name", "-"),
            tool.get("description", "-")[:80],
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(tools_list)} tool(s)[/dim]")


# ============================================================================
# INDEX COMMANDS
# ============================================================================

# Create a sub-app for index commands
index_app = typer.Typer(
    name="index",
    help="Manage domain agent index records",
    no_args_is_help=True,
)
app.add_typer(index_app, name="index")


@index_app.command("list")
def index_list(
    domain: Annotated[str, typer.Argument(help="Domain to list index from")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
):
    """
    List agents in a domain's index record.

    Shows all agents listed in _index._agents.{domain}.

    Example:
        dns-aid index list example.com
    """
    from dns_aid.core.indexer import read_index, read_index_via_dns

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Agent index for {domain}:[/bold]\n")

    entries = run_async(read_index(domain, dns_backend))

    if not entries:
        # Fallback: try direct DNS query (works without backend credentials)
        entries = run_async(read_index_via_dns(domain))

    if not entries:
        console.print(f"[yellow]No index record found at _index._agents.{domain}[/yellow]")
        console.print(
            "\n[dim]Tip: Publish an agent or run 'dns-aid index sync' to create the index[/dim]"
        )
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Protocol")
    table.add_column("FQDN")

    for entry in sorted(entries, key=lambda e: (e.name, e.protocol)):
        fqdn = f"_{entry.name}._{entry.protocol}._agents.{domain}"
        table.add_row(entry.name, entry.protocol, fqdn)

    console.print(table)
    console.print(f"\n[dim]Total: {len(entries)} agent(s) in index[/dim]")


@index_app.command("sync")
def index_sync(
    domain: Annotated[str, typer.Argument(help="Domain to sync index for")],
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="DNS backend, or set DNS_AID_BACKEND env var",
            show_default="route53",
        ),
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="TTL for index record")] = 3600,
):
    """
    Sync index with actual DNS records.

    Scans for all _agents.* SVCB records and updates the index to match.

    Example:
        dns-aid index sync example.com
    """
    from dns_aid.core.indexer import sync_index

    dns_backend = _get_backend(backend)

    console.print(f"\n[bold]Syncing index for {domain}...[/bold]\n")

    try:
        result = run_async(sync_index(domain, dns_backend, ttl=ttl))
    except Exception as e:
        error_console.print(f"[red]✗ Failed to sync index for {domain}: {e}[/red]")
        raise typer.Exit(1) from None

    if result.success:
        if result.entries:
            console.print(f"[green]✓ {result.message}[/green]\n")

            table = Table(show_header=True, header_style="bold")
            table.add_column("Name")
            table.add_column("Protocol")

            for entry in sorted(result.entries, key=lambda e: (e.name, e.protocol)):
                table.add_row(entry.name, entry.protocol)

            console.print(table)

            if result.created:
                console.print(f"\n[dim]Index record created at _index._agents.{domain}[/dim]")
        else:
            console.print("[yellow]No agents found to index[/yellow]")
    else:
        error_console.print(f"[red]✗ Sync failed: {result.message}[/red]")
        raise typer.Exit(1)


# ============================================================================
# KEYS COMMANDS (JWS Signing)
# ============================================================================

keys_app = typer.Typer(
    help="Manage signing keys for JWS verification (alternative to DNSSEC)",
    no_args_is_help=True,
)
app.add_typer(keys_app, name="keys")


@keys_app.command("generate")
def keys_generate(
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output directory for keypair files"),
    ] = ".",
    kid: Annotated[
        str,
        typer.Option("--kid", help="Key ID for the keypair"),
    ] = "dns-aid-default",
    password: Annotated[
        str | None,
        typer.Option("--password", "-p", help="Password to encrypt private key (optional)"),
    ] = None,
):
    """
    Generate an EC P-256 keypair for JWS signing.

    Creates two files:
    - {output}/private.pem: Private key (keep secret!)
    - {output}/public.pem: Public key

    Example:
        dns-aid keys generate --output ./keys --kid dns-aid-2024

        # With password protection:
        dns-aid keys generate -o ./keys -p mypassword
    """
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from dns_aid.core.jwks import generate_keypair

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print("\n[bold]Generating EC P-256 keypair...[/bold]\n")

    private_key, public_key = generate_keypair()

    # Determine encryption
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    private_path = output_dir / "private.pem"
    private_path.write_bytes(private_pem)
    os.chmod(private_path, 0o600)  # Restrict permissions

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = output_dir / "public.pem"
    public_path.write_bytes(public_pem)

    console.print("[green]✓ Keypair generated successfully![/green]\n")
    console.print(f"  [bold]Private key:[/bold] {private_path}")
    console.print(f"  [bold]Public key:[/bold] {public_path}")
    console.print(f"  [bold]Key ID:[/bold] {kid}")

    if password:
        console.print("\n  [yellow]Private key is password-protected[/yellow]")
    else:
        console.print("\n  [yellow]⚠ Private key is NOT encrypted - protect this file![/yellow]")

    console.print("\n[dim]Next steps:[/dim]")
    console.print("  1. Export JWKS: dns-aid keys export-jwks -i public.pem")
    console.print("  2. Publish JWKS to: https://yourdomain/.well-known/dns-aid-jwks.json")
    console.print("  3. Sign agents: dns-aid publish --sign --private-key private.pem ...")


@keys_app.command("export-jwks")
def keys_export_jwks(
    input_key: Annotated[
        str,
        typer.Option("--input", "-i", help="Path to public key PEM file"),
    ],
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path (stdout if not specified)"),
    ] = None,
    kid: Annotated[
        str,
        typer.Option("--kid", help="Key ID to include in JWKS"),
    ] = "dns-aid-default",
):
    """
    Export a public key as a JWKS document.

    The JWKS document should be published at:
    https://yourdomain/.well-known/dns-aid-jwks.json

    Example:
        # Export to stdout
        dns-aid keys export-jwks -i public.pem

        # Export to file
        dns-aid keys export-jwks -i public.pem -o jwks.json

        # With custom key ID
        dns-aid keys export-jwks -i public.pem --kid dns-aid-2024 -o jwks.json
    """
    import json
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization

    from dns_aid.core.jwks import export_jwks

    # Load public key
    key_path = Path(input_key)
    if not key_path.exists():
        error_console.print(f"[red]✗ Key file not found: {input_key}[/red]")
        raise typer.Exit(1)

    key_data = key_path.read_bytes()

    # Try to load as public key first, then try private key
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )

    try:
        public_key = serialization.load_pem_public_key(key_data)
        if not isinstance(public_key, EllipticCurvePublicKey):
            error_console.print("[red]✗ Key must be an EC (P-256) key[/red]")
            raise typer.Exit(1)
    except Exception:
        # Try loading as private key and extracting public key
        try:
            private_key = serialization.load_pem_private_key(key_data, password=None)
            if not isinstance(private_key, EllipticCurvePrivateKey):
                error_console.print("[red]✗ Key must be an EC (P-256) key[/red]")
                raise typer.Exit(1)
            public_key = private_key.public_key()
        except Exception as e:
            error_console.print(f"[red]✗ Failed to load key: {e}[/red]")
            raise typer.Exit(1) from None

    # Generate JWKS
    jwks = export_jwks(public_key, kid=kid)
    jwks_json = json.dumps(jwks, indent=2)

    if output:
        Path(output).write_text(jwks_json)
        console.print(f"[green]✓ JWKS exported to {output}[/green]")
    else:
        console.print(jwks_json)

    console.print("\n[dim]Publish this file at:[/dim]")
    console.print("  https://yourdomain/.well-known/dns-aid-jwks.json")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _get_backend(backend_name: str | None):
    """Get DNS backend by name with helpful error messages.

    Resolution order:
      1. Explicit ``--backend`` flag
      2. ``DNS_AID_BACKEND`` environment variable
      3. Auto-detect from configured credentials
      4. Actionable error with guidance
    """
    import os

    from dns_aid.cli.backends import ALL_BACKEND_NAMES, BACKEND_REGISTRY, detect_backend

    # --- resolve backend name ---
    source = "flag"
    if backend_name is None:
        env_val = os.environ.get("DNS_AID_BACKEND")
        if env_val:
            backend_name = env_val
            source = "DNS_AID_BACKEND env var"
        else:
            try:
                backend_name = detect_backend()
                source = "auto-detect"
            except ValueError as exc:
                error_console.print(f"[red]✗ {exc}[/red]")
                raise typer.Exit(1) from None

    if backend_name is None:
        error_console.print("[red]✗ No DNS backend configured.[/red]\n")
        error_console.print("Set up a backend with one of:")
        error_console.print("  • dns-aid init          (interactive wizard)")
        error_console.print("  • --backend <name>      (per-command)")
        error_console.print("  • DNS_AID_BACKEND=name  (environment variable)\n")
        error_console.print(
            f"Available backends: {', '.join(n for n in ALL_BACKEND_NAMES if n != 'mock')}"
        )
        raise typer.Exit(1)

    backend_name = backend_name.lower()

    if backend_name not in BACKEND_REGISTRY:
        error_console.print(f"[red]✗ Unknown backend: {backend_name}[/red]")
        error_console.print(f"Available backends: {', '.join(ALL_BACKEND_NAMES)}")
        raise typer.Exit(1)

    info = BACKEND_REGISTRY[backend_name]

    # --- check required env vars ---
    missing = [var for var in info.required_env if not os.environ.get(var)]
    if missing and backend_name != "mock":
        error_console.print(
            f"[red]✗ {info.display_name} backend requires environment variables:[/red]\n"
        )
        for var in missing:
            desc = info.required_env[var]
            error_console.print(f"  {var}  — {desc}")
        if info.setup_steps:
            error_console.print("\n[bold]Setup steps:[/bold]")
            for step in info.setup_steps:
                error_console.print(f"  • {step}")
        if info.setup_url:
            error_console.print(f"\nDocs: {info.setup_url}")
        raise typer.Exit(1)

    # --- import and instantiate via central factory ---
    from dns_aid.backends import create_backend

    try:
        backend = create_backend(backend_name)
    except ImportError as exc:
        dep = f"dns-aid[{info.optional_dep}]" if info.optional_dep else "dns-aid"
        error_console.print(f"[red]✗ Missing dependency for {info.display_name}:[/red]")
        error_console.print(f"  {exc}\n")
        error_console.print(f"Install with:  pip install '{dep}'")
        raise typer.Exit(1) from None
    except (ValueError, OSError) as exc:
        error_console.print(f"[red]✗ Failed to initialize {info.display_name}:[/red]")
        error_console.print(f"  {exc}")
        if info.setup_steps:
            error_console.print("\n[bold]Setup steps:[/bold]")
            for step in info.setup_steps:
                error_console.print(f"  • {step}")
        raise typer.Exit(1) from None

    if source != "flag":
        error_console.print(f"[dim]Using {info.display_name} backend ({source})[/dim]")

    return backend


# ============================================================================
# VERSION
# ============================================================================


def version_callback(value: bool):
    if value:
        from dns_aid import __version__

        console.print(f"dns-aid version {__version__}")
        raise typer.Exit()


def quiet_callback(value: bool):
    if value:
        from dns_aid.utils.logging import silence_logging

        silence_logging()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version"),
    ] = None,
    quiet: Annotated[
        bool | None,
        typer.Option("--quiet", "-q", callback=quiet_callback, is_eager=True, help="Suppress logs"),
    ] = None,
):
    """
    DNS-AID: DNS-based Agent Identification and Discovery

    Publish and discover AI agents using DNS infrastructure.
    """
    from dotenv import load_dotenv

    load_dotenv()


# ============================================================================
# POLICY COMMANDS
# ============================================================================

policy_app = typer.Typer(
    name="policy",
    help="Compile and manage policy enforcement zones",
    no_args_is_help=True,
)
app.add_typer(policy_app, name="policy")


@policy_app.command("compile")
def policy_compile(
    input_file: Annotated[
        str,
        typer.Option("--input", "-i", help="Path to policy document JSON file"),
    ],
    output_file: Annotated[
        str,
        typer.Option("--output", "-o", help="Output zone file path"),
    ],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: rpz, bindaid, or both"),
    ] = "both",
    allow_broad_rpz: Annotated[
        bool,
        typer.Option(
            "--allow-broad-rpz",
            help="Allow wildcard RPZ triggers outside _agents.* namespace. "
            "Without this flag, broad wildcards like *.example.com are rejected.",
        ),
    ] = False,
):
    """
    Compile a policy document to RPZ and/or bind-aid zone files.

    Reads a PolicyDocument JSON file and produces DNS zone files that can be
    loaded into RPZ-capable resolvers or Ingmar's bind-aid fork.

    By default, broad wildcards outside the _agents.* namespace are rejected
    to prevent accidental DNS outages. Use --allow-broad-rpz to override.

    Example:
        dns-aid policy compile -i policy.json -o /tmp/zone.rpz -f rpz
        dns-aid policy compile -i policy.json -o /tmp/zone -f both
    """
    import json
    from pathlib import Path

    from dns_aid.sdk.policy.bindaid_writer import write_bindaid_zone
    from dns_aid.sdk.policy.compiler import PolicyCompiler
    from dns_aid.sdk.policy.rpz_writer import write_rpz_zone
    from dns_aid.sdk.policy.schema import PolicyDocument

    if format not in ("rpz", "bindaid", "both"):
        error_console.print("[red]✗ --format must be rpz, bindaid, or both[/red]")
        raise typer.Exit(1)

    input_path = Path(input_file)
    if not input_path.exists():
        error_console.print(f"[red]✗ Input file not found: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        raw = input_path.read_text()
        doc = PolicyDocument.model_validate(json.loads(raw))
    except Exception as e:
        error_console.print(f"[red]✗ Failed to parse policy document: {e}[/red]")
        raise typer.Exit(1) from None

    compiler = PolicyCompiler()
    result = compiler.compile(doc, allow_broad_rpz=allow_broad_rpz)

    output_path = Path(output_file)

    if format in ("rpz", "both"):
        rpz_path = output_path if format == "rpz" else output_path.with_suffix(".rpz")
        zone_name = f"rpz.{doc.agent.split('.')[-2]}.policy"
        rpz_content = write_rpz_zone(result, zone_name)
        rpz_path.write_text(rpz_content)
        console.print(f"[green]✓ RPZ zone written to {rpz_path}[/green]")
        console.print(f"  {len(result.rpz_directives)} directive(s)")

    if format in ("bindaid", "both"):
        ba_path = output_path if format == "bindaid" else output_path.with_suffix(".bindaid")
        zone_name = f"policy.{doc.agent.split('.')[-2]}.bindaid"
        ba_content = write_bindaid_zone(result, zone_name)
        ba_path.write_text(ba_content)
        console.print(f"[green]✓ bind-aid zone written to {ba_path}[/green]")
        console.print(f"  {len(result.bindaid_directives)} directive(s)")

    if result.skipped:
        console.print(
            f"\n[yellow]⚠ {len(result.skipped)} rule(s) skipped (Layer 1/2 only):[/yellow]"
        )
        for s in result.skipped:
            console.print(f"  • {s.rule_name}: {s.reason}")


@policy_app.command("show")
def policy_show(
    input_file: Annotated[
        str,
        typer.Option("--input", "-i", help="Path to policy document JSON file"),
    ],
    allow_broad_rpz: Annotated[
        bool,
        typer.Option(
            "--allow-broad-rpz",
            help="Allow wildcard RPZ triggers outside _agents.* namespace.",
        ),
    ] = False,
):
    """
    Show a compilation report for a policy document.

    Displays which rules compile to RPZ/bind-aid and which are skipped.

    Example:
        dns-aid policy show -i policy.json
    """
    import json
    from pathlib import Path

    from dns_aid.sdk.policy.compiler import PolicyCompiler
    from dns_aid.sdk.policy.schema import PolicyDocument

    input_path = Path(input_file)
    if not input_path.exists():
        error_console.print(f"[red]✗ Input file not found: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        raw = input_path.read_text()
        doc = PolicyDocument.model_validate(json.loads(raw))
    except Exception as e:
        error_console.print(f"[red]✗ Failed to parse policy document: {e}[/red]")
        raise typer.Exit(1) from None

    compiler = PolicyCompiler()
    result = compiler.compile(doc, allow_broad_rpz=allow_broad_rpz)

    console.print("\n[bold]Policy Compilation Report[/bold]")
    console.print(f"  Agent: {result.agent_fqdn}\n")

    # RPZ directives
    console.print(f"[bold]RPZ Directives ({len(result.rpz_directives)}):[/bold]")
    if result.rpz_directives:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Owner")
        table.add_column("Action")
        table.add_column("Source Rule")
        for rpz_d in result.rpz_directives:
            table.add_row(rpz_d.owner, rpz_d.action.value, rpz_d.source_rule)
        console.print(table)
    else:
        console.print("  [dim]None[/dim]")

    # bind-aid directives
    console.print(f"\n[bold]bind-aid Directives ({len(result.bindaid_directives)}):[/bold]")
    if result.bindaid_directives:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Owner")
        table.add_column("Action")
        table.add_column("Param Ops")
        table.add_column("Source Rule")
        for ba_d in result.bindaid_directives:
            table.add_row(
                ba_d.owner, ba_d.action.value, ", ".join(ba_d.param_ops) or "-", ba_d.source_rule
            )
        console.print(table)
    else:
        console.print("  [dim]None[/dim]")

    # Skipped rules
    console.print(f"\n[bold]Skipped Rules ({len(result.skipped)}):[/bold]")
    if result.skipped:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Rule")
        table.add_column("Reason")
        for s in result.skipped:
            table.add_row(s.rule_name, s.reason)
        console.print(table)
    else:
        console.print("  [dim]None[/dim]")


@policy_app.command("rollback")
def policy_rollback(
    rpz_zone: Annotated[
        str,
        typer.Option("--rpz-zone", help="RPZ zone name to rollback"),
    ],
    backend: Annotated[
        str,
        typer.Option("--backend", "-b", help="DNS backend for RPZ push (nios or infoblox)"),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be restored without pushing"),
    ] = False,
):
    """
    Rollback an RPZ zone to the previous snapshot.

    Before each enforce push, a snapshot is saved to .dns-aid/snapshots/.
    This command restores the most recent snapshot for the given RPZ zone.

    Example:
        dns-aid policy rollback --rpz-zone rpz.example.com -b nios --dry-run
        dns-aid policy rollback --rpz-zone rpz.example.com -b nios
    """
    from dns_aid.sdk.policy.snapshot import load_latest_snapshot

    snapshot = load_latest_snapshot(rpz_zone)
    if not snapshot:
        error_console.print(f"[red]✗ No snapshots found for zone: {rpz_zone}[/red]")
        error_console.print("  Snapshots are created during 'dns-aid enforce --mode enforce'")
        raise typer.Exit(1)

    console.print(f"\n[bold]Rollback: {rpz_zone}[/bold]")
    console.print(f"  Snapshot: {snapshot.timestamp}")
    console.print(f"  Backend: {snapshot.backend}")
    console.print(f"  Directives: {snapshot.directive_count}")
    console.print()

    for d in snapshot.directives:
        console.print(f"    {d['action']:10s}  {d['owner']}  ({d.get('source_rule', '')})")

    if dry_run:
        console.print("\n[yellow]Dry run:[/yellow] No changes pushed.")
        return

    backend_lower = backend.lower()
    if backend_lower == "nios":
        from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend

        async def _rollback_nios():
            nios = InfobloxNIOSBackend()
            try:
                await nios.ensure_rpz_zone(rpz_zone)
                pushed, errors = 0, []
                for d in snapshot.directives:
                    try:
                        await nios.create_rpz_cname_record(
                            rpz_zone=rpz_zone,
                            owner=d["owner"],
                            action=d["action"],
                            comment=f"DNS-AID rollback: {d.get('comment', '')}",
                        )
                        pushed += 1
                    except Exception as exc:
                        errors.append(f"{d['owner']}: {exc}")
                return pushed, errors
            finally:
                await nios.close()

        pushed, errors = run_async(_rollback_nios())
        console.print(
            f"\n[green]✓ Rolled back {pushed}/{snapshot.directive_count} "
            f"RPZ records to NIOS[/green]"
        )
        for err in errors:
            console.print(f"  [red]✗ {err}[/red]")

    elif backend_lower == "infoblox":
        from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend

        blocked = [
            d["owner"]
            for d in snapshot.directives
            if d["action"] in ("NXDOMAIN", "DROP") and d["owner"] != "*"
        ]
        list_name = f"dns-aid-rpz-{rpz_zone.replace('.', '-')}"

        async def _rollback_bloxone():
            bx = InfobloxBloxOneBackend()
            try:
                return await bx.create_or_update_named_list(
                    name=list_name,
                    items=blocked,
                    description=f"DNS-AID rollback for {rpz_zone}",
                )
            finally:
                await bx.close()

        run_async(_rollback_bloxone())
        console.print(
            f"\n[green]✓ Rolled back TD named list '{list_name}' "
            f"with {len(blocked)} domains[/green]"
        )
    else:
        error_console.print(f"[red]✗ Rollback not supported for backend: {backend}[/red]")
        raise typer.Exit(1)


@app.command()
def enforce(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain to enforce policy on")],
    policy_file: Annotated[
        str | None,
        typer.Option("--policy-file", "-p", help="Path to policy document JSON file"),
    ] = None,
    auto_policy: Annotated[
        bool,
        typer.Option(
            "--auto-policy",
            help="Fetch policy documents from each agent's policy_uri (SVCB key65403)",
        ),
    ] = False,
    backend: Annotated[
        str | None,
        typer.Option("--backend", "-b", help="DNS backend for RPZ publishing"),
    ] = None,
    rpz_zone: Annotated[
        str | None,
        typer.Option("--rpz-zone", help="RPZ zone name (default: rpz.{domain})"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: rpz, bindaid, or both"),
    ] = "both",
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Enforcement mode: shadow (log only) or enforce (live)"),
    ] = "shadow",
    output_dir: Annotated[
        str | None,
        typer.Option("--output-dir", "-o", help="Write zone files to this directory"),
    ] = None,
    td_policy_id: Annotated[
        int | None,
        typer.Option(
            "--td-policy-id",
            help="Infoblox TD security policy ID to bind the named list to. "
            "Default: auto-detect the default global policy.",
        ),
    ] = None,
    td_action: Annotated[
        str,
        typer.Option(
            "--td-action",
            help="TD action: action_block (NXDOMAIN), action_log (monitor only), "
            "action_redirect, action_allow",
        ),
    ] = "action_block",
    allow_broad_rpz: Annotated[
        bool,
        typer.Option(
            "--allow-broad-rpz",
            help="Allow wildcard RPZ triggers outside _agents.* namespace. "
            "Without this flag, broad wildcards like *.example.com are rejected.",
        ),
    ] = False,
    report: Annotated[
        str | None,
        typer.Option(
            "--report",
            help="Write JSON inventory report (discovered agents, compiled rules, warnings) "
            "to this path. Supports .json and .csv extensions.",
        ),
    ] = None,
):
    """
    Full enforcement pipeline: discover → compile → write zone → push to backend.

    Two policy modes:

      --policy-file: Compile a single policy document against the domain.
      --auto-policy: Discover agents, fetch each agent's policy_uri from DNS,
                     and compile all policies into a merged RPZ zone.

    Shadow mode (default) logs what would be blocked without pushing live.
    Enforce mode pushes live RPZ rules and binds to TD security policy.

    By default, broad wildcards outside the _agents.* namespace are rejected
    to prevent accidental DNS outages. Use --allow-broad-rpz to override.

    Use --report to write a JSON/CSV inventory of discovered agents and
    compiled rules — useful for auditing and compliance reporting.

    Example:
        dns-aid enforce -d example.com --auto-policy --mode shadow
        dns-aid enforce -d example.com -p policy.json --mode enforce -b infoblox
        dns-aid enforce -d example.com -p policy.json --mode shadow --report inventory.json
    """
    import json
    from pathlib import Path

    from dns_aid.sdk.policy.bindaid_writer import write_bindaid_zone
    from dns_aid.sdk.policy.compiler import CompilationResult, PolicyCompiler
    from dns_aid.sdk.policy.rpz_writer import write_rpz_zone
    from dns_aid.sdk.policy.schema import PolicyDocument

    if not policy_file and not auto_policy:
        error_console.print("[red]✗ Provide --policy-file or --auto-policy[/red]")
        raise typer.Exit(1)

    if mode not in ("shadow", "enforce"):
        error_console.print("[red]✗ --mode must be shadow or enforce[/red]")
        raise typer.Exit(1)

    if format not in ("rpz", "bindaid", "both"):
        error_console.print("[red]✗ --format must be rpz, bindaid, or both[/red]")
        raise typer.Exit(1)

    zone = rpz_zone or f"rpz.{domain}"

    console.print(f"\n[bold]Enforcing policy on {domain} (mode: {mode})...[/bold]\n")

    # Step 1: Discover agents
    from dns_aid.core.discoverer import discover as do_discover

    console.print("[bold]Step 1:[/bold] Discovering agents...")
    discovery_result = run_async(do_discover(domain=domain))
    console.print(f"  Found {discovery_result.count} agent(s)")
    agents_with_policy = [a for a in discovery_result.agents if a.policy_uri]
    if agents_with_policy:
        console.print(f"  Agents with policy_uri: {len(agents_with_policy)}")
        for a in agents_with_policy:
            console.print(f"    • {a.name} → {a.policy_uri}")
    console.print()

    # Step 2: Load and compile policies
    compiler = PolicyCompiler()
    doc = None  # used for BloxOne agent_fqdn reference

    if auto_policy:
        console.print("[bold]Step 2:[/bold] Fetching policies from agent policy_uri...")
        if not agents_with_policy:
            console.print("  [yellow]No agents have policy_uri set — nothing to compile[/yellow]")
            console.print("  [dim]Publish agents with --policy-uri to enable auto-policy[/dim]\n")
            raise typer.Exit(0)

        import httpx

        merged = CompilationResult(agent_fqdn=f"_merged._policy._agents.{domain}")
        fetched, failed = 0, 0

        for agent in agents_with_policy:
            try:
                console.print(f"  Fetching {agent.name}: {agent.policy_uri}")
                resp = run_async(httpx.AsyncClient(timeout=10).get(agent.policy_uri))
                resp.raise_for_status()
                agent_doc = PolicyDocument.model_validate(json.loads(resp.text))
                agent_result = compiler.compile(agent_doc, allow_broad_rpz=allow_broad_rpz)

                # Merge directives
                merged.rpz_directives.extend(agent_result.rpz_directives)
                merged.bindaid_directives.extend(agent_result.bindaid_directives)
                merged.skipped.extend(agent_result.skipped)
                merged.warnings.extend(agent_result.warnings)
                fetched += 1
                console.print(
                    f"    ✓ {len(agent_result.rpz_directives)} RPZ, "
                    f"{len(agent_result.bindaid_directives)} bind-aid"
                )
            except Exception as exc:
                failed += 1
                console.print(f"    [yellow]⚠ Failed: {exc}[/yellow]")

        # Deduplicate merged result
        compiler._deduplicate(merged)
        result = merged
        doc = PolicyDocument(agent=merged.agent_fqdn)  # placeholder for BloxOne reference

        console.print(f"\n  Fetched: {fetched}, Failed: {failed}")
        console.print(
            f"  Merged RPZ: {len(result.rpz_directives)}, bind-aid: {len(result.bindaid_directives)}"
        )
        console.print(f"  Skipped: {len(result.skipped)}\n")

    else:
        # Load from file
        console.print("[bold]Step 2:[/bold] Compiling policy from file...")
        policy_path = Path(policy_file)  # type: ignore[arg-type]
        if not policy_path.exists():
            error_console.print(f"[red]✗ Policy file not found: {policy_file}[/red]")
            raise typer.Exit(1)

        try:
            raw = policy_path.read_text()
            doc = PolicyDocument.model_validate(json.loads(raw))
        except Exception as e:
            error_console.print(f"[red]✗ Failed to parse policy document: {e}[/red]")
            raise typer.Exit(1) from None

        result = compiler.compile(doc, allow_broad_rpz=allow_broad_rpz)
        console.print(f"  RPZ directives: {len(result.rpz_directives)}")
        console.print(f"  bind-aid directives: {len(result.bindaid_directives)}")
        console.print(f"  Skipped rules: {len(result.skipped)}\n")

    # Step 3: Write zone files
    console.print("[bold]Step 3:[/bold] Generating zone files...")
    rpz_content = None
    ba_content = None

    if format in ("rpz", "both"):
        rpz_content = write_rpz_zone(result, zone)
        console.print(f"  RPZ zone: {zone} ({len(result.rpz_directives)} records)")

    if format in ("bindaid", "both"):
        ba_zone = f"policy.{domain}"
        ba_content = write_bindaid_zone(result, ba_zone)
        console.print(f"  bind-aid zone: {ba_zone} ({len(result.bindaid_directives)} records)")

    # Write to disk if output dir specified
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        if rpz_content:
            (out / f"{zone}.rpz").write_text(rpz_content)
            console.print(f"  Written: {out / f'{zone}.rpz'}")
        if ba_content:
            (out / f"policy.{domain}.bindaid").write_text(ba_content)
            console.print(f"  Written: {out / f'policy.{domain}.bindaid'}")

    console.print()

    # Step 4: Push or shadow
    if mode == "shadow":
        console.print("[yellow]Shadow mode:[/yellow] No changes pushed to DNS backend.")
        console.print("  The following rules WOULD be enforced:\n")
        for d in result.rpz_directives:
            console.print(f"    {d.action.value:10s}  {d.owner}  ({d.source_rule})")
    elif mode == "enforce":
        if not backend:
            error_console.print("[red]✗ Enforce mode requires --backend[/red]")
            raise typer.Exit(1)

        # Snapshot before push — enables rollback if something goes wrong
        from dns_aid.sdk.policy.snapshot import save_snapshot

        snap_path = save_snapshot(
            result.rpz_directives,
            rpz_zone=zone,
            backend=backend,
            mode=mode,
        )
        console.print(f"  [dim]Snapshot saved: {snap_path}[/dim]")

        backend_lower = backend.lower()
        console.print(f"[bold]Step 4:[/bold] Pushing RPZ to {backend}...")

        if backend_lower == "nios":
            from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend

            async def _push_nios():
                nios = InfobloxNIOSBackend()
                try:
                    await nios.ensure_rpz_zone(zone)
                    pushed, errors = 0, []
                    for d in result.rpz_directives:
                        try:
                            await nios.create_rpz_cname_record(
                                rpz_zone=zone,
                                owner=d.owner,
                                action=d.action.value,
                                comment=f"DNS-AID: {d.comment}",
                            )
                            pushed += 1
                        except Exception as exc:
                            errors.append(f"{d.owner}: {exc}")
                    return pushed, errors
                finally:
                    await nios.close()

            pushed, errors = run_async(_push_nios())
            console.print(
                f"  [green]✓ Pushed {pushed}/{len(result.rpz_directives)} "
                f"RPZ records to NIOS[/green]"
            )
            for err in errors:
                console.print(f"  [red]✗ {err}[/red]")

        elif backend_lower == "infoblox":
            from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend
            from dns_aid.sdk.policy.compiler import RPZAction

            blocked = [
                d.owner
                for d in result.rpz_directives
                if d.action in (RPZAction.NXDOMAIN, RPZAction.DROP) and d.owner != "*"
            ]

            list_name = f"dns-aid-rpz-{zone.replace('.', '-')}"

            async def _push_and_bind():
                bx = InfobloxBloxOneBackend()
                try:
                    # Step 4a: Create/update named list
                    nl_result = await bx.create_or_update_named_list(
                        name=list_name,
                        items=blocked,
                        description=f"DNS-AID RPZ for {doc.agent}",
                    )
                    # Step 4b: Bind to TD security policy
                    bind_result = await bx.bind_named_list_to_policy(
                        named_list_name=list_name,
                        policy_id=td_policy_id,
                        action=td_action,
                    )
                    return nl_result, bind_result
                finally:
                    await bx.close()

            nl_result, bind_result = run_async(_push_and_bind())

            nl_action = "Updated" if nl_result.get("updated") else "Created"
            console.print(
                f"  [green]✓ {nl_action} TD named list '{list_name}' "
                f"with {len(blocked)} blocked domains[/green]"
            )

            bind_status = bind_result.get("action")
            policy_name = bind_result.get("policy_name", "unknown")
            if bind_status == "bound":
                console.print(
                    f"  [green]✓ Bound to security policy '{policy_name}' "
                    f"(id={bind_result['policy_id']}, {bind_result['rule_count']} rules)[/green]"
                )
                console.print(
                    "  [bold]Blocked domains will receive NXDOMAIN from Threat Defense[/bold]"
                )
            elif bind_status == "already_bound":
                console.print(f"  [dim]Already bound to policy '{policy_name}'[/dim]")

        else:
            if output_dir:
                console.print(f"  Zone files written to {output_dir}")
            else:
                console.print(
                    f"[yellow]⚠ Backend '{backend}' does not support direct RPZ push. "
                    "Use --output-dir to write zone files.[/yellow]"
                )

    # Summary
    if result.skipped:
        console.print(
            f"\n[dim]Skipped {len(result.skipped)} Layer 1/2 rules "
            "(enforced by caller/target SDK, not DNS)[/dim]"
        )

    # Report generation
    if report:
        _write_enforce_report(
            report_path=Path(report),
            domain=domain,
            mode=mode,
            discovery_result=discovery_result,
            compilation_result=result,
        )


def _write_enforce_report(  # type: ignore[no-untyped-def]
    *,
    report_path,
    domain: str,
    mode: str,
    discovery_result,
    compilation_result,
) -> None:
    """Write a JSON or CSV inventory report from the enforce pipeline."""
    import csv
    import json
    from datetime import UTC, datetime
    from pathlib import Path

    report_data = {
        "domain": domain,
        "timestamp": datetime.now(UTC).isoformat(),
        "mode": mode,
        "agents_discovered": [
            {
                "name": a.name,
                "protocol": a.protocol,
                "endpoint": str(a.endpoint) if a.endpoint else None,
                "policy_uri": a.policy_uri,
            }
            for a in discovery_result.agents
        ],
        "rpz_directives": [
            {
                "owner": d.owner,
                "action": d.action.value,
                "source_rule": d.source_rule,
                "comment": d.comment,
            }
            for d in compilation_result.rpz_directives
        ],
        "skipped_rules": [
            {"rule": s.rule_name, "reason": s.reason} for s in compilation_result.skipped
        ],
        "warnings": compilation_result.warnings,
        "summary": {
            "total_agents": len(discovery_result.agents),
            "agents_with_policy": sum(1 for a in discovery_result.agents if a.policy_uri),
            "rpz_rules": len(compilation_result.rpz_directives),
            "skipped_rules": len(compilation_result.skipped),
        },
    }

    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    if report_path.suffix == ".csv":
        with report_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "protocol", "endpoint", "policy_uri"])
            for agent in report_data["agents_discovered"]:
                writer.writerow(
                    [
                        agent["name"],
                        agent["protocol"],
                        agent["endpoint"] or "",
                        agent["policy_uri"] or "",
                    ]
                )
        console.print(f"\n[green]✓ CSV inventory written to {report_path}[/green]")
    else:
        report_path.write_text(json.dumps(report_data, indent=2))
        console.print(f"\n[green]✓ JSON report written to {report_path}[/green]")


# ============================================================================
# DCV COMMANDS
# ============================================================================

dcv_app = typer.Typer(
    name="dcv",
    help="Domain Control Validation — prove zone ownership for agent identity",
    no_args_is_help=True,
)
app.add_typer(dcv_app, name="dcv")


@dcv_app.command("issue")
def dcv_issue(
    domain: Annotated[str, typer.Argument(help="Domain to challenge (e.g., orgb.test)")],
    agent_name: Annotated[
        str | None, typer.Option("--agent", "-a", help="Agent name to scope the bnd-req field")
    ] = None,
    issuer_domain: Annotated[
        str | None, typer.Option("--issuer", "-i", help="Issuer domain to scope the bnd-req field")
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="Challenge validity in seconds")] = 3600,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Generate a DCV challenge token for a domain.

    The challenger calls this and delivers the result out-of-band (A2A, MCP, etc.)
    to the claimant.  Nothing is written to DNS — placement is the claimant's job.
    """
    import json as _json

    from dns_aid.core import dcv as _dcv
    from dns_aid.utils.validation import validate_domain, validate_ttl

    domain = validate_domain(domain)
    ttl = validate_ttl(ttl)
    challenge = _dcv.issue(
        domain,
        agent_name=agent_name,
        issuer_domain=issuer_domain,
        ttl_seconds=ttl,
    )

    if json_output:
        console.print_json(_json.dumps(challenge.model_dump(mode="json")))
        return

    console.print("[bold]DCV Challenge[/bold]")
    console.print(f"  Domain  : {challenge.domain}")
    console.print(f"  FQDN    : {challenge.fqdn}")
    console.print(f"  Token   : {challenge.token}")
    console.print(f"  Expiry  : {challenge.expiry.isoformat()}")
    if challenge.bnd_req:
        console.print(f"  bnd-req : {challenge.bnd_req}")
    console.print()
    console.print("[bold]TXT record to place:[/bold]")
    console.print(f'  {challenge.fqdn}  TXT  "{challenge.txt_value}"')


@dcv_app.command("place")
def dcv_place(
    domain: Annotated[str, typer.Argument(help="Domain to write the challenge into")],
    token: Annotated[str, typer.Argument(help="Token received from the challenger")],
    bnd_req: Annotated[
        str | None, typer.Option("--bnd-req", help="Binding scope (pass through from challenge)")
    ] = None,
    ttl: Annotated[int, typer.Option("--ttl", help="DNS record TTL in seconds")] = 300,
    expiry_seconds: Annotated[
        int, typer.Option("--expiry", help="Challenge validity window in seconds")
    ] = 3600,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Write a DCV challenge TXT record to DNS via the configured backend.

    The claimant calls this using their own dns-aid backend credentials,
    proving they have write access to the domain's zone.
    """
    import json as _json

    from dns_aid.core import dcv as _dcv

    try:
        place_result = run_async(
            _dcv.place(domain, token, bnd_req=bnd_req, ttl=ttl, expiry_seconds=expiry_seconds)
        )
        if json_output:
            console.print_json(_json.dumps({"success": True, "fqdn": place_result.fqdn}))
        else:
            console.print(f"[green]✓[/green] Challenge placed at {place_result.fqdn}")
    except Exception as e:
        if json_output:
            console.print_json(_json.dumps({"success": False, "error": str(e)}))
        else:
            error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from e


@dcv_app.command("verify")
def dcv_verify_cmd(
    domain: Annotated[str, typer.Argument(help="Domain to verify challenge for")],
    token: Annotated[str, typer.Argument(help="Token originally issued by the challenger")],
    nameserver: Annotated[
        str | None,
        typer.Option("--nameserver", "-s", help="Nameserver IP address to query directly"),
    ] = None,
    port: Annotated[int, typer.Option("--port", help="DNS port")] = 53,
    expected_bnd_req: Annotated[
        str | None,
        typer.Option("--bnd-req", help="Expected bnd-req value (enforces cross-vendor binding)"),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Verify that a DCV challenge token is present and unexpired in DNS.

    The challenger calls this after the claimant has placed the record.
    No backend credentials required — pure DNS resolution.
    """
    import json as _json

    from dns_aid.core import dcv as _dcv
    from dns_aid.utils.validation import validate_port

    validate_port(port)  # always validate, even without --nameserver
    result = run_async(
        _dcv.verify(
            domain, token, nameserver=nameserver, port=port, expected_bnd_req=expected_bnd_req
        )
    )

    if json_output:
        console.print_json(_json.dumps(result.model_dump()))
        if not result.verified:
            raise typer.Exit(1)
        return

    if result.verified:
        console.print(f"[green]✓[/green] DCV verified for {result.fqdn}")
    else:
        label = "expired" if result.expired else "failed"
        console.print(f"[red]✗[/red] DCV {label} for {result.fqdn}")
        if result.error:
            console.print(f"  {result.error}")
        raise typer.Exit(1)


@dcv_app.command("revoke")
def dcv_revoke(
    domain: Annotated[str, typer.Argument(help="Domain to remove the challenge from")],
    token: Annotated[str, typer.Argument(help="Token to revoke (must match the record in DNS)")],
    json_output: Annotated[bool, typer.Option("--json", "-j", help="Output as JSON")] = False,
) -> None:
    """Delete the DCV challenge TXT record from DNS.

    Should be called immediately after successful verification to prevent token reuse.
    """
    import json as _json

    from dns_aid.core import dcv as _dcv

    try:
        revoke_result = run_async(_dcv.revoke(domain, token=token))
        if json_output:
            console.print_json(_json.dumps({"success": revoke_result.removed}))
        elif revoke_result.removed:
            console.print(f"[green]✓[/green] Challenge record removed from {domain}")
        else:
            console.print("[yellow]![/yellow] Challenge record not found (already removed?)")
        if not revoke_result.removed:
            raise typer.Exit(1)
    except Exception as e:
        if json_output:
            console.print_json(_json.dumps({"success": False, "error": str(e)}))
        else:
            error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from e


# ============================================================================
# EXPERIMENTAL: edns-probe — demonstrate EDNS(0) agent-hint signaling
# ============================================================================


@app.command("edns-probe")
def edns_probe(
    domain: Annotated[str, typer.Argument(help="Domain to discover agents at")],
    # Axis 1 — substrate filters
    realm: Annotated[
        str | None, typer.Option("--realm", help="[Axis 1] Multi-tenant scope identifier.")
    ] = None,
    transport: Annotated[
        str | None,
        typer.Option("--transport", help="[Axis 1] Transport: mcp | a2a | https."),
    ] = None,
    policy_required: Annotated[
        bool,
        typer.Option(
            "--policy-required",
            help="[Axis 1] Only return records carrying a policy= URI.",
        ),
    ] = False,
    min_trust: Annotated[
        str | None,
        typer.Option(
            "--min-trust",
            help="[Axis 1] Trust posture: signed | dnssec | signed+dnssec.",
        ),
    ] = None,
    jurisdiction: Annotated[
        str | None,
        typer.Option("--jurisdiction", help="[Axis 1] ISO region tag (e.g. eu, us-east)."),
    ] = None,
    # Axis 2 — metering / lifecycle
    intent_class: Annotated[
        str | None,
        typer.Option(
            "--intent-class",
            help="[Axis 2] Client intent: discovery | invocation.",
        ),
    ] = None,
    max_age: Annotated[
        int | None,
        typer.Option(
            "--max-age",
            help="[Axis 2] Don't return cache entries older than this many seconds.",
        ),
    ] = None,
    parallelism: Annotated[
        int | None,
        typer.Option(
            "--parallelism",
            help="[Axis 2] Expected sibling-query count (signals fan-out to caches).",
        ),
    ] = None,
    deadline_ms: Annotated[
        int | None,
        typer.Option(
            "--deadline-ms",
            help="[Axis 2] Wait budget in milliseconds. Hint-only — auth cannot refuse for SLA in v0.",
        ),
    ] = None,
    show_wire: Annotated[
        bool,
        typer.Option(
            "--show-wire",
            help="Print the EDNS option payload bytes (hex) for manual wire correlation.",
        ),
    ] = False,
) -> None:
    """[experimental] Demonstrate EDNS(0) agent-hint signaling end-to-end.

    Constructs an AgentHint from the CLI flags, wraps the discovery resolver
    with EdnsAwareResolver, performs two discover() calls back-to-back, and
    reports the cache miss/hit behavior plus any AgentHintEcho the upstream
    returned.

    Requires DNS_AID_EXPERIMENTAL_EDNS_HINTS=1 in the environment. Without the
    flag, the command prints how to enable and exits non-zero.
    """
    import os
    import sys

    if os.environ.get("DNS_AID_EXPERIMENTAL_EDNS_HINTS", "").lower() not in (
        "1",
        "true",
        "yes",
    ):
        error_console.print(
            "[yellow]Set DNS_AID_EXPERIMENTAL_EDNS_HINTS=1 to enable this command.[/yellow]"
        )
        raise typer.Exit(1)

    print(
        "[experimental] EDNS(0) agent-hint signaling is unstable; APIs may change.", file=sys.stderr
    )

    from dns_aid import discover
    from dns_aid.experimental import AgentHint

    hint = AgentHint(
        # Axis 1
        realm=realm,
        transport=transport,
        policy_required=policy_required,
        min_trust=min_trust,
        jurisdiction=jurisdiction,
        # Axis 2
        client_intent_class=intent_class,
        max_age=max_age,
        parallelism=parallelism,
        deadline_ms=deadline_ms,
    )

    console.print(
        f"[bold]Probing {domain}[/bold] with hint signature: [cyan]{hint.signature() or '(empty)'}[/cyan]"
    )
    if show_wire:
        payload = hint.encode()
        console.print(f"  Wire payload ({len(payload)} bytes): [dim]{payload.hex()}[/dim]")

    # First call — cold
    console.print("\n[bold]Call 1[/bold] (expect upstream DNS query)")
    t0 = time.perf_counter()
    result1 = run_async(discover(domain, agent_hint=hint))
    elapsed1_ms = (time.perf_counter() - t0) * 1000
    console.print(
        f"  agents={len(result1.agents)} dnssec={result1.dnssec_validated} "
        f"elapsed={elapsed1_ms:.1f}ms"
    )

    # Second call — same hint, demonstrates that without an EdnsAwareResolver wrapping,
    # the second call still hits DNS. The cache lives in EdnsAwareResolver itself;
    # the standard discover() path doesn't share it. We demonstrate the cache
    # separately below.
    console.print("\n[bold]Call 2[/bold] via EdnsAwareResolver (in-process cache, Locus 1)")
    from dns_aid.experimental import EdnsAwareResolver

    resolver = EdnsAwareResolver()
    fqdn_hint = f"_index._agents.{domain}"
    t0 = time.perf_counter()
    cached1 = run_async(resolver.resolve(fqdn_hint, "TXT", agent_hint=hint))
    miss_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    cached2 = run_async(resolver.resolve(fqdn_hint, "TXT", agent_hint=hint))
    hit_ms = (time.perf_counter() - t0) * 1000
    console.print(f"  Cache miss: {miss_ms:.2f}ms — upstream resolve happened")
    console.print(f"  Cache hit:  {hit_ms:.2f}ms — no upstream call")
    if cached1.echo is not None:
        applied = ",".join(str(c) for c in cached1.echo.applied_selectors)
        console.print(f"  Upstream echoed applied selectors: [green]{applied}[/green]")
    else:
        console.print(
            "  No echo from upstream — stock authoritative or stripped en route. "
            "Local filtering is the only narrowing that happened."
        )
    # Reference cached2 so linters know it's intentional
    _ = cached2


# ============================================================================
# ONBOARDING COMMANDS
# ============================================================================

# Import and register init/doctor commands
from dns_aid.cli.doctor import doctor  # noqa: E402
from dns_aid.cli.init import init  # noqa: E402

app.command()(init)
app.command()(doctor)


if __name__ == "__main__":
    app()
