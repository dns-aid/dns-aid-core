#!/usr/bin/env python3
"""
Integration Test: DNS-AID Python Library

Validates the Python library integration pattern from docs/integrations.md.
Discovers the booking agent at example.com via DNS,
then calls its MCP endpoint directly.

Usage:
    python examples/integration_python_library.py
"""

import asyncio
import json
import sys

import httpx

from dns_aid.core.discoverer import discover
from dns_aid.core.validator import verify


async def main() -> int:
    print("=" * 60)
    print("DNS-AID Integration Test: Python Library")
    print("=" * 60)
    errors = 0

    # ── Step 1: Discover booking agent via DNS ──────────────────
    print("\n[1/4] Discovering booking agent via DNS...")
    result = await discover(
        "example.com", protocol="mcp", name="booking"
    )

    if result.count == 0:
        print("  FAIL: No agents found")
        return 1

    agent = result.agents[0]
    print(f"  OK: Found '{agent.name}' at {agent.endpoint_url}")
    print(f"      Capabilities: {agent.capabilities}")
    print(f"      FQDN: {agent.fqdn}")

    # ── Step 2: Verify DNSSEC ───────────────────────────────────
    print("\n[2/4] Verifying DNSSEC...")
    verification = await verify(agent.fqdn)
    print(f"  Record exists: {verification.record_exists}")
    print(f"  SVCB valid:    {verification.svcb_valid}")
    print(f"  DNSSEC valid:  {verification.dnssec_valid}")
    print(f"  Endpoint live: {verification.endpoint_reachable}")
    print(f"  Security:      {verification.security_score}/100 ({verification.security_rating})")

    if not verification.record_exists:
        print("  FAIL: DNS record does not exist")
        errors += 1

    # ── Step 3: Call booking agent MCP endpoint ─────────────────
    print("\n[3/4] Calling booking agent MCP endpoint...")
    endpoint = agent.endpoint_url.rstrip("/")

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # List tools
        resp = await client.post(
            f"{endpoint}/mcp",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        tools_result = resp.json()
        tools = tools_result.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        print(f"  OK: MCP tools available: {tool_names}")

        expected_tools = {"search_flights", "get_flight_details", "check_availability", "create_reservation"}
        if not expected_tools.issubset(set(tool_names)):
            print(f"  FAIL: Missing tools: {expected_tools - set(tool_names)}")
            errors += 1

    # ── Step 4: Search flights via MCP tool call ────────────────
    print("\n[4/4] Searching flights SFO -> JFK via MCP...")
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.post(
            f"{endpoint}/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "search_flights",
                    "arguments": {
                        "origin": "SFO",
                        "destination": "JFK",
                        "date": "2026-03-15",
                    },
                },
                "id": 2,
            },
        )
        call_result = resp.json()
        content = call_result.get("result", {}).get("content", [])
        if content:
            flights = json.loads(content[0]["text"])
            print(f"  OK: Found {flights['found']} flights on route {flights['route']}")
            for f in flights.get("flights", []):
                print(f"      {f['flight_number']} {f['departure']}-{f['arrival']} ${f['price']}")
        else:
            print("  FAIL: No flight results returned")
            errors += 1

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED — Python library integration works")
    else:
        print(f"FAILED — {errors} check(s) failed")
    print("=" * 60)
    return errors


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
