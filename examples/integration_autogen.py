#!/usr/bin/env python3
"""
Integration Test: Microsoft AutoGen + DNS-AID MCP Server

Validates the AutoGen integration pattern from docs/integrations.md.
Connects to DNS-AID MCP server via autogen-ext[mcp], lists tools,
and calls discover_agents_via_dns to find the booking agent.

No LLM API key required — this tests the MCP transport only.

Usage:
    python examples/integration_autogen.py
"""

import asyncio
import sys

from autogen_core import CancellationToken
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools


async def main() -> int:
    print("=" * 60)
    print("DNS-AID Integration Test: Microsoft AutoGen")
    print("=" * 60)
    errors = 0

    # ── Step 1: Connect to DNS-AID MCP server ──────────────────
    print("\n[1/3] Connecting to DNS-AID MCP server via StdioServerParams...")

    server = StdioServerParams(
        command=sys.executable, args=["-m", "dns_aid.mcp.server"]
    )
    tools = await mcp_server_tools(server)

    print(f"  OK: Connected and loaded {len(tools)} tools")

    # ── Step 2: List available tools ────────────────────────────
    print("\n[2/3] Listing MCP tools...")
    tool_names = [t.name for t in tools]
    for t in tools:
        desc = t.description or ""
        print(f"      - {t.name}: {desc[:60]}...")

    expected = {"discover_agents_via_dns", "publish_agent_to_dns", "verify_agent_dns"}
    missing = expected - set(tool_names)
    if missing:
        print(f"  FAIL: Missing expected tools: {missing}")
        errors += 1
    else:
        print(f"  OK: All expected tools present ({', '.join(sorted(expected))})")

    # ── Step 3: Call discover_agents_via_dns ────────────────────
    print("\n[3/3] Calling discover_agents_via_dns for booking agent...")

    discover_tool = next(t for t in tools if t.name == "discover_agents_via_dns")
    result = await discover_tool.run_json(
        {
            "domain": "example.com",
            "protocol": "mcp",
            "name": "booking",
        },
        CancellationToken(),
    )

    result_str = str(result)
    print(f"  OK: Tool returned result ({len(result_str)} chars)")

    if "booking" in result_str.lower():
        print("  OK: Result contains 'booking' agent data")
    else:
        print("  FAIL: Result does not mention booking agent")
        print(f"  Got: {result_str[:200]}")
        errors += 1

    if "example.com" in result_str:
        print("  OK: Result contains domain reference")
    else:
        print("  WARN: Domain not found in result")

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if errors == 0:
        print("ALL CHECKS PASSED — AutoGen MCP integration works")
        print("\nThe docs/integrations.md AutoGen example is validated.")
        print("To use with a real LLM, set OPENAI_API_KEY and create an AssistantAgent.")
    else:
        print(f"FAILED — {errors} check(s) failed")
    print("=" * 60)
    return errors


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
