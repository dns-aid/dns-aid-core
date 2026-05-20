#!/usr/bin/env python3
"""
DNS-AID Full Demo - End-to-End Agent Discovery

This script demonstrates the complete DNS-AID workflow:
1. Publish an agent to DNS (Route 53)
2. Verify the DNS records
3. Discover the agent via DNS
4. Show how another agent would connect

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Uncomment DNS_AID_TEST_ZONE and your backend section

    # Option 2: Set environment variables manually
    export DNS_AID_TEST_ZONE="example.com"

    # Run the demo
    python examples/demo_full.py

Requirements:
    - AWS credentials configured
    - A Route 53 hosted zone you control
"""

import asyncio
import os
import sys
import time

from dotenv import load_dotenv

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

load_dotenv()


def print_section(title: str):
    """Print a section header."""
    width = 70
    print()
    print("=" * width)
    print(f" {title}")
    print("=" * width)


def print_step(step: int, description: str):
    """Print a step header."""
    print(f"\n[{step}] {description}")
    print("-" * 50)


async def main(zone: str):
    """Run the full DNS-AID demo."""
    from dns_aid import discover, publish
    from dns_aid.backends.route53 import Route53Backend
    from dns_aid.core.validator import verify

    print_section("DNS-AID FULL DEMONSTRATION")
    print(f"""
This demo will:
  1. Publish an AI agent to DNS using DNS-AID protocol
  2. Verify the DNS records are properly configured
  3. Discover the agent using DNS queries
  4. Show how another agent would connect

Target zone: {zone}
""")

    # Create backend
    backend = Route53Backend()

    # Agent configuration
    agent_name = "demo-network-agent"
    agent_protocol = "mcp"
    agent_capabilities = ["ipam", "dns", "vpn", "aws-networking"]
    agent_endpoint = f"mcp.{zone}"

    # =========================================================================
    # STEP 1: PUBLISH AGENT TO DNS
    # =========================================================================
    print_step(1, "PUBLISH AGENT TO DNS")

    print(f"""
Publishing agent with DNS-AID:
  Name:         {agent_name}
  Protocol:     {agent_protocol}
  Domain:       {zone}
  Endpoint:     {agent_endpoint}
  Capabilities: {", ".join(agent_capabilities)}
""")

    result = await publish(
        name=agent_name,
        domain=zone,
        protocol=agent_protocol,
        endpoint=agent_endpoint,
        port=443,
        capabilities=agent_capabilities,
        version="1.0.0",
        ttl=300,  # Short TTL for demo
        backend=backend,
    )

    if result.success:
        print("✓ Agent published successfully!")
        print(f"\n  FQDN: {result.agent.fqdn}")
        print(f"  Endpoint URL: {result.agent.endpoint_url}")
        print("\n  DNS records created:")
        for record in result.records_created:
            print(f"    • {record}")
    else:
        print(f"✗ Failed to publish: {result.message}")
        return

    # =========================================================================
    # STEP 2: VERIFY DNS RECORDS
    # =========================================================================
    print_step(2, "VERIFY DNS RECORDS")

    print(f"""
Verifying DNS-AID records for:
  {result.agent.fqdn}

Checks:
  • DNS record existence
  • SVCB record validity
  • DNSSEC validation
  • DANE/TLSA configuration
  • Endpoint reachability
""")

    # Wait a moment for DNS propagation
    print("Waiting 3 seconds for DNS propagation...")
    time.sleep(3)

    verify_result = await verify(result.agent.fqdn)

    def status(ok: bool | None) -> str:
        if ok is None:
            return "○ (not checked)"
        return "✓" if ok else "✗"

    print(f"\n  {status(verify_result.record_exists)} DNS record exists")
    print(f"  {status(verify_result.svcb_valid)} SVCB record valid")
    print(f"  {status(verify_result.dnssec_valid)} DNSSEC validated")
    print(f"  {status(verify_result.dane_valid)} DANE/TLSA configured")
    print(f"  {status(verify_result.endpoint_reachable)} Endpoint reachable")

    if verify_result.endpoint_latency_ms:
        print(f"    (Latency: {verify_result.endpoint_latency_ms:.0f}ms)")

    print(
        f"\n  Security Score: {verify_result.security_score}/100 ({verify_result.security_rating})"
    )

    # =========================================================================
    # STEP 3: DISCOVER AGENT VIA DNS
    # =========================================================================
    print_step(3, "DISCOVER AGENT VIA DNS")

    print(f"""
Discovering agents at {zone}...

This is what another AI agent would do to find available services.
The discovery uses standard DNS queries - no special infrastructure needed.
""")

    discovery_result = await discover(domain=zone, protocol="mcp")

    if discovery_result.count > 0:
        print(f"✓ Found {discovery_result.count} agent(s):\n")

        for agent in discovery_result.agents:
            print(f"  Agent: {agent.name}")
            print(f"    Protocol: {agent.protocol.value}")
            print(f"    Endpoint: {agent.endpoint_url}")
            print(f"    Capabilities: {', '.join(agent.capabilities)}")
            print(f"    FQDN: {agent.fqdn}")
            print()
    else:
        print("No agents found (DNS propagation may still be in progress)")

    print(f"  Query: {discovery_result.query}")
    print(f"  Time: {discovery_result.query_time_ms:.2f}ms")

    # =========================================================================
    # STEP 4: HOW ANOTHER AGENT WOULD CONNECT
    # =========================================================================
    print_step(4, "AGENT-TO-AGENT CONNECTION FLOW")

    print(f"""
Now that we've discovered the agent, here's how another AI agent would connect:

┌─────────────────────────────────────────────────────────────────────┐
│                    AGENT DISCOVERY & CONNECTION                      │
└─────────────────────────────────────────────────────────────────────┘

  Agent A (LLM)                    DNS                       Agent B (MCP)
      │                             │                             │
      │  "Find network agent at     │                             │
      │   {zone}"             │                             │
      │                             │                             │
      ├────────────────────────────►│                             │
      │  Query: {result.agent.fqdn}                               │
      │         (SVCB record)       │                             │
      │                             │                             │
      │◄────────────────────────────┤                             │
      │  Response: 1 {agent_endpoint}. alpn="mcp" port=443        │
      │  (DNSSEC validated)         │                             │
      │                             │                             │
      ├──────────────────────────────────────────────────────────►│
      │  Connect to https://{agent_endpoint}:443                  │
      │  (Standard MCP protocol)                                  │
      │                             │                             │
      │◄──────────────────────────────────────────────────────────┤
      │  MCP tools available: list_ip_spaces, create_dns_record...│
      │                             │                             │


Code example for Agent A to discover and connect:

    import dns_aid

    # Step 1: Discover the agent
    result = await dns_aid.discover("{zone}", protocol="mcp")
    agent = result.agents[0]  # Get the network agent

    print(f"Found: {{agent.name}} at {{agent.endpoint_url}}")
    # Output: Found: {agent_name} at https://{agent_endpoint}:443

    # Step 2: Connect using standard MCP client
    from mcp import ClientSession
    async with ClientSession(agent.endpoint_url) as session:
        tools = await session.list_tools()
        # Now Agent A can use Agent B's capabilities!
""")

    # =========================================================================
    # STEP 5: CLEANUP
    # =========================================================================
    print_step(5, "CLEANUP")

    print(f"""
DNS records created during this demo:
  • {result.agent.fqdn} (SVCB)
  • {result.agent.fqdn} (TXT)
""")

    cleanup = input("Delete these test records? [y/N]: ").strip().lower()

    if cleanup == "y":
        record_name = f"_{agent_name}._{agent_protocol}._agents"
        await backend.delete_record(zone, record_name, "SVCB")
        await backend.delete_record(zone, record_name, "TXT")
        print("✓ Records deleted")
    else:
        print("Records kept. You can delete them with:")
        print(f"  dns-aid delete -n {agent_name} -d {zone} -p {agent_protocol}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print_section("DEMO COMPLETE")

    print("""
What we demonstrated:

  1. PUBLISH - Created DNS-AID records (SVCB + TXT) for an AI agent
  2. VERIFY  - Checked DNS records, DNSSEC, and endpoint health
  3. DISCOVER - Found the agent using standard DNS queries
  4. CONNECT - Showed how another agent would use the discovered endpoint

Key Takeaways:

  • DNS-AID uses existing DNS infrastructure - no new servers needed
  • Discovery is decentralized - each org controls their own agents
  • Security is built-in via DNSSEC and optional DANE
  • Works with both MCP (Anthropic) and A2A (Google) protocols

Next Steps:

  • Try the CLI: dns-aid --help
  • Use the MCP server: dns-aid-mcp
  • Read the IETF draft: draft-mozleywilliams-dnsop-dnsaid-01

""")

    print("Thank you for trying DNS-AID!")


if __name__ == "__main__":
    # Get zone from argument or environment
    if len(sys.argv) > 1:
        zone = sys.argv[1]
    else:
        zone = os.environ.get("DNS_AID_TEST_ZONE", "")

    if not zone:
        print("Usage: python demo_full.py <zone>")
        print("   or: DNS_AID_TEST_ZONE=example.com python demo_full.py")
        print("\nYour available zones:")

        async def list_zones():
            from dns_aid.backends.route53 import Route53Backend

            backend = Route53Backend()
            zones = await backend.list_zones()
            for z in zones:
                print(f"   - {z['name']} (ID: {z['id']})")

        asyncio.run(list_zones())
        sys.exit(1)

    asyncio.run(main(zone))
