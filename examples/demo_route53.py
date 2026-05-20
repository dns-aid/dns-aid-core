#!/usr/bin/env python3
"""
Demo: DNS-AID with AWS Route 53

This script demonstrates publishing and discovering an agent
using real DNS records in Route 53.

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Uncomment DNS_AID_TEST_ZONE and the Route 53 section

    # Option 2: Set environment variables manually
    export DNS_AID_TEST_ZONE="example.com"

    # Run the demo
    python examples/demo_route53.py

    # Or specify zone directly
    python examples/demo_route53.py example.com
"""

import asyncio
import os
import sys

from dotenv import load_dotenv

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

load_dotenv()


async def main(zone: str):
    """Run the DNS-AID demo."""
    from dns_aid import publish
    from dns_aid.backends.route53 import Route53Backend

    print("=" * 60)
    print("DNS-AID Demo with AWS Route 53")
    print("=" * 60)
    print(f"\nZone: {zone}")

    # Create backend
    backend = Route53Backend()

    # Check zone exists
    print("\n[1] Checking zone exists...")
    if not await backend.zone_exists(zone):
        print(f"❌ Zone '{zone}' not found in your Route 53 account")
        return

    print(f"✓ Zone '{zone}' found")

    # List existing DNS-AID records
    print("\n[2] Checking for existing DNS-AID records...")
    existing = []
    async for record in backend.list_records(zone, name_pattern="_agents"):
        existing.append(record)
        print(f"   Found: {record['fqdn']} ({record['type']})")

    if not existing:
        print("   No existing DNS-AID records found")

    # Publish a test agent
    print("\n[3] Publishing test agent to DNS...")
    agent_name = "demo-agent"

    result = await publish(
        name=agent_name,
        domain=zone,
        protocol="mcp",
        endpoint=f"mcp.{zone}",
        port=443,
        capabilities=["demo", "test", "dns-aid"],
        version="1.0.0",
        ttl=300,  # Short TTL for demo
        backend=backend,
    )

    if result.success:
        print("✓ Agent published successfully!")
        print(f"\n   FQDN: {result.agent.fqdn}")
        print(f"   Endpoint: {result.agent.endpoint_url}")
        print("\n   Records created:")
        for record in result.records_created:
            print(f"   - {record}")
    else:
        print(f"❌ Failed to publish: {result.message}")
        return

    # Verify with dig
    print("\n[4] You can verify with dig:")
    print(f"   dig {result.agent.fqdn} SVCB")
    print(f"   dig {result.agent.fqdn} TXT")

    # Ask about cleanup
    print("\n[5] Cleanup")
    cleanup = input("   Delete the test records? [y/N]: ").strip().lower()

    if cleanup == "y":
        record_name = f"_{agent_name}._mcp._agents"
        await backend.delete_record(zone, record_name, "SVCB")
        await backend.delete_record(zone, record_name, "TXT")
        print("   ✓ Records deleted")
    else:
        print("   Records kept. Delete manually or run script again.")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    # Get zone from argument or environment
    if len(sys.argv) > 1:
        zone = sys.argv[1]
    else:
        zone = os.environ.get("DNS_AID_TEST_ZONE", "")

    if not zone:
        print("Usage: python demo_route53.py <zone>")
        print("   or: DNS_AID_TEST_ZONE=example.com python demo_route53.py")
        print("\nYour available zones:")

        async def list_zones():
            from dns_aid.backends.route53 import Route53Backend

            backend = Route53Backend()
            zones = await backend.list_zones()
            for z in zones:
                print(f"   - {z['name']} (ID: {z['id']}, {z['record_count']} records)")

        asyncio.run(list_zones())
        sys.exit(1)

    asyncio.run(main(zone))
