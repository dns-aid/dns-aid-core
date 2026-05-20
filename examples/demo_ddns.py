#!/usr/bin/env python3
"""
Demo: DNS-AID with DDNS (RFC 2136)

This script demonstrates publishing and discovering an agent
using Dynamic DNS updates. Works with BIND9, Windows DNS,
PowerDNS, Knot DNS, and any RFC 2136 compliant server.

Usage:
    # Option 1: Use .env file (recommended)
    cp .env.example .env
    # Uncomment the DDNS and Docker Playground sections in .env

    # Option 2: Set environment variables manually
    export DDNS_SERVER="ns1.example.com"
    export DDNS_KEY_NAME="dns-aid-key"
    export DDNS_KEY_SECRET="YourBase64SecretHere=="
    export DNS_AID_TEST_ZONE="example.com"

    # Run the demo
    python examples/demo_ddns.py

    # Or specify zone directly
    python examples/demo_ddns.py example.com
"""

import asyncio
import os
import sys

from dotenv import load_dotenv

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

load_dotenv()


async def main(zone: str):
    """Run the DNS-AID DDNS demo."""
    from dns_aid import discover, publish
    from dns_aid.backends.ddns import DDNSBackend

    print("=" * 60)
    print("DNS-AID Demo with DDNS (RFC 2136)")
    print("=" * 60)
    print(f"\nZone: {zone}")
    print(f"Server: {os.environ.get('DDNS_SERVER', 'not set')}")
    print(f"Port: {os.environ.get('DDNS_PORT', '53')}")
    print(f"Key: {os.environ.get('DDNS_KEY_NAME', 'not set')}")

    # Create backend
    try:
        backend = DDNSBackend()
    except ValueError as e:
        print(f"\n❌ Configuration error: {e}")
        print("\nRequired environment variables:")
        print("  DDNS_SERVER      - DNS server hostname or IP")
        print("  DDNS_KEY_NAME    - TSIG key name")
        print("  DDNS_KEY_SECRET  - TSIG key secret (base64)")
        print("\nOptional:")
        print("  DDNS_KEY_ALGORITHM - Algorithm (default: hmac-sha256)")
        print("  DDNS_PORT          - DNS port (default: 53)")
        return

    # Check zone exists
    print("\n[1] Checking zone exists...")
    if not await backend.zone_exists(zone):
        print(f"❌ Zone '{zone}' not found or not accessible")
        print("   Check that the DNS server is reachable and the zone is configured")
        return

    print(f"✓ Zone '{zone}' found")

    # Publish a test agent
    print("\n[2] Publishing test agent to DNS via DDNS...")
    agent_name = "demo-ddns-agent"

    result = await publish(
        name=agent_name,
        domain=zone,
        protocol="mcp",
        endpoint=f"mcp.{zone}",
        port=443,
        capabilities=["demo", "ddns", "on-premise"],
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
    server = os.environ.get("DDNS_SERVER")
    port = os.environ.get("DDNS_PORT", "53")
    port_flag = f" -p {port}" if port != "53" else ""
    print("\n[3] Verify with dig:")
    print(f"   dig @{server}{port_flag} {result.agent.fqdn} SVCB")
    print(f"   dig @{server}{port_flag} {result.agent.fqdn} TXT")

    # Try to discover
    print("\n[4] Discovering agent via DNS...")
    try:
        discovery = await discover(domain=zone, protocol="mcp")
        if discovery.count > 0:
            print(f"✓ Found {discovery.count} agent(s):")
            for agent in discovery.agents:
                print(f"   - {agent.name} at {agent.endpoint_url}")
        else:
            print("   No agents found (may need DNS propagation)")
    except Exception as e:
        print(f"   Discovery skipped: {e}")

    # Ask about cleanup
    print("\n[5] Cleanup")
    cleanup = input("   Delete the test records? [y/N]: ").strip().lower()

    if cleanup == "y":
        record_name = f"_{agent_name}._mcp._agents"
        await backend.delete_record(zone, record_name, "SVCB")
        await backend.delete_record(zone, record_name, "TXT")
        print("   ✓ Records deleted")
    else:
        print("   Records kept. Delete manually with:")
        print(f"   dns-aid delete -n {agent_name} -d {zone} -p mcp --backend ddns")

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
        print("Usage: python demo_ddns.py <zone>")
        print("   or: DNS_AID_TEST_ZONE=example.com python demo_ddns.py")
        print("\nRequired environment variables:")
        print("  DDNS_SERVER      - DNS server hostname or IP")
        print("  DDNS_KEY_NAME    - TSIG key name")
        print("  DDNS_KEY_SECRET  - TSIG key secret (base64)")
        print("  DNS_AID_TEST_ZONE - Zone to use for testing")
        print("\nExample with Docker BIND9:")
        print("  cd tests/integration/bind && docker-compose up -d")
        print("  export DDNS_SERVER=localhost")
        print("  export DDNS_KEY_NAME=dns-aid-key")
        print("  export DDNS_KEY_SECRET=<from tests/integration/bind/keys/dns-aid-key.conf>")
        print("  export DNS_AID_TEST_ZONE=test.dns-aid.local")
        print("  python examples/demo_ddns.py")
        sys.exit(1)

    asyncio.run(main(zone))
