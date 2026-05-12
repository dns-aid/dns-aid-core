#!/usr/bin/env bash
# Manual wire-level verification for the experimental EDNS(0) agent-hint feature.
#
# What this does:
#   1. Brings the testbed up (orga.test BIND9 authoritative + agent-a container)
#   2. Starts a tcpdump on the agent-a container, listening for DNS traffic to bind-orga
#   3. Runs `dns-aid edns-probe orga.test` with the experimental flag on
#   4. Captures the wire and greps for the agent-hint option code (0xff96 = 65430)
#
# What you should see:
#   - tcpdump shows the EDNS(0) OPT pseudo-RR carrying option-code 0xff96 in the
#     outgoing query packet
#   - The probe command prints cache miss + hit timings
#   - No echo is expected: BIND9 stock treats unknown options as inert per RFC 6891
#
# Run from: tests/testbed/
# Not in CI. tcpdump needs CAP_NET_RAW inside the container — works in compose
# because docker-compose runs containers as root by default.
set -euo pipefail

echo "=== EDNS(0) agent-hint smoke test ==="
echo

echo "--- [1] Ensure testbed is up ---"
docker compose ps --status running | grep -q bind-orga || docker compose up -d bind-orga agent-a

echo
echo "--- [2] Start tcpdump on agent-a (background) ---"
# 0xff96 in hex == 65430 decimal == AGENT_HINT_OPTION_CODE
# Capturing for 5 seconds is plenty to see two probe calls.
docker exec -d agent-a bash -c \
  'apt-get install -y -q tcpdump 2>/dev/null || true; tcpdump -i any -nn -X -c 20 host 172.28.0.10 and port 53 > /tmp/edns_capture.txt 2>&1 &'
sleep 1

echo
echo "--- [3] Run edns-probe with experimental flag on ---"
docker exec -e DNS_AID_EXPERIMENTAL_EDNS_HINTS=1 agent-a \
  dns-aid edns-probe orga.test \
  --capabilities=chat,code \
  --intent=summarize \
  --transport=mcp \
  --auth-type=bearer \
  --show-wire

echo
echo "--- [4] Capture results ---"
sleep 2
docker exec agent-a cat /tmp/edns_capture.txt 2>/dev/null | head -80 || \
  echo "  (tcpdump may not have been installed; install it inside the agent-a container manually)"

echo
echo "--- [5] Look for the agent-hint option code (0xff96) in the capture ---"
docker exec agent-a grep -i "ff96\|ff 96" /tmp/edns_capture.txt 2>/dev/null && \
  echo "  ✓ agent-hint option code 0xff96 (=65430) appeared on the wire" || \
  echo "  ✗ option code not found in capture — feature flag set? tcpdump captured the right packets?"

echo
echo "=== smoke_edns.sh complete ==="
echo
echo "Reminder: BIND9 stock will not emit an AgentHintEcho — its absence is correct"
echo "and meaningful. A hint-aware authoritative would echo applied selectors back."
