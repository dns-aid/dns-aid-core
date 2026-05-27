#!/usr/bin/env bash
# Baseline smoke test — verifies dns-aid publish/discover/verify works
# in the testbed before any DCV changes are made.
# Run from: tests/testbed/
set -euo pipefail

echo "=== dns-aid testbed smoke test ==="
echo

echo "--- [1] Publish Org A agent ---"
docker exec agent-a dns-aid publish \
  --name "assistant" \
  --domain "orga.test" \
  --protocol mcp \
  --endpoint "assistant.orga.test" \
  --port 443 \
  --description "Org A assistant agent"

echo
echo "--- [2] Publish Org B agent ---"
docker exec agent-b dns-aid publish \
  --name "assistant" \
  --domain "orgb.test" \
  --protocol mcp \
  --endpoint "assistant.orgb.test" \
  --port 443 \
  --description "Org B assistant agent"

echo
echo "--- [3] Discover agents at orga.test (from agent-a) ---"
docker exec agent-a dns-aid discover orga.test

echo
echo "--- [4] Discover agents at orgb.test (from agent-b) ---"
docker exec agent-b dns-aid discover orgb.test

echo
echo "--- [5] Cross-org: discover orgb.test from agent-a ---"
docker exec agent-a dns-aid discover orgb.test

echo
echo "--- [6] Verify Org A agent record ---"
docker exec agent-a dns-aid verify assistant.orga.test || true

echo
echo "--- [7] Raw DNS check: SVCB and TXT records exist ---"
echo "Org A SVCB:"; docker exec agent-a dig @172.28.0.10 assistant.orga.test SVCB +short
echo "Org A TXT:";  docker exec agent-a dig @172.28.0.10 assistant.orga.test TXT +short
echo "Org B SVCB:"; docker exec agent-b dig @172.28.0.11 assistant.orgb.test SVCB +short
echo "Org A index:"; docker exec agent-a dig @172.28.0.10 _index._agents.orga.test TXT +short

# ---------------------------------------------------------------------------
# DCV flow: agent-a (Org A) challenges agent-b (Org B) to prove orgb.test control
# ---------------------------------------------------------------------------

echo
echo "=== DCV challenge flow ==="
echo

echo "--- [8] Org A issues a DCV challenge for orgb.test (scoped to agent-b) ---"
CHALLENGE_JSON=$(docker exec agent-a dns-aid --quiet dcv issue orgb.test \
  --agent "assistant" \
  --issuer "orga.test" \
  --json)
echo "$CHALLENGE_JSON"

TOKEN=$(echo "$CHALLENGE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
BND_REQ=$(echo "$CHALLENGE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('bnd_req') or '')")
echo "Token  : $TOKEN"
echo "bnd-req: $BND_REQ"

echo
echo "--- [9] Org B (agent-b) places the challenge in its zone ---"
if [ -n "$BND_REQ" ]; then
  docker exec agent-b dns-aid dcv place orgb.test "$TOKEN" --bnd-req "$BND_REQ"
else
  docker exec agent-b dns-aid dcv place orgb.test "$TOKEN"
fi

echo
echo "--- [10] Raw DNS check: challenge TXT is present at Org B ---"
docker exec agent-a dig @172.28.0.11 _agents-challenge.orgb.test TXT +short

echo
echo "--- [11] Org A verifies the challenge (querying Org B's nameserver directly) ---"
docker exec agent-a dns-aid dcv verify orgb.test "$TOKEN" --nameserver 172.28.0.11

echo
echo "--- [12] Org B revokes (cleans up) the challenge record ---"
docker exec agent-b dns-aid dcv revoke orgb.test "$TOKEN"

echo
echo "--- [13] Confirm challenge record is gone ---"
docker exec agent-a dig @172.28.0.11 _agents-challenge.orgb.test TXT +short || echo "(empty — record removed)"

echo
echo "=== Smoke test complete ==="
