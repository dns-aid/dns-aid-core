# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""How long a JWS record signature asserts its binding.

A leaf module on purpose. The default used to live in ``jwks.py`` and the
bounds in ``publisher.py``, so ``publisher`` imported ``jwks`` at module scope
just to re-export one integer — which pulled the whole ``cryptography`` backend
into every import of the publish path, including CLI startup and MCP server
boot, whether or not anything was going to be signed. Splitting the numbers
across two modules also meant a reader had to find both to know the range.

Nothing here imports anything, so both sides can take these without cost.
"""

from __future__ import annotations

# This is deliberately NOT the DNS record TTL. The TTL states how long a
# resolver may cache the answer and is tuned for propagation speed; the JWS
# `exp` states how long the assertion holds and is tuned for re-signing cadence.
# Deriving one from the other made every signature expire at the cache-refresh
# interval -- a 3600s TTL produced a signature that was dead an hour after
# publication while the record itself stayed in DNS for months, and the more
# aggressively an operator tuned the TTL the faster their signatures broke.
#
# 90 days matches the ACME renewal rhythm deployments already automate.
DEFAULT_SIG_VALIDITY_SECONDS = 7_776_000  # 90 days
MIN_SIG_VALIDITY_SECONDS = 3_600  # 1 hour
MAX_SIG_VALIDITY_SECONDS = 34_128_000  # ~13 months, the maximum certificate lifetime
