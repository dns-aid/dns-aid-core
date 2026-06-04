#!/usr/bin/env bash
# Pre-push local verification — runs every CI check we can run locally
# so we stop force-pushing things that fail server-side.
#
# Exit code 0 = all checks passed. Non-zero = at least one failed.
# Usage: ./scripts/preflight.sh [--against <base-ref>]

set -uo pipefail

BASE_REF="${BASE_REF:-origin/main}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --against) BASE_REF="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

OK="\033[32m✓\033[0m"
BAD="\033[31m✗\033[0m"
DIM="\033[2m"
RST="\033[0m"

failed=()

step() { printf "\n${DIM}══ %s ══${RST}\n" "$1"; }
pass() { printf "${OK} %s\n" "$1"; }
fail() { printf "${BAD} %s\n" "$1"; failed+=("$1"); }

# ───────────────────────────────────────────────────────────────────
step "Format check (ruff format)"
if uv run ruff format --check src/ tests/ >/dev/null 2>&1; then
  pass "ruff format clean"
else
  fail "ruff format would reformat files (run 'uv run ruff format src/ tests/')"
fi

# ───────────────────────────────────────────────────────────────────
step "Lint (ruff check)"
if uv run ruff check src/ tests/ >/dev/null 2>&1; then
  pass "ruff check clean"
else
  fail "ruff check has issues (run 'uv run ruff check src/ tests/' to see them)"
fi

# ───────────────────────────────────────────────────────────────────
step "Type check (mypy)"
if uv run mypy src/dns_aid >/dev/null 2>&1; then
  pass "mypy clean"
else
  fail "mypy has errors (run 'uv run mypy src/dns_aid')"
fi

# ───────────────────────────────────────────────────────────────────
step "Unit tests"
if uv run pytest tests/unit/ -q --no-header --tb=no 2>&1 | tail -1 | grep -qE "passed"; then
  pass "unit tests pass"
else
  fail "unit tests failing (run 'uv run pytest tests/unit/ -v')"
fi

# ───────────────────────────────────────────────────────────────────
step "Mock integration tests"
if uv run pytest tests/integration/ -m "not live" -q --no-header --tb=no 2>&1 | tail -1 | grep -qE "passed"; then
  pass "integration tests pass (not live)"
else
  fail "integration tests failing (run 'uv run pytest tests/integration/ -m \"not live\" -v')"
fi

# ───────────────────────────────────────────────────────────────────
step "SAST (Bandit)"
if uv run --with "bandit[toml]" bandit -r src/dns_aid -c pyproject.toml -q >/dev/null 2>&1; then
  pass "bandit clean"
else
  fail "bandit has findings (run 'uv run --with bandit[toml] bandit -r src/dns_aid -c pyproject.toml')"
fi

# ───────────────────────────────────────────────────────────────────
step "Dependency Audit (pip-audit)"
# Mirrors security.yml — same --ignore-vuln list. Update both when CVEs change.
audit_args=(
  --ignore-vuln CVE-2026-4539
  --ignore-vuln CVE-2025-8869
  --ignore-vuln CVE-2026-1703
  --ignore-vuln CVE-2026-34073
  --ignore-vuln CVE-2026-25645
  --ignore-vuln CVE-2026-3219
  --ignore-vuln CVE-2025-45768
)
if uv run --with pip-audit pip-audit "${audit_args[@]}" >/dev/null 2>&1; then
  pass "pip-audit clean"
else
  fail "pip-audit found vulnerabilities (run 'uv run --with pip-audit pip-audit ${audit_args[*]}')"
fi

# ───────────────────────────────────────────────────────────────────
step "DCO trailer placement"
# The KineticCafe DCO action follows git's trailer-block rule: the
# Signed-off-by line MUST be in the LAST paragraph of the commit
# message. Body text after it invalidates the trailer.
bad_dco=()
for sha in $(git log --format=%h "$BASE_REF..HEAD" 2>/dev/null); do
  last_so=$(git cat-file -p "$sha" | awk '/^Signed-off-by:/{n=NR} END{print n+0}')
  last_line=$(git cat-file -p "$sha" | awk 'NF{n=NR} END{print n+0}')
  if [[ "$last_so" -eq 0 ]]; then
    bad_dco+=("$sha: missing Signed-off-by")
  elif [[ "$last_so" -ne "$last_line" ]]; then
    bad_dco+=("$sha: Signed-off-by at line $last_so but body extends to line $last_line")
  fi
done
if [[ ${#bad_dco[@]} -eq 0 ]]; then
  pass "every commit's Signed-off-by is the last line"
else
  fail "DCO trailer placement issues:"
  for entry in "${bad_dco[@]}"; do echo "    $entry"; done
  echo "    (use 'git rebase -i $BASE_REF' + 'reword' to fix)"
fi

# ───────────────────────────────────────────────────────────────────
step "Workflow files unchanged (fork-PR approval gate)"
# When a fork PR modifies .github/workflows/, GitHub requires
# maintainer approval per push — CI doesn't auto-run. Catch this so
# we don't push an unrelated workflow drift.
wf_diff=$(git diff "$BASE_REF...HEAD" -- .github/workflows/ 2>/dev/null)
if [[ -z "$wf_diff" ]]; then
  pass "no .github/workflows/ changes (CI will auto-fire)"
else
  fail ".github/workflows/ changed vs $BASE_REF — fork PRs need maintainer approval per push"
fi

# ───────────────────────────────────────────────────────────────────
step "Summary"
if [[ ${#failed[@]} -eq 0 ]]; then
  printf "${OK} all preflight checks passed — safe to push\n"
  exit 0
else
  printf "${BAD} %d check(s) failed:\n" "${#failed[@]}"
  for entry in "${failed[@]}"; do printf "    %s\n" "$entry"; done
  exit 1
fi
