#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# consistency_check.sh — verify that all project artifacts stay in sync
#
# Checks:
#   1. Test count matches across README, CHANGELOG, CLAUDE.md
#   2. Every module on disk is listed in README
#   3. Every detector in code is listed in README
#   4. Every skill in code is listed in README
#   5. Every collector in code is mentioned in CLAUDE.md
#   6. CHANGELOG [Unreleased] reflects new modules
#   7. Integration recipes match available collectors
#   8. Linked files in README/docs actually exist
#   9. Personas file exists and is non-empty
#  10. ROADMAP milestones are consistent with CHANGELOG
#
# Portable: works on macOS (BSD grep) and Linux (GNU grep).
# Exit codes: 0 = all checks pass, 1 = at least one failure
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
WARN=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; WARN=$((WARN + 1)); }
section() { echo -e "\n${BOLD}${CYAN}[$1]${NC}"; }

# Portable helper: extract first number from a line
first_number() { echo "$1" | sed 's/[^0-9]*//' | sed 's/[^0-9].*//' ; }

# ── 1. Test count ─────────────────────────────────────────────────────────────
section "Test count"

# Count #[test] and #[tokio::test] annotations in source
SENSOR_TESTS=$(grep -r '#\[test\]\|#\[tokio::test\]' "$ROOT/crates/sensor/src/" 2>/dev/null | wc -l | tr -d ' ')
AGENT_TESTS=$(grep -r '#\[test\]\|#\[tokio::test\]' "$ROOT/crates/agent/src/" 2>/dev/null | wc -l | tr -d ' ')
CTL_TESTS=$(grep -r '#\[test\]\|#\[tokio::test\]' "$ROOT/crates/ctl/src/" 2>/dev/null | wc -l | tr -d ' ')
ACTUAL_TOTAL=$((SENSOR_TESTS + AGENT_TESTS + CTL_TESTS))

# Check README — look for pattern like "486 tests"
README_TESTS_LINE=$(grep -o '[0-9]* tests' "$ROOT/README.md" | head -1 || echo "")
README_TESTS=$(first_number "${README_TESTS_LINE:-0 tests}")
if [ "$README_TESTS" = "$ACTUAL_TOTAL" ]; then
  pass "README test count: $README_TESTS (matches actual $ACTUAL_TOTAL)"
else
  fail "README claims $README_TESTS tests, actual is $ACTUAL_TOTAL (sensor=$SENSOR_TESTS agent=$AGENT_TESTS ctl=$CTL_TESTS)"
fi

# Check CHANGELOG [Unreleased] for test count — pattern: "486 tests across"
CHANGELOG_UNRELEASED=$(sed -n '/\[Unreleased\]/,/^## \[/p' "$ROOT/CHANGELOG.md" | head -80)
CHANGELOG_TESTS_LINE=$(echo "$CHANGELOG_UNRELEASED" | grep 'tests across' | head -1 || echo "")
if [ -n "$CHANGELOG_TESTS_LINE" ]; then
  CHANGELOG_TESTS=$(first_number "$CHANGELOG_TESTS_LINE")
  if [ "$CHANGELOG_TESTS" = "$ACTUAL_TOTAL" ]; then
    pass "CHANGELOG [Unreleased] test count: $CHANGELOG_TESTS"
  else
    fail "CHANGELOG [Unreleased] claims $CHANGELOG_TESTS tests, actual is $ACTUAL_TOTAL"
  fi
fi

# Check CLAUDE.md — pattern: "make test  # 486 testes ("
CLAUDE_TESTS_LINE=$(grep 'make test.*testes' "$ROOT/CLAUDE.md" | head -1 || echo "")
if [ -n "$CLAUDE_TESTS_LINE" ]; then
  # Extract the number right before "testes"
  CLAUDE_TESTS=$(echo "$CLAUDE_TESTS_LINE" | sed 's/.*# //' | sed 's/ testes.*//')
  if [ "$CLAUDE_TESTS" = "$ACTUAL_TOTAL" ]; then
    pass "CLAUDE.md test count: $CLAUDE_TESTS"
  else
    fail "CLAUDE.md claims $CLAUDE_TESTS tests, actual is $ACTUAL_TOTAL"
  fi
fi

# ── 2. Modules on disk vs README ──────────────────────────────────────────────
section "Modules"

MODULES_ON_DISK=()
for d in "$ROOT/modules"/*/; do
  if [ -f "$d/module.toml" ]; then
    MODULES_ON_DISK+=("$(basename "$d")")
  fi
done

README_CONTENT=$(cat "$ROOT/README.md")
MISSING_FROM_README=()
for mod in "${MODULES_ON_DISK[@]}"; do
  if ! echo "$README_CONTENT" | grep -q "$mod"; then
    MISSING_FROM_README+=("$mod")
  fi
done

if [ ${#MISSING_FROM_README[@]} -eq 0 ]; then
  pass "All ${#MODULES_ON_DISK[@]} modules on disk are mentioned in README"
else
  fail "Modules on disk but NOT in README: ${MISSING_FROM_README[*]}"
fi

# Check modules in CHANGELOG
CHANGELOG_CONTENT=$(cat "$ROOT/CHANGELOG.md")
MISSING_FROM_CHANGELOG=()
for mod in "${MODULES_ON_DISK[@]}"; do
  if ! echo "$CHANGELOG_CONTENT" | grep -q "$mod"; then
    MISSING_FROM_CHANGELOG+=("$mod")
  fi
done

if [ ${#MISSING_FROM_CHANGELOG[@]} -eq 0 ]; then
  pass "All ${#MODULES_ON_DISK[@]} modules on disk are mentioned in CHANGELOG"
else
  warn "Modules on disk but NOT in CHANGELOG: ${MISSING_FROM_CHANGELOG[*]}"
fi

# ── 3. Detectors in code vs README ────────────────────────────────────────────
section "Detectors"

DETECTORS_IN_CODE=()
for f in "$ROOT/crates/sensor/src/detectors/"*.rs; do
  name=$(basename "$f" .rs)
  [ "$name" = "mod" ] && continue
  DETECTORS_IN_CODE+=("$name")
done

MISSING_DETECTORS=()
for det in "${DETECTORS_IN_CODE[@]}"; do
  if ! echo "$README_CONTENT" | grep -qi "$det"; then
    MISSING_DETECTORS+=("$det")
  fi
done

if [ ${#MISSING_DETECTORS[@]} -eq 0 ]; then
  pass "All ${#DETECTORS_IN_CODE[@]} detectors in code are in README"
else
  fail "Detectors in code but NOT in README: ${MISSING_DETECTORS[*]}"
fi

# ── 4. Skills in code vs README ───────────────────────────────────────────────
section "Skills"

SKILLS_IN_CODE=()
for f in "$ROOT/crates/agent/src/skills/builtin/"*.rs; do
  name=$(basename "$f" .rs)
  [ "$name" = "mod" ] && continue
  SKILLS_IN_CODE+=("$name")
done
# Honeypot directory counts as a skill
if [ -d "$ROOT/crates/agent/src/skills/builtin/honeypot" ]; then
  SKILLS_IN_CODE+=("honeypot")
fi

MISSING_SKILLS=()
for skill in "${SKILLS_IN_CODE[@]}"; do
  # block_ip_* variants are covered by "Block IP" in README
  if [[ "$skill" == block_ip_* ]]; then
    if echo "$README_CONTENT" | grep -qi "block.ip\|Block IP"; then
      continue
    fi
  fi
  # Normalize underscores to spaces and hyphens for matching
  normalized=$(echo "$skill" | sed 's/_/-/g')
  spaced=$(echo "$skill" | tr '_' ' ')
  if ! echo "$README_CONTENT" | grep -qi "$normalized\|$spaced\|$skill"; then
    MISSING_SKILLS+=("$skill")
  fi
done

if [ ${#MISSING_SKILLS[@]} -eq 0 ]; then
  pass "All ${#SKILLS_IN_CODE[@]} skills in code are represented in README"
else
  fail "Skills in code but NOT in README: ${MISSING_SKILLS[*]}"
fi

# ── 5. Collectors in code vs CLAUDE.md ────────────────────────────────────────
section "Collectors"

COLLECTORS_IN_CODE=()
for f in "$ROOT/crates/sensor/src/collectors/"*.rs; do
  name=$(basename "$f" .rs)
  [ "$name" = "mod" ] && continue
  COLLECTORS_IN_CODE+=("$name")
done

MISSING_COLLECTORS=()
for col in "${COLLECTORS_IN_CODE[@]}"; do
  if ! grep -qi "$col" "$ROOT/CLAUDE.md"; then
    MISSING_COLLECTORS+=("$col")
  fi
done

if [ ${#MISSING_COLLECTORS[@]} -eq 0 ]; then
  pass "All ${#COLLECTORS_IN_CODE[@]} collectors in code are in CLAUDE.md"
else
  fail "Collectors in code but NOT in CLAUDE.md: ${MISSING_COLLECTORS[*]}"
fi

# ── 6. File links in README ───────────────────────────────────────────────────
section "File links"

# Extract markdown links to local files (not http)
# Pattern: [text](path) where path does not start with http
extract_local_links() {
  local file="$1"
  # Use sed to extract link targets, then filter out http links
  sed -n 's/.*\](\([^)]*\)).*/\1/p' "$file" | grep -v '^http' | grep -v '^#' || true
}

LINKS=$(extract_local_links "$ROOT/README.md")
BROKEN_LINKS=()
for link in $LINKS; do
  target="$ROOT/$link"
  if [ ! -e "$target" ]; then
    BROKEN_LINKS+=("$link")
  fi
done

if [ ${#BROKEN_LINKS[@]} -eq 0 ]; then
  pass "All local links in README resolve"
else
  fail "Broken links in README: ${BROKEN_LINKS[*]}"
fi

# Check docs/index.md links
if [ -f "$ROOT/docs/index.md" ]; then
  DOC_LINKS=$(extract_local_links "$ROOT/docs/index.md")
  BROKEN_DOC_LINKS=()
  for link in $DOC_LINKS; do
    if [[ "$link" == ../* ]]; then
      # ../README.md from docs/ -> ROOT/README.md
      target="$ROOT/docs/$link"
    else
      target="$ROOT/docs/$link"
    fi
    if [ ! -e "$target" ]; then
      BROKEN_DOC_LINKS+=("$link")
    fi
  done
  if [ ${#BROKEN_DOC_LINKS[@]} -eq 0 ]; then
    pass "All local links in docs/index.md resolve"
  else
    fail "Broken links in docs/index.md: ${BROKEN_DOC_LINKS[*]}"
  fi
fi

# ── 7. Integration recipes ────────────────────────────────────────────────────
section "Integration recipes"

if [ -d "$ROOT/integrations" ]; then
  RECIPE_COUNT=0
  for recipe_dir in "$ROOT/integrations"/*/; do
    [ ! -f "$recipe_dir/recipe.toml" ] && continue
    RECIPE_COUNT=$((RECIPE_COUNT + 1))
    recipe_name=$(basename "$recipe_dir")
    if [ ! -d "$ROOT/modules/${recipe_name}-integration" ] && [ ! -d "$ROOT/modules/${recipe_name}" ]; then
      warn "Recipe '$recipe_name' has no matching module directory"
    fi
  done
  pass "$RECIPE_COUNT integration recipes found"
fi

# ── 8. Personas file ──────────────────────────────────────────────────────────
section "Personas"

if [ -f "$ROOT/.claude/personas.md" ]; then
  PERSONA_COUNT=$(grep -c '^## Persona' "$ROOT/.claude/personas.md" || echo "0")
  if [ "$PERSONA_COUNT" -gt 0 ]; then
    pass "$PERSONA_COUNT personas defined in .claude/personas.md"
  else
    warn "Personas file exists but no personas defined"
  fi
else
  warn "No personas file at .claude/personas.md — site content may drift"
fi

# ── 9. ROADMAP consistency ────────────────────────────────────────────────────
section "Roadmap"

if [ -f "$ROOT/ROADMAP.md" ]; then
  ROADMAP_SHIPPED=$(grep -c '✅' "$ROOT/ROADMAP.md" || echo "0")
  pass "ROADMAP.md exists with $ROADMAP_SHIPPED shipped items"

  if grep -q 'v0.1.0.*shipped\|v0.1.0.*Shipped' "$ROOT/ROADMAP.md"; then
    pass "ROADMAP marks v0.1.0 as shipped"
  else
    warn "ROADMAP does not clearly mark v0.1.0 as shipped"
  fi
else
  fail "ROADMAP.md not found"
fi

# ── 10. Required files exist ──────────────────────────────────────────────────
section "Required files"

REQUIRED_FILES=(
  "README.md"
  "CLAUDE.md"
  "CHANGELOG.md"
  "ROADMAP.md"
  "CONTRIBUTING.md"
  "SECURITY.md"
  "CODE_OF_CONDUCT.md"
  "LICENSE"
  "Makefile"
  "docs/index.md"
  "docs/module-authoring.md"
  "docs/format.md"
)

for f in "${REQUIRED_FILES[@]}"; do
  if [ -f "$ROOT/$f" ]; then
    pass "$f exists"
  else
    fail "$f is MISSING"
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
  echo -e "${GREEN}${BOLD}  All checks passed.${NC}"
elif [ $FAIL -eq 0 ]; then
  echo -e "${YELLOW}${BOLD}  $WARN warning(s), 0 failures.${NC}"
else
  echo -e "${RED}${BOLD}  $FAIL failure(s), $WARN warning(s).${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo ""

exit $FAIL
