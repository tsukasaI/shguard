#!/usr/bin/env bash
# Fixture smoke test for the shguard release binary (issue #14, C2: E2E
# verification). Pipes recorded PreToolUse stdin fixtures through the real
# binary and diffs the resulting `permissionDecision` against expectations.
#
# The fixtures below mirror tests/hook_io.rs's Definition-of-Done cases, so
# this script and the integration test suite exercise the same contract
# through two different paths (compiled binary vs. `assert_cmd`).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$REPO_ROOT/target/release/shguard"

if [[ ! -x "$BINARY" ]]; then
  echo "shguard release binary not found at $BINARY; building..." >&2
  (cd "$REPO_ROOT" && cargo build --release)
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to run this script but was not found on PATH" >&2
  exit 2
fi

pass=0
fail=0

check() {
  local desc="$1" input="$2" expected="$3"
  local actual
  actual=$(echo "$input" | "$BINARY" | jq -r '.hookSpecificOutput.permissionDecision')
  if [[ "$actual" == "$expected" ]]; then
    echo "PASS: $desc (expected=$expected, got=$actual)"
    pass=$((pass + 1))
  else
    echo "FAIL: $desc (expected=$expected, got=$actual)"
    fail=$((fail + 1))
  fi
}

# Block: a canonical dangerous rm target must be denied.
check "Block: rm -rf /" \
  '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"hook_event_name":"PreToolUse"}' \
  "deny"

# Allow: a benign command must clear all checks.
check "Allow: echo hello" \
  '{"tool_name":"Bash","tool_input":{"command":"echo hello"},"hook_event_name":"PreToolUse"}' \
  "allow"

# Ask: a command substitution in command position cannot be resolved
# statically and must prompt rather than silently allow or block.
check "Ask: \$(which python3) --version" \
  '{"tool_name":"Bash","tool_input":{"command":"$(which python3) --version"},"hook_event_name":"PreToolUse"}' \
  "ask"

# Malformed input: invalid JSON on stdin must fail closed to ask, never
# crash and never silently allow.
check "Malformed: not JSON" \
  'this is not json' \
  "ask"

echo ""
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
