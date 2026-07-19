# End-to-end verification (issue #14, C2)

Verifies shguard against the real `target/release/shguard` release binary
wired up as a Claude Code `PreToolUse` hook, per `plan.md`'s hook adapter
contract (`src/adapter.rs`).

**Version tested**: `shguard 0.1.0` (`target/release/shguard --version`).

## `settings.json` registration

Register shguard as a `PreToolUse` hook on the `Bash` matcher:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "shguard"
          }
        ]
      }
    ]
  }
}
```

## Results

Each row was produced by piping the exact PreToolUse stdin payload through
the release binary, e.g.:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"hook_event_name":"PreToolUse"}' \
  | target/release/shguard
```

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `rm -rf /` | Block (deny) | deny | verified |
| `echo hello` | Allow | allow | verified |
| `$(which python3) --version` | Ask | ask | verified |

Raw `hookSpecificOutput` for each case:

- `rm -rf /`:
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"matches blocklist rule \"rm-recursive-force-dangerous-target\": rm with recursive+force flags against a root-level, home, or device target"}}
  ```
- `echo hello`:
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"shguard: command cleared all checks"}}
  ```
- `$(which python3) --version`:
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"command position contains a command/backquote substitution (`$(...)`/`` `...` ``); which command will run cannot be determined statically"}}
  ```

In a live Claude Code session with the hook registered as above, the Ask
case (`$(which python3) --version`) surfaces as the standard tool-use
confirmation dialog rather than running silently, and the Block case
prevents the tool call from executing at all.

## Fixture smoke test

`scripts/smoke.sh` pipes these same fixtures (plus a malformed-input case)
through the release binary and asserts each `permissionDecision` matches
expectations. It exits `0` when all fixtures pass:

```
$ scripts/smoke.sh
PASS: Block: rm -rf / (expected=deny, got=deny)
PASS: Allow: echo hello (expected=allow, got=allow)
PASS: Ask: $(which python3) --version (expected=ask, got=ask)
PASS: Malformed: not JSON (expected=ask, got=ask)

4 passed, 0 failed
```
