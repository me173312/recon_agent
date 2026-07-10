# Tool Execution & Permission Gating

Safety layer between the agent's decisions and real system access (shell,
HTTP, file I/O). No tool executes without passing through this gate first.

## Files

| File | Purpose |
|---|---|
| `blocklist.json` | Regex patterns that are hard-rejected before any prompt. Never overridable. |
| `permission_gate.py` | Decision engine: blocklist check -> session cache check -> human prompt. |
| `gate_logger.py` | Appends one JSON line per tool call attempt to `tool_gate.log`. |
| `tools.py` | The actual callable tools: `run_shell`, `http_request`, `read_file`, `write_file`. |
| `demo.py` | Non-interactive walkthrough of all decision paths (blocked / allow-once / allow-session / deny). |

## How a call flows

```
agent calls e.g. gt.run_shell("subfinder -d target.com")
        |
        v
1. Blocklist check (blocklist.json)
   -> match? reject immediately, log "blocked", never prompt a human
        |  no match
        v
2. Session cache check
   -> already allow-session'd for this (tool_type, key)? run immediately
        |  not cached
        v
3. Prompt the operator: allow-once / allow-session / deny
   -> deny: raise PermissionDenied, log "deny", nothing executes
   -> allow-once: execute, log outcome, do NOT cache (asks again next time)
   -> allow-session: execute, log outcome, cache (tool_type, key) for the
      rest of this run
```

## The "key" concept (why session caching isn't per-exact-command)

Recon commands vary on every call (different subdomain, different port,
different URL). Caching by the literal string would make "allow-session"
almost useless. Instead each tool type defines a coarser key:

- **shell** -> base command name (`subfinder`, `curl`, `nuclei`, ...)
- **http** -> target hostname
- **file** -> resolved parent directory

So approving one `nuclei` call session-wide covers future `nuclei` calls
with different flags, but does NOT extend trust to an unrelated command
like `curl`.

## Wiring into the agent loop (for Essam)

```python
from tools import GatedTools

gt = GatedTools(
    blocklist_path="blocklist.json",
    log_path="tool_gate.log",
)

# Register these as callable tools/functions for the model:
gt.run_shell(command: str) -> str
gt.http_request(method: str, url: str, headers=None, data=None) -> str
gt.read_file(path: str) -> str
gt.write_file(path: str, content: str) -> str
```

By default, permission prompts block on `input()` in the terminal. To run
non-interactively (e.g. inside the agent loop with a different UI), pass a
custom function:

```python
def my_prompt(tool_type: str, description: str) -> Decision:
    # route to wherever the human operator actually is
    ...

gt = GatedTools(auto_prompt=my_prompt)
```

All exceptions from denied/blocked calls are `PermissionDenied` — catch
this in the agent loop and feed the `.reason` back to the model as the
tool's result, so it can adapt (e.g. try a narrower request, or move on).

## Extending the blocklist

Add entries to the relevant array in `blocklist.json`. Every entry needs
a `pattern` (regex, case-insensitive) and a `reason` (shown in prompts
and logs). Keep this list to things that are **never** legitimate for
this agent — anything merely risky-but-sometimes-needed should go through
the normal permission prompt instead, not the blocklist.

## Reviewing the audit log

`tool_gate.log` is JSONL (one JSON object per line) — safe to append to
even if the process crashes mid-run. Tail it live during a demo:

```bash
tail -f tool_gate.log
```

Or grep for denials/blocks after a session:

```bash
grep -E '"decision": "(deny|blocked)"' tool_gate.log
```

## Coordination note

Rana's `recon_tools.py` wrappers (subfinder, httpx, naabu, etc.) should
call through `GatedTools.run_shell()` rather than `subprocess` directly,
so every recon tool invocation is gated and logged the same way.
