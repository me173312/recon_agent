"""
demo.py -- exercises all four permission paths without needing a human
at the keyboard, by substituting a scripted auto_prompt function.
"""

from permission_gate import Decision, PermissionDenied
from tools import GatedTools

# Scripted operator responses, consumed in order per prompt call.
_script = iter([
    Decision.ALLOW_ONCE,     # for the first "echo hello" -> allow-once
    Decision.ALLOW_SESSION,  # for "echo world" -> allow-session
    Decision.DENY,           # for the http call -> deny
])


def scripted_prompt(tool_type, description):
    decision = next(_script)
    print(f"[auto-prompt] {tool_type}: {description} -> {decision.value}")
    return decision


def main():
    gt = GatedTools(auto_prompt=scripted_prompt)

    print("\n== 1) BLOCKLIST: catastrophic command, should hard-reject ==")
    try:
        gt.run_shell("rm -rf /")
    except PermissionDenied as e:
        print(f"Correctly blocked: {e}")

    print("\n== 2) ALLOW-ONCE: first safe shell command ==")
    out = gt.run_shell("echo hello")
    print(f"Output: {out.strip()}")

    print("\n== 3) ALLOW-SESSION: second safe shell command, different base cmd ==")
    out = gt.run_shell("echo world")
    print(f"Output: {out.strip()}")

    print("\n== 4) SESSION CACHE: same base command again, should NOT re-prompt ==")
    out = gt.run_shell("echo world again")
    print(f"Output: {out.strip()} (no [auto-prompt] line above means cache worked)")

    print("\n== 5) DENY: http request, operator says no ==")
    try:
        gt.http_request("GET", "https://example.com")
    except PermissionDenied as e:
        print(f"Correctly denied: {e}")

    print("\n== Log file contents (tool_gate.log) ==")
    with open("tool_gate.log") as f:
        for line in f:
            print(line.strip())


if __name__ == "__main__":
    main()
