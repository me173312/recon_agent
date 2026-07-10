"""
permission_gate.py

The safety brain of the tool execution layer. Every gated tool call passes
through PermissionGate.check() BEFORE it is allowed to run.

Decision flow for a single call:

    1. Blocklist check (hard, silent-to-the-agent rejection, no prompt)
       -> if matched: DENY immediately, log it, done.

    2. Session cache check
       -> if this exact (tool, key) was already granted "allow-session"
          earlier in this run: ALLOW immediately, no re-prompt.

    3. Interactive prompt to the human operator
       -> allow-once   : run this one call, ask again next time
       -> allow-session : run this call AND remember the decision for
                           the rest of the session (same tool+key)
       -> deny          : do not run, tell the agent it was denied

Why a "key" instead of gating per raw command string?
Recon commands change slightly every call (different subdomain, different
port, etc). If we cached by the literal string, "allow-session" would
almost never actually save the operator from re-approving. So each tool
defines what its meaningful "key" is (see tools.py) -- e.g. for shell it's
the base command name, for HTTP it's the target host, for file it's the
resolved directory.
"""

import re
import json
from enum import Enum
from pathlib import Path
from typing import Optional


class Decision(Enum):
    ALLOW_ONCE = "allow-once"
    ALLOW_SESSION = "allow-session"
    DENY = "deny"
    BLOCKED = "blocked"  # hit the blocklist -- never reaches the human


class PermissionDenied(Exception):
    """Raised when a gated tool call is not permitted to run."""
    def __init__(self, reason: str, decision: Decision):
        self.reason = reason
        self.decision = decision
        super().__init__(reason)


class PermissionGate:
    def __init__(self, blocklist_path: str = "blocklist.json",
                 auto_prompt=None):
        """
        blocklist_path: path to the JSON file of hard-blocked regex patterns.
        auto_prompt: optional callable(tool_type, description) -> Decision.
                     Defaults to an interactive input() prompt. Passing a
                     custom function lets the agent loop (or tests) run
                     non-interactively.
        """
        self._blocklist = self._load_blocklist(blocklist_path)
        self._session_allows = set()  # set of (tool_type, key) tuples
        self._prompt_fn = auto_prompt or self._interactive_prompt

    # ------------------------------------------------------------------
    # Blocklist
    # ------------------------------------------------------------------
    def _load_blocklist(self, path: str) -> dict:
        data = json.loads(Path(path).read_text())
        # Precompile regex for speed; drop the human-readable _readme key.
        compiled = {}
        for tool_type, entries in data.items():
            if tool_type.startswith("_"):
                continue
            compiled[tool_type] = [
                (re.compile(entry["pattern"], re.IGNORECASE), entry["reason"])
                for entry in entries
            ]
        return compiled

    def _check_blocklist(self, tool_type: str, target_string: str) -> Optional[str]:
        """Returns the block reason if matched, else None."""
        for pattern, reason in self._blocklist.get(tool_type, []):
            if pattern.search(target_string):
                return reason
        return None

    # ------------------------------------------------------------------
    # Interactive prompt (default -- swap out for the agent's own UI/CLI)
    # ------------------------------------------------------------------
    def _interactive_prompt(self, tool_type: str, description: str) -> Decision:
        print("\n--- PERMISSION REQUEST ---")
        print(f"Tool type : {tool_type}")
        print(f"Requested : {description}")
        choice = input("Allow? [o]nce / [s]ession / [d]eny: ").strip().lower()
        if choice in ("s", "session"):
            return Decision.ALLOW_SESSION
        if choice in ("o", "once"):
            return Decision.ALLOW_ONCE
        return Decision.DENY

    # ------------------------------------------------------------------
    # Main entrypoint
    # ------------------------------------------------------------------
    def check(self, tool_type: str, key: str, description: str,
              target_string: str) -> Decision:
        """
        tool_type      : "shell" | "http" | "file"
        key            : cache key for session-level allow (e.g. base command,
                          hostname, directory)
        description    : human-readable summary shown in the prompt/log
        target_string  : the actual string checked against the blocklist
                          (full command line, full URL, or full path)

        Returns the Decision. Raises PermissionDenied if not permitted.
        """
        # 1. Blocklist -- silent hard stop, never reaches a human prompt.
        block_reason = self._check_blocklist(tool_type, target_string)
        if block_reason is not None:
            raise PermissionDenied(
                f"Blocked by policy: {block_reason}", Decision.BLOCKED
            )

        # 2. Session cache -- already approved for the rest of this run.
        cache_key = (tool_type, key)
        if cache_key in self._session_allows:
            return Decision.ALLOW_SESSION

        # 3. Ask the human.
        decision = self._prompt_fn(tool_type, description)

        if decision == Decision.ALLOW_SESSION:
            self._session_allows.add(cache_key)
            return decision
        if decision == Decision.ALLOW_ONCE:
            return decision

        raise PermissionDenied(
            f"Denied by operator for: {description}", Decision.DENY
        )
