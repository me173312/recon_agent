"""Unified tool execution adapter for Mazen/Omar and Rana modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping
import importlib
import json
import logging
import sys


LOGGER = logging.getLogger("haitham.tools")

RANA_TOOL_MAP = {
    "run_subfinder": "run_subfinder",
    "run_alterx": "run_alterx",
    "run_httpx": "run_httpx",
    "run_naabu": "run_naabu",
    "run_gau": "run_gau",
}


def _lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _dedupe(values: List[str]) -> List[str]:
    return sorted(set(values))


@dataclass
class ToolAdapter:
    """Expose execute(tool_name, arguments) for Essam's AgentLoop."""

    project_root: Path
    log_dir: Path
    auto_allow: bool = True
    _gated_tools: Any = field(init=False, default=None)
    _permission_gate_module: Any = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._gated_tools = self._init_gated_tools()
        LOGGER.info("Tool adapter initialized with Omar gated tools")

    def _prompt(self, _: str, __: str) -> Any:
        if not self.auto_allow:
            return self._permission_gate_module.Decision.DENY
        return self._permission_gate_module.Decision.ALLOW_SESSION

    def _init_gated_tools(self) -> Any:
        omar_dir = self.project_root / "omar"
        if str(omar_dir) not in sys.path:
            sys.path.insert(0, str(omar_dir))
        self._permission_gate_module = importlib.import_module("permission_gate")
        tools_module = importlib.import_module("tools")
        return tools_module.GatedTools(
            blocklist_path=str(omar_dir / "blocklist.json"),
            log_path=str(self.log_dir / "tool_gate.log"),
            auto_prompt=self._prompt,
        )

    def _run_shell(self, command: str) -> str:
        result = self.execute("run_shell", {"command": command})
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "shell execution failed"))
        return str(result.get("result", ""))

    def _execute_rana(self, tool_name: str, arguments: Mapping[str, Any]) -> Dict[str, Any]:
        args = dict(arguments)
        if tool_name == "run_subfinder":
            target = str(args.get("target", ""))
            out = self._run_shell(f"subfinder -d {target} -silent")
            subdomains = _dedupe(_lines(out))
            return {
                "ok": True,
                "tool": tool_name,
                "result": {
                    "tool": "subfinder",
                    "target": target,
                    "subdomains": subdomains,
                    "count": len(subdomains),
                },
            }
        if tool_name == "run_alterx":
            subdomains = list(args.get("subdomains", []))
            target = str(args.get("target", ""))
            if not subdomains:
                return {
                    "ok": True,
                    "tool": tool_name,
                    "result": {"tool": "alterx", "target": target, "permutations": [], "count": 0},
                }
            payload = "\\n".join(subdomains)
            out = self._run_shell(f"echo \"{payload}\" | alterx -silent")
            permutations = _dedupe(_lines(out))
            return {
                "ok": True,
                "tool": tool_name,
                "result": {
                    "tool": "alterx",
                    "target": target,
                    "permutations": permutations,
                    "count": len(permutations),
                },
            }
        if tool_name == "run_httpx":
            hosts = list(args.get("hosts", []))
            target = str(args.get("target", ""))
            if not hosts:
                return {
                    "ok": True,
                    "tool": tool_name,
                    "result": {"tool": "httpx", "target": target, "live_hosts": [], "count": 0},
                }
            payload = "\\n".join(_dedupe([str(h) for h in hosts]))
            out = self._run_shell(
                f"echo \"{payload}\" | httpx -silent -json -status-code -title"
            )
            parsed: List[Dict[str, Any]] = []
            for line in _lines(out):
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {
                "ok": True,
                "tool": tool_name,
                "result": {"tool": "httpx", "target": target, "live_hosts": parsed, "count": len(parsed)},
            }
        if tool_name == "run_naabu":
            hosts = list(args.get("hosts", []))
            target = str(args.get("target", ""))
            if not hosts:
                return {
                    "ok": True,
                    "tool": tool_name,
                    "result": {"tool": "naabu", "target": target, "open_ports": [], "count": 0},
                }
            payload = "\\n".join(_dedupe([str(h) for h in hosts]))
            out = self._run_shell(f"echo \"{payload}\" | naabu -silent -json -passive")
            parsed: List[Dict[str, Any]] = []
            for line in _lines(out):
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {
                "ok": True,
                "tool": tool_name,
                "result": {"tool": "naabu", "target": target, "open_ports": parsed, "count": len(parsed)},
            }
        if tool_name == "run_gau":
            hostname = str(args.get("hostname", args.get("target", "")))
            out = self._run_shell(f"gau --subs {hostname}")
            urls = _dedupe([line for line in _lines(out) if line.startswith("http")])
            return {
                "ok": True,
                "tool": tool_name,
                "result": {"tool": "gau", "target": hostname, "urls": urls, "count": len(urls)},
            }
        raise ValueError(f"Unsupported Rana tool: {tool_name}")

    def execute(self, tool_name: str, arguments: Mapping[str, Any]) -> Dict[str, Any]:
        """Execute a gated Omar tool or mapped Rana recon wrapper."""

        tool_name = str(tool_name)
        args = dict(arguments)
        LOGGER.info("Tool call requested: %s", tool_name)

        try:
            if tool_name in RANA_TOOL_MAP:
                return self._execute_rana(tool_name, args)
            if hasattr(self._gated_tools, tool_name):
                result = getattr(self._gated_tools, tool_name)(**args)
                LOGGER.info("Tool call completed: %s", tool_name)
                return {"ok": True, "tool": tool_name, "result": result}
            raise ValueError(f"Unknown tool '{tool_name}'")
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Tool call failed: %s", tool_name)
            return {
                "ok": False,
                "tool": tool_name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
