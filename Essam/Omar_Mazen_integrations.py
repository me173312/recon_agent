"""Glue code that combines the delivered backend adapter and gated tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any, Callable, Optional, Sequence

from .agent_loop import AgentLoop, CoverageTrackerInterface, SkillLoaderInterface, ToolSpec


@dataclass(frozen=True)
class DeliveredPaths:
    """Locations of the two delivered teammate folders."""

    root: Path = Path(__file__).resolve().parent

    @property
    def adapter_dir(self) -> Path:
        return self.root / "Adapter"

    @property
    def tools_dir(self) -> Path:
        return self.root / "task_ phase 0 +1"

    @property
    def adapter_site_packages(self) -> Path:
        return self.adapter_dir / ".venv" / "Lib" / "site-packages"


DEFAULT_TOOL_SPECS: list[ToolSpec] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command through the permission gate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer", "default": 60},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Make an HTTP request through the permission gate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {"type": "object"},
                    "data": {},
                    "timeout": {"type": "integer", "default": 30},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a local file through the permission gate.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write a local file through the permission gate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
]


def add_delivered_import_paths(paths: DeliveredPaths = DeliveredPaths()) -> None:
    """Make teammate modules importable without copying their source folders."""

    for path in reversed((paths.adapter_site_packages, paths.adapter_dir, paths.tools_dir)):
        if path.exists() and str(path) not in sys.path:
            sys.path.insert(0, str(path))


def create_backend_adapter(
    *,
    base_url: str,
    api_key: str,
    model: str,
    paths: DeliveredPaths = DeliveredPaths(),
) -> Any:
    """Create the delivered BackendAdapter from the local Essam/Adapter folder."""

    add_delivered_import_paths(paths)
    from adapter import BackendAdapter

    return BackendAdapter(base_url=base_url, api_key=api_key, model=model)


def create_gated_tools(
    *,
    paths: DeliveredPaths = DeliveredPaths(),
    log_path: Optional[str] = None,
    auto_prompt: Optional[Callable[[str, str], Any]] = None,
) -> Any:
    """Create the delivered GatedTools from the local Essam/task_ phase 0 +1 folder."""

    add_delivered_import_paths(paths)
    from tools import GatedTools

    return GatedTools(
        blocklist_path=str(paths.tools_dir / "blocklist.json"),
        log_path=log_path or str(paths.tools_dir / "tool_gate.log"),
        auto_prompt=auto_prompt,
    )


def create_agent_loop(
    *,
    base_url: str,
    api_key: str,
    model: str,
    paths: DeliveredPaths = DeliveredPaths(),
    max_steps: int = 30,
    max_tool_calls: Optional[int] = None,
    log_path: Optional[str] = None,
    auto_prompt: Optional[Callable[[str, str], Any]] = None,
    tools: Optional[Sequence[ToolSpec]] = None,
    coverage_tracker: Optional[CoverageTrackerInterface] = None,
    skill_loader: Optional[SkillLoaderInterface] = None,
) -> AgentLoop:
    """Build Essam's loop with the delivered adapter and gated tools wired in."""

    adapter = create_backend_adapter(
        base_url=base_url,
        api_key=api_key,
        model=model,
        paths=paths,
    )
    gated_tools = create_gated_tools(
        paths=paths,
        log_path=log_path,
        auto_prompt=auto_prompt,
    )
    return AgentLoop(
        adapter=adapter,
        tool_layer=gated_tools,
        tools=list(tools or DEFAULT_TOOL_SPECS),
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        coverage_tracker=coverage_tracker,
        skill_loader=skill_loader,
    )
