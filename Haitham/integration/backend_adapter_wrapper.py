"""Wrapper around teammate backend adapter implementations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import importlib.util
import logging


LOGGER = logging.getLogger("haitham.backend")


def _load_backend_class(project_root: Path) -> type:
    """Discover BackendAdapter from teammate folders without editing them."""

    candidates = [
        project_root / "omar" / "adapter.py",
        project_root / "mazen" / "adapter.py",
        project_root / "Essam" / "Adapter" / "adapter.py",
    ]
    for path in candidates:
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location(f"backend_{path.parent.name}", str(path))
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        adapter_class = getattr(module, "BackendAdapter", None)
        if adapter_class is not None:
            LOGGER.info("Loaded backend adapter from %s", path)
            return adapter_class
    raise ImportError("No BackendAdapter implementation found in teammate folders.")


@dataclass
class BackendAdapterWrapper:
    """Stable send(messages, tools) interface for Essam's AgentLoop."""

    project_root: Path
    base_url: str
    api_key: str
    model: str

    def __post_init__(self) -> None:
        adapter_class = _load_backend_class(self.project_root)
        self._adapter = adapter_class(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
        )

    def send(
        self,
        messages: Sequence[Dict[str, Any]],
        tools: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Send chat completion request and normalize response payload."""

        response = self._adapter.send(list(messages), list(tools or []))
        if isinstance(response, dict):
            return {
                "role": response.get("role", "assistant"),
                "content": response.get("content", ""),
                "tool_calls": response.get("tool_calls", []),
                "finish_reason": response.get("finish_reason", "stop"),
            }

        choices = getattr(response, "choices", [])
        if not choices:
            return {"role": "assistant", "content": str(response), "tool_calls": [], "finish_reason": "stop"}

        message = choices[0].message
        return {
            "role": getattr(message, "role", "assistant"),
            "content": getattr(message, "content", ""),
            "tool_calls": getattr(message, "tool_calls", []),
            "finish_reason": getattr(choices[0], "finish_reason", "stop"),
        }
