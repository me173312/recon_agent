"""Adapter around Sherif's SQLite coverage tracker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import importlib.util
import logging


LOGGER = logging.getLogger("haitham.coverage")


def _load_module(file_path: Path, module_name: str) -> Any:
    """Dynamically import a teammate module without modifying package layout."""

    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to import module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class CoverageAdapter:
    """Normalize Sherif coverage APIs for Essam's AgentLoop interface."""

    project_root: Path
    default_target: str = "integration-demo"

    def __post_init__(self) -> None:
        coverage_path = self._find_coverage_module()
        self._module = _load_module(coverage_path, "sherif_coverage")
        self._module.initialize_database()
        LOGGER.info("Sherif coverage tracker initialized")

    def mark_tested(self, item: str) -> None:
        """Mark one loop item as tested."""

        endpoint = item.split(":", 1)[1] if ":" in item else item
        self._module.mark_tested(
            target=self.default_target,
            endpoint=endpoint,
            parameter="n/a",
            vulnerability_class="loop-step",
            tool_used="agent_loop",
        )
        LOGGER.info("Coverage marked tested: %s", endpoint)

    def mark_vulnerability_tested(
        self,
        endpoint: str,
        parameter: str,
        vulnerability_class: str,
        tool_used: str,
    ) -> None:
        """Mark one tool-aware recon coverage item as tested."""

        self._module.mark_tested(
            target=self.default_target,
            endpoint=endpoint,
            parameter=parameter,
            vulnerability_class=vulnerability_class,
            tool_used=tool_used,
        )
        LOGGER.info(
            "Coverage marked tested: endpoint=%s parameter=%s class=%s tool=%s",
            endpoint,
            parameter,
            vulnerability_class,
            tool_used,
        )

    def get_untested(self) -> List[str]:
        """Return untested endpoint labels for the active target."""

        rows = self._module.get_untested(self.default_target)
        return [str(row.get("endpoint", "unknown")) for row in rows]

    def add_scan_snapshot(
        self,
        target: str,
        subdomains: List[str],
        open_ports: List[int],
        js_hashes: Dict[str, str],
    ) -> None:
        """Persist a scan snapshot in Sherif's database."""

        self._module.add_scan_snapshot(target, subdomains, open_ports, js_hashes)
        LOGGER.info("Coverage snapshot stored for target=%s", target)

    def _find_coverage_module(self) -> Path:
        """Locate Sherif's coverage module across known teammate layouts."""

        candidates = [
            self.project_root / "Sherif" / "coverage" / "coverage.py",
            self.project_root / "sherif" / "coverage" / "coverage.py",
            self.project_root / "sherif" / "coverage.py",
            self.project_root.parent / "Sherif" / "coverage" / "coverage.py",
            self.project_root.parent / "sherif" / "coverage" / "coverage.py",
            self.project_root.parent / "sherif" / "coverage.py",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise FileNotFoundError("Unable to locate Sherif coverage module.")
