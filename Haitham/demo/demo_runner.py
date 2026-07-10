"""Full demonstration runner for Haitham integration deliverables."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any, Dict

HAITHAM_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = HAITHAM_DIR.parent

for path in (str(PROJECT_ROOT), str(HAITHAM_DIR)):
    while path in sys.path:
        sys.path.remove(path)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(HAITHAM_DIR))

from config import load_config  # noqa: E402
from integration.coverage_adapter import CoverageAdapter  # noqa: E402
from integration.logger import setup_logging  # noqa: E402
from integration.skill_loader import SkillLoader  # noqa: E402
from integration.tool_adapter import ToolAdapter  # noqa: E402
from main import OfflineDemoBackend, DEFAULT_TOOL_SPECS, _load_demo_goal  # noqa: E402
from Essam.agent_loop import AgentLoop  # noqa: E402


def run_demo() -> Dict[str, Any]:
    """Execute a complete integration demonstration and return summary."""

    config = load_config()
    logger = setup_logging(config.log_dir, config.log_level)
    logger.info("Demo runner started")

    skill_loader = SkillLoader(config.skill_dir)
    skills = skill_loader.load_skills()
    skill_name = next(iter(skills.keys()), "none")
    logger.info("Skill loaded: %s", skill_name)

    tool_adapter = ToolAdapter(PROJECT_ROOT, log_dir=config.log_dir, auto_allow=True)
    tool_result = tool_adapter.execute("run_shell", {"command": "echo demo-runner"})
    logger.info("Tool call result: %s", tool_result.get("ok"))

    coverage = CoverageAdapter(PROJECT_ROOT, default_target=config.coverage_target)
    coverage.mark_tested("step:demo-runner")
    coverage.add_scan_snapshot(
        target=config.coverage_target,
        subdomains=["runner.demo"],
        open_ports=[443],
        js_hashes={"bundle.js": "sha256-runner"},
    )
    logger.info("Coverage updated")

    backend = OfflineDemoBackend()
    agent = AgentLoop(
        adapter=backend,
        tool_layer=tool_adapter,
        tools=DEFAULT_TOOL_SPECS,
        max_steps=config.max_steps,
        max_tool_calls=config.max_tool_calls,
        coverage_tracker=coverage,
        skill_loader=skill_loader,
    )
    loop_result = agent.run(_load_demo_goal(config))
    logger.info("Agent response generated")

    summary = {
        "skill_loaded": skill_name,
        "tool_called": tool_result,
        "coverage_untested": coverage.get_untested(),
        "agent_status": loop_result.status,
        "agent_report": loop_result.report,
        "events": [asdict(event) for event in loop_result.events],
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
    }

    output_path = config.output_dir / "demo_runner_result.json"
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Demo runner artifact: %s", output_path)
    return summary


if __name__ == "__main__":
    result = run_demo()
    print(json.dumps(result, indent=2))
