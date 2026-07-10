"""Production entry point for the AI Recon Agent."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

HAITHAM_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HAITHAM_DIR.parent

for path in (str(PROJECT_ROOT), str(HAITHAM_DIR)):
    while path in sys.path:
        sys.path.remove(path)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(HAITHAM_DIR))

from config import load_config  # noqa: E402
from integration.backend_adapter_wrapper import BackendAdapterWrapper  # noqa: E402
from integration.coverage_adapter import CoverageAdapter  # noqa: E402
from integration.logger import setup_logging  # noqa: E402
from integration.skill_loader import SkillLoader  # noqa: E402
from integration.tool_adapter import ToolAdapter  # noqa: E402
from Essam.agent_loop import AgentLoop, LoopResult  # noqa: E402
from recon_pipeline import ReconResult, run_full_recon, save_recon_result  # noqa: E402


class OfflineDemoBackend:
    """Deterministic backend used only for integration-demo mode."""

    def __init__(self) -> None:
        self._acted = False

    def send(self, messages: Sequence[Dict[str, Any]], tools: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        phase = messages[-1].get("content", "").lower() if messages else ""
        if "phase: act" in phase and not self._acted:
            self._acted = True
            return {
                "role": "assistant",
                "content": "Executing one safe shell command for integration demo.",
                "tool_calls": [{"name": "run_shell", "arguments": {"command": "echo haitham-demo"}}],
                "finish_reason": "tool_calls",
            }
        if "phase: verify" in phase:
            return {"role": "assistant", "content": "completed", "tool_calls": [], "finish_reason": "stop"}
        if "phase: report" in phase:
            return {
                "role": "assistant",
                "content": "Haitham integration demo completed successfully.",
                "tool_calls": [],
                "finish_reason": "stop",
            }
        return {"role": "assistant", "content": "Planning complete.", "tool_calls": [], "finish_reason": "stop"}


DEFAULT_TOOL_SPECS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command through permission-gated execution.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_subfinder",
            "description": "Run subfinder recon wrapper.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        },
    },
]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""

    parser = argparse.ArgumentParser(description="AI Recon Agent")
    parser.add_argument("--target", help="Authorized domain or host to scan, for example example.com.")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you are authorized to scan the provided target.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the old safe integration demo instead of real recon.",
    )
    return parser.parse_args(argv)


def _build_backend(config, logger) -> Any:
    if config.offline_demo:
        logger.warning("OFFLINE_DEMO=true: using deterministic offline backend.")
        return OfflineDemoBackend()
    if not config.api_key:
        raise RuntimeError("API_KEY is required unless OFFLINE_DEMO=true.")
    return BackendAdapterWrapper(
        project_root=PROJECT_ROOT,
        base_url=config.base_url,
        api_key=config.api_key,
        model=config.model,
    )


def _load_demo_goal(config) -> str:
    if config.demo_target_file.exists():
        return config.demo_target_file.read_text(encoding="utf-8").strip()
    return config.demo_target


def _save_demo_artifacts(output_dir: Path, result: LoopResult) -> Path:
    payload = {
        "status": result.status,
        "report": result.report,
        "steps_taken": result.steps_taken,
        "events": [asdict(event) for event in result.events],
        "messages": result.messages,
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
    }
    output_path = output_dir / "integration_demo_result.json"
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def run_demo(config: Any, coverage: CoverageAdapter, logger: Any) -> int:
    """Run the safe integration demo."""

    skill_loader = SkillLoader(config.skill_dir)
    skills = skill_loader.load_skills()
    logger.info("Loaded %s Kero skills", len(skills))

    tools = ToolAdapter(PROJECT_ROOT, log_dir=config.log_dir, auto_allow=True)
    backend = OfflineDemoBackend()

    agent = AgentLoop(
        adapter=backend,
        tool_layer=tools,
        tools=DEFAULT_TOOL_SPECS,
        max_steps=config.max_steps,
        max_tool_calls=config.max_tool_calls,
        coverage_tracker=coverage,
        skill_loader=skill_loader,
    )

    result = agent.run(_load_demo_goal(config))
    coverage.add_scan_snapshot(
        target=config.coverage_target,
        subdomains=["demo.example.com"],
        open_ports=[80, 443],
        js_hashes={"app.js": "sha256-demo"},
    )

    artifact = _save_demo_artifacts(config.output_dir, result)
    logger.info("Demo artifact saved: %s", artifact)
    print(result.report)
    print(f"Output: {artifact}")
    return 0


def run_recon(target: str, config: Any, coverage: CoverageAdapter, logger: Any) -> int:
    """Run real recon pipeline for an authorized target."""

    logger.info("Starting real recon target=%s", target)
    result: ReconResult = run_full_recon(target, output_dir=config.output_dir, coverage=coverage)
    output_folder = save_recon_result(result, config.output_dir)

    logger.info("Recon completed status=%s target=%s", result.status, target)
    print(f"Recon status: {result.status}")
    print(f"Target: {result.target}")
    print(f"Subdomains: {len(result.subdomains)}")
    print(f"Live hosts: {len(result.live_hosts)}")
    print(f"Open ports: {len(result.open_ports)}")
    print(f"URLs: {len(result.urls)}")
    print(f"Archived URLs: {len(result.archived_urls)}")
    print(f"Found paths: {len(result.found_paths)}")
    print(f"Findings: {len(result.findings)}")
    print(f"Output folder: {output_folder}")
    print(f"Summary: {output_folder / 'summary.txt'}")
    print(f"Full report: {output_folder / 'full_report.json'}")
    print(f"Latest: {config.output_dir / 'recon_latest.json'}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Initialize modules and run either demo mode or real recon."""

    args = parse_args(argv)
    config = load_config()
    logger = setup_logging(config.log_dir, config.log_level)
    logger.info("AI Recon Agent startup")

    try:
        coverage_target = args.target or config.coverage_target
        coverage = CoverageAdapter(PROJECT_ROOT, default_target=coverage_target)

        if args.demo:
            return run_demo(config, coverage, logger)

        if args.target:
            if not args.authorized:
                print("Refusing to scan without --authorized. Only scan assets you own or have permission to test.")
                return 2
            return run_recon(args.target, config, coverage, logger)

        print("No target provided.")
        print("Run a safe demo: python Haitham/main.py --demo")
        print("Run real recon: python Haitham/main.py --target example.com --authorized")
        return 2
    except Exception:
        logger.exception("AI Recon Agent failed")
        return 1
    finally:
        logger.info("AI Recon Agent shutdown")


if __name__ == "__main__":
    raise SystemExit(main())
