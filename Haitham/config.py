"""Central configuration for Haitham's integration layer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from dotenv import load_dotenv


HAITHAM_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HAITHAM_DIR.parent
ENV_PATH = HAITHAM_DIR / ".env"
load_dotenv(ENV_PATH)
load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class AppConfig:
    """Runtime settings loaded from environment variables."""

    api_key: str = os.getenv("API_KEY", os.getenv("OPENAI_API_KEY", "")).strip()
    model: str = os.getenv("MODEL", os.getenv("MODEL_NAME", "gpt-4o-mini")).strip()
    base_url: str = os.getenv("BASE_URL", os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).strip()
    log_level: str = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    demo_target: str = os.getenv(
        "DEMO_TARGET",
        "Perform integration demo recon on example.com with one safe tool action.",
    ).strip()
    offline_demo: bool = os.getenv("OFFLINE_DEMO", "false").lower() in {"1", "true", "yes"}
    max_steps: int = int(os.getenv("MAX_STEPS", "3"))
    max_tool_calls: int = int(os.getenv("MAX_TOOL_CALLS", "6"))
    coverage_target: str = os.getenv("COVERAGE_TARGET", "integration-demo").strip()
    skill_dir: Path = PROJECT_ROOT / "kero"
    log_dir: Path = HAITHAM_DIR / "logs"
    output_dir: Path = HAITHAM_DIR / "outputs"
    demo_target_file: Path = HAITHAM_DIR / "demo" / "demo_target.md"


def load_config() -> AppConfig:
    """Load and validate runtime configuration."""

    config = AppConfig()
    config.log_dir.mkdir(parents=True, exist_ok=True)
    config.output_dir.mkdir(parents=True, exist_ok=True)
    return config
