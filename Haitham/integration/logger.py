"""Structured logging utilities for Haitham integration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


def setup_logging(log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure file + console logging under Haitham/logs."""

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "integration.log"
    gate_log_file = log_dir / "tool_gate.log"

    root_logger = logging.getLogger("haitham")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    root_logger.info("Logging initialized at %s", log_file)
    root_logger.info("Tool gate log path: %s", gate_log_file)
    return root_logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a namespaced logger under the Haitham logging tree."""

    if not name:
        return logging.getLogger("haitham")
    return logging.getLogger(f"haitham.{name}")
