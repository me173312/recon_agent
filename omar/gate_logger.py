"""
gate_logger.py

Appends one JSON line per tool call attempt to a log file. Deliberately
JSONL (one JSON object per line) rather than a single JSON array, because:
  - it's append-only and safe even if the process crashes mid-run
  - it's trivial to tail -f, grep, or stream into another tool later
"""

import json
import time
from pathlib import Path


class GateLogger:
    def __init__(self, log_path: str = "tool_gate.log"):
        self.log_path = Path(log_path)

    def log(self, tool_type: str, description: str, target_string: str,
             decision: str, result: str = "", error: str = ""):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool_type": tool_type,
            "description": description,
            "target": target_string,
            "decision": decision,
            "result_summary": (result[:300] if result else ""),
            "error": error,
        }
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
