"""
tools.py

The callable "tools" the agent invokes. Each one:
  1. Builds a description + key for the permission gate
  2. Calls gate.check(...) -- this may raise PermissionDenied
  3. Logs the outcome either way (allowed+executed, or blocked/denied)
  4. Executes for real only if the gate did not raise

These are the functions Essam's agent loop will register as callable
tools for the model (e.g. as OpenAI-style tool/function definitions).
"""

import subprocess
import shlex
from pathlib import Path
from urllib.parse import urlparse

import requests

from permission_gate import PermissionGate, PermissionDenied
from gate_logger import GateLogger


class GatedTools:
    def __init__(self, blocklist_path: str = "blocklist.json",
                 log_path: str = "tool_gate.log", auto_prompt=None):
        self.gate = PermissionGate(blocklist_path=blocklist_path,
                                    auto_prompt=auto_prompt)
        self.logger = GateLogger(log_path=log_path)

    # ------------------------------------------------------------------
    # Shell
    # ------------------------------------------------------------------
    def run_shell(self, command: str, timeout: int = 60) -> str:
        """
        Runs a shell command after passing it through the permission gate.
        `key` for session caching is the base command name (e.g. "subfinder"),
        so approving one subfinder call can cover the whole session without
        covering unrelated commands.
        """
        base_cmd = shlex.split(command)[0] if command.strip() else ""
        description = f"Run shell command: {command}"

        try:
            decision = self.gate.check(
                tool_type="shell",
                key=base_cmd,
                description=description,
                target_string=command,
            )
        except PermissionDenied as e:
            self.logger.log("shell", description, command,
                             decision=e.decision.value, error=str(e))
            raise

        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout,
            )
            output = proc.stdout + proc.stderr
            self.logger.log("shell", description, command,
                             decision=decision.value, result=output)
            return output
        except Exception as e:
            self.logger.log("shell", description, command,
                             decision=decision.value, error=str(e))
            raise

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def http_request(self, method: str, url: str, headers: dict = None,
                      data=None, timeout: int = 30) -> str:
        """
        Makes an HTTP request after gating. `key` is the target host, so
        allow-session covers repeat calls to the same host (typical during
        recon against one target) without silently trusting every host.
        """
        host = urlparse(url).netloc or url
        description = f"{method.upper()} request to {url}"

        try:
            decision = self.gate.check(
                tool_type="http",
                key=host,
                description=description,
                target_string=url,
            )
        except PermissionDenied as e:
            self.logger.log("http", description, url,
                             decision=e.decision.value, error=str(e))
            raise

        try:
            resp = requests.request(method, url, headers=headers, data=data,
                                     timeout=timeout)
            summary = f"status={resp.status_code} len={len(resp.content)}"
            self.logger.log("http", description, url,
                             decision=decision.value, result=summary)
            return resp.text
        except Exception as e:
            self.logger.log("http", description, url,
                             decision=decision.value, error=str(e))
            raise

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------
    def read_file(self, path: str) -> str:
        return self._file_op("read", path, lambda p: Path(p).read_text())

    def write_file(self, path: str, content: str) -> str:
        def _write(p):
            Path(p).write_text(content)
            return f"wrote {len(content)} bytes to {p}"
        return self._file_op("write", path, _write)

    def _file_op(self, mode: str, path: str, action) -> str:
        """
        `key` is the resolved parent directory, so allow-session covers
        repeated reads/writes within the same working/output directory
        without covering a jump to an unrelated path like /etc or ~/.ssh.
        """
        resolved = str(Path(path).resolve())
        directory = str(Path(resolved).parent)
        description = f"{mode.capitalize()} file: {resolved}"

        try:
            decision = self.gate.check(
                tool_type="file",
                key=directory,
                description=description,
                target_string=resolved,
            )
        except PermissionDenied as e:
            self.logger.log("file", description, resolved,
                             decision=e.decision.value, error=str(e))
            raise

        try:
            result = action(resolved)
            self.logger.log("file", description, resolved,
                             decision=decision.value,
                             result=str(result)[:300])
            return result
        except Exception as e:
            self.logger.log("file", description, resolved,
                             decision=decision.value, error=str(e))
            raise
