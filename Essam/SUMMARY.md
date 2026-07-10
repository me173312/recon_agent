# Essam Core Agent Loop Summary

## What This Folder Contains

This folder is self-contained for Essam's task. It combines:

- `Adapter/`
  - Backend adapter with `BackendAdapter(base_url, api_key, model)`.
  - Main method: `send(messages, tools=None) -> dict`.
- `task_ phase 0 +1/`
  - Gated tool execution layer.
  - Main methods: `run_shell`, `http_request`, `read_file`, `write_file`.

## Essam Files

- `agent_loop.py`
  - Implements plan -> act -> observe -> verify -> report.
  - Uses the backend adapter for model calls.
  - Uses the gated tools for tool execution.
  - Enforces `max_steps` and `max_tool_calls` to prevent runaway behavior.
  - Converts adapter/tool failures into observe events instead of crashing.
  - Includes clean hooks for future coverage tracker and skill loader integrations.

- `Omar_Mazen_integrations.py`
  - Wires the local `Adapter/` and `task_ phase 0 +1/` folders into the loop.
  - Default paths are relative to this `Essam` folder, so no `D:/LLM TASK` path is needed.
  - Provides `create_agent_loop(...)` for building the combined system.

- `__init__.py`
  - Exports the main loop and helper functions.

## Verification

The current project tests pass:

```powershell
python -m pytest -q -ra
```

Result:

```text
11 passed
```

Note: `pytest.ini` limits the test run to Essam's integration/unit tests under `tests/`, so copied teammate tests inside `Adapter/` are not accidentally collected.
