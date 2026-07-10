# Integration Notes

## Repository Discovery Summary

Detected teammate modules:

- `Essam/agent_loop.py` — core loop
- `mazen/adapter.py` — `BackendAdapter.send(messages, tools)`
- `omar/tools.py` — `GatedTools` (`run_shell`, `http_request`, `read_file`, `write_file`)
- `sherif/coverage.py` — coverage DB functions
- `kero/*.md` — recon skill playbooks
- `rana/Recon.ipynb` + `rana/recon_tools.py` — recon wrapper design

## Role Mapping vs Repository Layout

Project role labels and folder ownership differ in this repository:

| Role Label | Expected | Found In Repo |
|------------|----------|---------------|
| Omar Backend | backend adapter | `mazen/adapter.py` (primary) |
| Mazen Execution | gated tools | `omar/tools.py` (primary) |

Haitham adapters auto-discover implementations and do not rewrite teammate modules.

## Adapter Contracts

### SkillLoader

- Input: `kero/` directory
- Output: `{skill_key: markdown_content}`

### ToolAdapter

- Input: `execute(tool_name, arguments)`
- Output: normalized dict `{ok, tool, result|error}`

### CoverageAdapter

- Input: loop-compatible `mark_tested(item)`, `get_untested()`
- Output: normalized list of untested endpoint labels

### BackendAdapterWrapper

- Input: `send(messages, tools)`
- Output: normalized assistant payload with `tool_calls`

## Import Strategy

Teammate modules are loaded with:

- `sys.path` insertion for `omar/` local imports
- `importlib` file loading for `sherif/` and backend adapter discovery

This avoids editing teammate package structure.

## Non-Goals

- No modification of teammate folders
- No replacement of Essam loop logic
- No bypass of permission gate/blocklist protections

## Validation Checklist

- Skills count > 0
- At least one successful gated tool call
- Coverage DB updated
- Agent loop completes with `status=completed`
- Artifacts written under `Haitham/outputs/` and `Haitham/logs/`
