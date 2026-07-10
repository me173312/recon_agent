# Troubleshooting

## `API_KEY is required unless OFFLINE_DEMO=true`

Cause: live mode enabled without API key.

Fix:

- set `OFFLINE_DEMO=true` in `Haitham/.env`, or
- provide valid `API_KEY`.

## `No BackendAdapter implementation found`

Cause: teammate backend files missing or moved.

Fix:

- verify `mazen/adapter.py` or `Essam/Adapter/adapter.py` exists at repository root.

## `ModuleNotFoundError: permission_gate` or `tools`

Cause: `omar/` folder missing or not reachable.

Fix:

- run commands from `Haitham/` with full repository present.
- confirm `omar/permission_gate.py` and `omar/tools.py` exist.

## Tool call denied (`PermissionDenied`)

Cause: auto-allow disabled or blocklist match.

Fix:

- keep demo mode auto-allow enabled in `ToolAdapter(auto_allow=True)`.
- avoid blocked commands (`rm -rf`, sensitive paths).

## `ModuleNotFoundError: openai`

Cause: dependencies not installed.

Fix:

```bash
pip install -r requirements.txt
```

## No skills loaded

Cause: `kero/` directory missing.

Fix:

- ensure repository includes Kero markdown skills at `../kero`.

## No output artifacts

Cause: run failed before save step.

Fix:

- inspect `Haitham/logs/integration.log`
- rerun `python main.py` after fixing config/dependency issues.

## Permission gate log looks corrupted

Cause: prior interrupted writes in shared log file.

Fix:

- inspect latest JSONL lines in `Haitham/logs/tool_gate.log`
- rerun demo to append fresh entries.
