# Phase 1 — Subdomain Enumeration

## Goal

Discover all publicly known subdomains of the target domain. This is the
foundational phase — every subsequent phase depends on its output.

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `subfinder` (ProjectDiscovery) |
| **Wrapper function** | `run_subfinder(target, is_wildcard=False)` |
| **Binary path** | Resolved via `pd_bin("subfinder")` (GOBIN lookup) |

## How It Works

Subfinder queries passive sources (certificate transparency logs, search engines,
DNS datasets, public APIs) to collect subdomains. It does **not** send traffic to
the target — it is entirely passive.

## Command Constructed by Wrapper

```bash
subfinder -d <domain> -silent -json
```

| Flag | Purpose |
|------|---------|
| `-d <domain>` | Target domain (wildcard prefix `*.` is stripped automatically) |
| `-silent` | Suppress banner and status messages — output only results |
| `-json` | Emit one JSON object per line (enables structured parsing) |

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | `str` | The target domain, e.g. `"example.com"` or `"*.example.com"` |
| `is_wildcard` | `bool` | If `True`, the `*.` prefix is stripped before passing to subfinder |

## Expected Output

The wrapper returns a **`SubfinderResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "subfinder",
    "target": "example.com",
    "command_used": "subfinder -d example.com -silent -json",
    "execution_time_seconds": 12.34,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "mail.example.com"
  ],
  "total_subdomains": 3
}
```

**Key fields the agent should use downstream:**
- `subdomains` → feed into Phase 2 (alterx) and Phase 3 (httpx)
- `total_subdomains` → log for coverage tracking
- `metadata.success` → decide whether to proceed or retry

## Output File

`outputs/json/subfinder.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `subdomains` is a non-empty, deduplicated, sorted list.
3. `outputs/json/subfinder.json` exists and is valid JSON.
4. The subdomain list has been passed to the coverage tracker via `mark_tested()`.

## Error Handling

- If subfinder returns zero subdomains for a valid domain, this is **not** an
  error — it means no passive sources had data. Log it and continue; the agent
  can still proceed with the base domain through httpx.
- If `metadata.success` is `false`, check `metadata.errors` for the reason.
  Common causes: network timeout, rate limiting by upstream APIs.

## Next Phase

Pass `subdomains` to → **Phase 2: Subdomain Permutation** (`run_alterx`)
and also directly to → **Phase 3: Live Host Probing** (`run_httpx`).
