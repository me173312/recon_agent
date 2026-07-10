# Phase 2 — Subdomain Permutation

## Goal

Generate plausible subdomain variations from the subdomains discovered in Phase 1.
This expands the attack surface by finding subdomains that passive enumeration
missed (e.g. `staging-api.example.com`, `dev.mail.example.com`).

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `alterx` (ProjectDiscovery) |
| **Wrapper function** | `run_alterx(subdomains, target)` |
| **Binary path** | Resolved via `pd_bin("alterx")` (GOBIN lookup) |

## How It Works

AlterX takes a list of known subdomains and applies pattern-based permutation
rules (prefix, suffix, word swap, number increment) to generate candidate
hostnames that might also exist. The output is fed into httpx for live-host
verification.

## Command Constructed by Wrapper

```bash
echo "<subdomains>" | alterx -silent
```

| Flag | Purpose |
|------|---------|
| `-silent` | Suppress banner — output only generated permutations |
| *(stdin)* | Subdomains piped in, one per line |

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `subdomains` | `List[str]` | Subdomain list from Phase 1 (`subfinder_result.subdomains`) |
| `target` | `str` | Original target domain (for metadata) |

**Edge case**: If `subdomains` is empty, the wrapper skips execution entirely and
returns a valid `AlterxResult` with `permutations=[]` and `success=True`. This is
correct behavior — there is nothing to permute.

## Expected Output

The wrapper returns an **`AlterxResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "alterx",
    "target": "example.com",
    "command_used": "alterx -silent",
    "execution_time_seconds": 2.15,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "permutations": [
    "dev-www.example.com",
    "staging-api.example.com",
    "api2.example.com"
  ],
  "total_permutations": 3
}
```

**Key fields the agent should use downstream:**
- `permutations` → merge with original `subdomains` then feed into Phase 3 (httpx)
- `total_permutations` → log for coverage tracking

## Output File

`outputs/json/alterx.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `permutations` is a deduplicated, sorted list (may be empty if input was empty).
3. `outputs/json/alterx.json` exists and is valid JSON.
4. The merged list (`subdomains + permutations`) is ready for Phase 3.

## Important Notes

- AlterX can produce **thousands of permutations** (10,000+ is common). The httpx
  wrapper in Phase 3 caps input to 2,000 hosts to avoid excessive probing.
- Permutations are **unverified** — most will not resolve. That is expected; the
  purpose is breadth. Phase 3 filters down to only live hosts.

## Error Handling

- If alterx exits non-zero but still produces output lines, treat it as a partial
  success — collect whatever permutations were generated.
- If no output at all and the exit code is non-zero, log the error and proceed to
  Phase 3 using only the original subfinder subdomains.

## Next Phase

Merge `subdomains` (Phase 1) + `permutations` (Phase 2), then pass to →
**Phase 3: Live Host Probing** (`run_httpx`).
