# Phase 6 — URL Harvesting (Web Archives)

## Goal

Collect historically known URLs for the target from web archives and passive
sources (Wayback Machine, Common Crawl, AlienVault OTX, URLScan). This surfaces
endpoints that may no longer be linked from the live site but are still reachable
— including forgotten admin panels, debug endpoints, and old API versions.

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `gau` (Get All URLs) |
| **Wrapper function** | `run_gau(hostname)` |
| **Binary path** | Resolved via `pd_bin("gau")` (GOBIN lookup) |

## How It Works

GAU queries multiple public URL archive services in parallel and collects every
URL ever seen for the target domain. It includes subdomains by default via the
`--subs` flag.

## Command Constructed by Wrapper

```bash
gau --subs <hostname>
```

| Flag | Purpose |
|------|---------|
| `--subs` | Include URLs for all subdomains, not just the apex domain |
| `<hostname>` | The target domain (positional argument) |

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `hostname` | `str` | The target domain, e.g. `"example.com"` |

**Note**: This phase runs independently — it takes the original target domain
directly, not output from previous phases. It can run in parallel with Phases 4–5.

## Expected Output

The wrapper returns a **`GauResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "gau",
    "target": "example.com",
    "command_used": "gau --subs example.com",
    "execution_time_seconds": 18.76,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "urls": [
    "https://www.example.com/old-admin/",
    "https://api.example.com/v1/debug",
    "https://example.com/backup.sql"
  ],
  "total_urls": 3
}
```

**Key fields the agent should use downstream:**
- `urls` → merge with katana endpoints for comprehensive nuclei scanning
- `total_urls` → log for coverage tracking (can be very large — 10,000+ is common)

## Output File

`outputs/json/gau.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `urls` is a deduplicated, sorted list of URLs (all starting with `http`).
3. `outputs/json/gau.json` exists and is valid JSON.
4. Results logged to coverage tracker.

## Crash Safety

The wrapper includes a **catch-all exception handler** that guarantees
`outputs/json/gau.json` is always written, even if an unexpected error occurs.
This prevents downstream phases from encountering a missing file. If an exception
is caught:
- `metadata.success` = `false`
- `metadata.errors` contains the exception details
- `urls` = `[]`

## Error Handling

- GAU depends on external archive services. If any source is temporarily
  unavailable, GAU still returns results from other sources.
- Network timeouts are the most common failure mode. The default command timeout
  (100s) is usually sufficient.
- Zero URLs is possible for very new or obscure domains — not an error.

## Next Phase

Proceed to → **Phase 7: Directory Fuzzing** (`run_ffuf`) using the first live URL.
Then merge all discovered URLs (live, crawled, archived) for →
**Phase 8: Vulnerability Scanning** (`run_nuclei`).
