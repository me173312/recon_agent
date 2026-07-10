# Phase 5 — Web Crawling

## Goal

Crawl live web hosts to discover endpoints, URLs, API routes, JavaScript files,
and forms. This expands the attack surface beyond what passive enumeration found.

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `katana` (ProjectDiscovery) |
| **Wrapper function** | `run_katana(urls, target)` |
| **Binary path** | Resolved via `pd_bin("katana")` (GOBIN lookup) |

## How It Works

Katana is a web crawler that follows links, parses JavaScript, and extracts
endpoints from web pages. It respects depth limits to prevent unbounded crawling.

## Command Constructed by Wrapper

```bash
katana -list <url_file> -silent -depth 2
```

| Flag | Purpose |
|------|---------|
| `-list <file>` | Read target URLs from file (**not stdin** — katana is unreliable with stdin) |
| `-silent` | Suppress banner and progress output |
| `-depth 2` | Crawl up to 2 levels deep from each starting URL |

> **Important**: The wrapper writes URLs to `config/katana_targets.txt` and uses
> `-list` instead of piping via stdin. This is a deliberate fix — katana's stdin
> handling is unreliable and caused silent failures in earlier versions.

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `urls` | `List[str]` | Live URLs from Phase 3 (`httpx_result.live_hosts[].url`) |
| `target` | `str` | Original target domain (for metadata) |

**Edge case**: If `urls` is empty, the wrapper skips execution and returns a
valid `KatanaResult` with `endpoints=[]`.

## Expected Output

The wrapper returns a **`KatanaResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "katana",
    "target": "example.com",
    "command_used": "katana -list config/katana_targets.txt -silent -depth 2",
    "execution_time_seconds": 34.21,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "endpoints": [
    {
      "url": "https://www.example.com/api/v1/users",
      "method": "GET",
      "source": "https://www.example.com/"
    },
    {
      "url": "https://www.example.com/login",
      "method": "POST",
      "source": "https://www.example.com/js/app.js"
    }
  ],
  "total_endpoints": 2
}
```

**Key fields the agent should use downstream:**
- `endpoints[].url` → merge with gau URLs for comprehensive vulnerability scanning
- `endpoints[].method` → useful context (POST endpoints may accept user input)
- `total_endpoints` → log for coverage tracking

## Output File

`outputs/json/katana.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true` (determined by return code 0 **or** endpoints found).
2. `endpoints` contains discovered URL/method/source entries.
3. `outputs/json/katana.json` exists and is valid JSON.
4. Results logged to coverage tracker.

## Success Logic Note

The wrapper uses relaxed success logic: the phase is considered successful if
**either** the return code is 0 **or** at least one endpoint was parsed from the
output. This handles cases where katana exits with a non-zero code due to
connection errors on some URLs but still produced valid output for others.

## Error Handling

- Default timeout is 100 seconds. For large target lists, some URLs may time out
  individually — katana handles this internally.
- If katana produces mixed JSON and plain-text output, the parser handles both:
  JSON lines are parsed for `request.endpoint` / `request.method`, plain-text
  lines starting with `http` are added as GET endpoints.

## Next Phase

Proceed to → **Phase 6: URL Harvesting** (`run_gau`) for archived URLs, then
merge crawled + archived URLs for vulnerability scanning.
