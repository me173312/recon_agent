# Phase 3 — Live Host Probing

## Goal

Determine which of the discovered subdomains (from Phases 1–2) actually resolve
to live web servers. Collect HTTP metadata (status codes, page titles,
technologies, content length) for each live host.

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `httpx` (ProjectDiscovery) |
| **Wrapper function** | `run_httpx(hosts, target)` |
| **Binary path** | Resolved via `pd_bin("httpx")` (GOBIN lookup — **not** the Python `httpx` package) |

## How It Works

HTTPX probes each hostname over HTTP and HTTPS, sends a HEAD/GET request, and
reports the response metadata. It uses concurrent connections for speed.

> **Critical**: The Go binary `httpx` from ProjectDiscovery must be used, **not**
> the Python `httpx` pip package. The wrapper resolves this via `pd_bin("httpx")`
> which checks GOBIN specifically.

## Command Constructed by Wrapper

```bash
echo "<hosts>" | httpx -silent -json -status-code -title -tech-detect -content-length
```

| Flag | Purpose |
|------|---------|
| `-silent` | Suppress banner |
| `-json` | One JSON object per live host |
| `-status-code` | Include HTTP status code |
| `-title` | Include HTML `<title>` tag content |
| `-tech-detect` | Fingerprint technologies (e.g. nginx, WordPress, PHP) |
| `-content-length` | Include response body size |
| *(stdin)* | Hostnames piped in, one per line |

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `hosts` | `List[str]` | Merged list of subdomains + permutations from Phases 1–2 |
| `target` | `str` | Original target domain (for metadata) |

**Safety cap**: If `hosts` exceeds 2,000 entries, the wrapper truncates to the
first 2,000 to prevent excessive probing time.

**Edge case**: If `hosts` is empty, the wrapper skips execution and returns a
valid `HttpxResult` with `live_hosts=[]`.

## Expected Output

The wrapper returns an **`HttpxResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "httpx",
    "target": "example.com",
    "command_used": "httpx -silent -json -status-code -title -tech-detect -content-length",
    "execution_time_seconds": 45.67,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "live_hosts": [
    {
      "url": "https://www.example.com",
      "status_code": 200,
      "title": "Example Domain",
      "tech": ["nginx", "PHP"],
      "content_length": 12345
    }
  ],
  "total_live_hosts": 1
}
```

**Key fields the agent should use downstream:**
- `live_hosts[].url` → feed into Phases 4, 5, 7, and 8
- `live_hosts[].tech` → useful context for vulnerability scanning (Phase 8)
- `total_live_hosts` → log for coverage tracking

## Output File

`outputs/json/httpx.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `live_hosts` contains only verified live hosts (each with a valid URL).
3. `outputs/json/httpx.json` exists and is valid JSON.
4. The live URL list is extracted and ready for downstream phases.

## Extracting Live URLs for Downstream Use

After this phase, extract the URL list for subsequent tools:

```python
live_urls = [host.url for host in httpx_result.live_hosts]
```

## Error Handling

- Timeout is set to 600 seconds (10 minutes) for large host lists. If it
  times out, partial results in stdout should still be parsed.
- If zero live hosts are found, this is **not** an error — it means no
  subdomains resolved to web servers. Phases 4, 5, 7 are skipped; Phases 6
  and 8 can still run on the base target.

## Next Phase

Extract `live_urls` from `live_hosts`, then pass to:
- **Phase 4: Port Scanning** (`run_naabu`) — needs hostnames
- **Phase 5: Web Crawling** (`run_katana`) — needs URLs
- **Phase 7: Directory Fuzzing** (`run_ffuf`) — needs first live URL
- **Phase 8: Vulnerability Scanning** (`run_nuclei`) — needs URLs
