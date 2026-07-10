# Phase 4 — Port Scanning

## Goal

Identify open TCP ports on live hosts discovered in Phase 3. This reveals
services running beyond standard HTTP/HTTPS (e.g. SSH on 22, database on 3306,
custom APIs on non-standard ports).

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `naabu` (ProjectDiscovery) |
| **Wrapper function** | `run_naabu(hosts, target)` |
| **Binary path** | Resolved via `pd_bin("naabu")` (GOBIN lookup) |

## How It Works

Naabu is a fast port scanner. In the wrapper's configuration, it runs in
**passive mode** (`-passive`), which uses Shodan InternetDB as the data source
instead of sending SYN packets directly. This avoids triggering intrusion
detection systems and works even without root privileges.

## Command Constructed by Wrapper

```bash
echo "<hosts>" | naabu -silent -json -passive
```

| Flag | Purpose |
|------|---------|
| `-silent` | Suppress banner and progress output |
| `-json` | One JSON object per host:port finding |
| `-passive` | Use passive data sources (Shodan InternetDB) — no active SYN scanning |
| *(stdin)* | Hostnames piped in, one per line |

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `hosts` | `List[str]` | Hostnames extracted from live URLs (Phase 3). Extract with `urlparse(url).hostname` |
| `target` | `str` | Original target domain (for metadata) |

**Edge case**: If `hosts` is empty, the wrapper skips execution and returns a
valid `NaabuResult` with `open_ports=[]`.

## Preparing Input from Phase 3

The httpx output contains full URLs. Naabu needs bare hostnames:

```python
from urllib.parse import urlparse

live_hosts = [
    urlparse(url).hostname
    for url in live_urls
    if urlparse(url).hostname
]
```

## Expected Output

The wrapper returns a **`NaabuResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "naabu",
    "target": "example.com",
    "command_used": "naabu -silent -json -passive",
    "execution_time_seconds": 8.42,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "open_ports": [
    { "host": "www.example.com", "port": 80, "protocol": "tcp" },
    { "host": "www.example.com", "port": 443, "protocol": "tcp" },
    { "host": "api.example.com", "port": 8080, "protocol": "tcp" }
  ],
  "total_ports_found": 3
}
```

**Key fields the agent should use downstream:**
- `open_ports` → context for vulnerability scanning; non-standard ports may host additional services
- `total_ports_found` → log for coverage tracking

## Output File

`outputs/json/naabu.json`

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `open_ports` lists all discovered host:port combinations.
3. `outputs/json/naabu.json` exists and is valid JSON.
4. Results logged to coverage tracker.

## Error Handling

- Passive mode depends on Shodan InternetDB availability. If the API is
  unreachable, naabu may return zero results — this is not a fatal error.
- The fallback raw output parser handles `host:port` plain-text lines if JSON
  parsing fails.

## Next Phase

Port scan results provide context but do not directly feed into subsequent tools.
Proceed to → **Phase 5: Web Crawling** (`run_katana`) using `live_urls` from
Phase 3.
