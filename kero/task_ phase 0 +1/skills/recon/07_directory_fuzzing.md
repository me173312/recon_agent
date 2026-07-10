# Phase 7 — Directory Fuzzing

## Goal

Discover hidden directories and files on the target web server by brute-forcing
common paths. This finds resources not linked from the site and not present in
web archives — such as admin panels, backup files, configuration files, and
development endpoints.

## Tool

| Field | Value |
|-------|-------|
| **Tool** | `ffuf` (Fuzz Faster U Fool) |
| **Wrapper function** | `run_ffuf(base_url, target)` |
| **Binary path** | Resolved via `pd_bin("ffuf")` (GOBIN lookup) |

## How It Works

FFUF replaces the `FUZZ` keyword in the URL with each word from a wordlist,
sends HTTP requests, and reports matches based on status code filters.

## Command Constructed by Wrapper

```bash
ffuf -u <base_url>/FUZZ -w <wordlist> -mc 200,201,301,302,403 -t 20 -o <output_file> -of json -s
```

| Flag | Purpose |
|------|---------|
| `-u <url>/FUZZ` | Target URL with `FUZZ` keyword replaced by each wordlist entry |
| `-w <wordlist>` | Path to the wordlist file |
| `-mc 200,201,301,302,403` | Match only these HTTP status codes |
| `-t 20` | Use 20 concurrent threads |
| `-o <file>` | Write results to `config/ffuf_output.json` |
| `-of json` | Output format is JSON |
| `-s` | Silent mode — no progress output |

## Wordlist Selection

The wrapper tries these wordlists in order:

1. `/usr/share/wordlists/dirb/common.txt`
2. `/usr/share/seclists/Discovery/Web-Content/common.txt`
3. `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`

If none exist (e.g. in a minimal environment like Google Colab), a **fallback
wordlist** is auto-generated at `config/ffuf_wordlist.txt` containing ~40 common
directory names (admin, api, backup, login, uploads, etc.).

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `base_url` | `str` | The first live URL from Phase 3 (e.g. `"https://www.example.com"`) |
| `target` | `str` | Original target domain (for metadata) |

**Note**: The wrapper runs against a **single** base URL. If multiple live hosts
were found, the agent should call `run_ffuf()` once per host — or at minimum
against the primary host.

## Expected Output

The wrapper returns a **`FfufResult`** Pydantic model:

```json
{
  "metadata": {
    "tool_name": "ffuf",
    "target": "example.com",
    "command_used": "ffuf -u https://www.example.com/FUZZ -w ... -mc 200,201,301,302,403 -t 20 -o config/ffuf_output.json -of json -s",
    "execution_time_seconds": 15.82,
    "timestamp": "2026-07-07T00:00:00+00:00",
    "success": true,
    "errors": [],
    "raw_output": "..."
  },
  "matches": [
    {
      "url": "https://www.example.com/admin",
      "status_code": 403,
      "content_length": 287,
      "words": 21,
      "lines": 10
    },
    {
      "url": "https://www.example.com/api",
      "status_code": 200,
      "content_length": 1452,
      "words": 87,
      "lines": 35
    }
  ],
  "total_matches": 2
}
```

**Key fields the agent should use downstream:**
- `matches[].url` → add to nuclei target list for vulnerability scanning
- `matches[].status_code` → 403 Forbidden results are interesting (may be bypassable)
- `total_matches` → log for coverage tracking

## Output File

`outputs/json/ffuf.json`

## Intermediate File

`config/ffuf_output.json` — raw ffuf JSON output (parsed by the wrapper).

## Definition of Done

All of the following must be true:

1. `metadata.success` is `true`.
2. `matches` contains discovered directories/files with status codes.
3. `outputs/json/ffuf.json` exists and is valid JSON.
4. Results logged to coverage tracker.

## Error Handling

- Timeout is set to 120 seconds. Large wordlists may need more time.
- If the ffuf output file doesn't exist after execution, the wrapper returns
  `matches=[]` — this typically means the target rejected all requests.
- Common false positives: custom 404 pages returning 200. Check `content_length`
  — if many matches have identical content lengths, they are likely soft-404s.

## Next Phase

Collect all discovered URLs from:
- Phase 3 (`live_urls`)
- Phase 5 (`katana_result.endpoints[].url`)
- Phase 6 (`gau_result.urls`)
- Phase 7 (`ffuf_result.matches[].url`)

Merge, deduplicate, and pass to → **Phase 8: Vulnerability Scanning** (`run_nuclei`).
