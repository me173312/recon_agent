# AI Recon Agent - Integration Guide

This package wires the AI Recon Agent modules into one runnable system. It supports an eight-phase recon workflow where each phase can use four interchangeable wrapper tools. Wrapper functions are owned by the wrapper layer and must return the normalized JSON schemas documented below.

## Project Architecture

```text
User goal
  -> Haitham main.py / demo runner
  -> Essam AgentLoop and run_phase()
  -> Kero phase skills
  -> Rana recon wrapper functions
  -> Omar/Mazen permission gate and backend adapter
  -> Sherif coverage tracker
  -> JSON artifacts, logs, and SQLite coverage
```

Responsibilities:

* Essam: core agent loop, configurable phase execution, merge/fallback orchestration.
* Sherif: SQLite coverage state, tested endpoint deduplication, tool-used tracking.
* Haitham: integration entry point, setup docs, troubleshooting, final demo wiring.
* Wrapper owner: `recon_tools.py` wrapper functions that call real tools and return normalized JSON.

## Installation

Create a Python environment first:

```bash
cd haitham/Haitham
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Linux/macOS use:

```bash
source .venv/bin/activate
```

## Go Tools

ProjectDiscovery and several recon tools are installed with Go. Install Go 1.22+ and ensure `GOBIN` or `GOPATH/bin` is on `PATH`.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
```

Validate:

```bash
subfinder -version
httpx -version
naabu -version
katana -version
nuclei -version
alterx -version
gau --version
ffuf -V
```

## Python Tools

Install Python package dependencies from `requirements.txt`. Wrapper authors may add Python-only scanners or parsers there. Keep Python HTTP libraries separate from Go binaries with the same name; for example, ProjectDiscovery `httpx` is a Go binary, not the Python `httpx` package.

```bash
pip install -r requirements.txt
```

## APT Tools

On Debian/Ubuntu/Kali, install OS-level scanners and support packages:

```bash
sudo apt update
sudo apt install -y nmap masscan dnsutils jq curl git ca-certificates
sudo apt install -y seclists wordlists
```

Optional tools often used by wrapper alternatives:

```bash
sudo apt install -y gobuster dirb whatweb wafw00f
```

## GitHub Binary Releases

Some tools are easier to install from GitHub releases when Go or APT packages are unavailable. Download the release for your OS/architecture, extract it, move the binary into a directory on `PATH`, and verify the version.

Recommended process:

```bash
mkdir -p ~/tools/bin
# extract downloaded binary into ~/tools/bin
export PATH="$HOME/tools/bin:$PATH"
tool-name --version
```

Pin versions in production images so scans are reproducible.

## Setup

Create an environment file:

```bash
copy .env.example .env
```

Set:

* `OFFLINE_DEMO=true` for deterministic local demo mode.
* `API_KEY`, `BASE_URL`, and `MODEL` for live model-backed mode.
* `MAX_STEPS` and `MAX_TOOL_CALLS` to prevent runaway agent loops.
* `COVERAGE_TARGET` to choose the SQLite target namespace.

Initialize coverage automatically by importing Sherif's module or running the integration:

```bash
python main.py
```

## Running The Agent

Run the safe integrated demo:

```bash
python ../recon_agent.py --demo
```

Run real recon against an authorized target:

```bash
python ../recon_agent.py --target example.com --authorized
```

Run the explicit demo runner:

```bash
python demo/demo_runner.py
```

Expected artifacts:

* `outputs/integration_demo_result.json`
* `outputs/recon_latest.json`
* `outputs/<target>/summary.txt`
* `outputs/<target>/subdomains.txt`
* `outputs/<target>/endpoints.txt`
* `outputs/<target>/findings.txt`
* `outputs/<target>/full_report.json`
* `outputs/demo_runner_result.json`
* `logs/integration.log`
* `logs/tool_gate.log`
* `Sherif/coverage/coverage.db`

## Wrapper Architecture

Wrappers live outside this deliverable. They should expose one callable per tool and return normalized dictionaries. The phase runner accepts:

* a bare callable, such as `run_subfinder`
* a mapping, such as `{"name": "subfinder", "function": run_subfinder}`
* an object with a `run()` method

Wrappers should not leak tool-specific output shapes into the agent. Parse stdout/stderr, normalize fields, and set `tool` to the producing tool name.

## Normalized Schemas

Phase 1 - subdomain enumeration:

```json
{"tool": "subfinder", "subdomains": ["api.example.com"]}
```

Phase 2 - permutation:

```json
{"tool": "alterx", "candidates": ["dev-api.example.com"]}
```

Phase 3 - DNS/live host resolution:

```json
{"tool": "httpx", "live_hosts": [{"host": "https://api.example.com", "status": "200", "title": "API"}]}
```

Phase 4 - port scan:

```json
{"tool": "naabu", "open_ports": [{"port": 443, "service": "https"}]}
```

Phase 5 - crawl:

```json
{"tool": "katana", "urls": ["https://api.example.com/v1/users"]}
```

Phase 6 - historical URLs:

```json
{"tool": "gau", "archived_urls": ["https://example.com/old"]}
```

Phase 7 - fuzzing:

```json
{"tool": "ffuf", "found_paths": [{"path": "/admin", "status": 403}]}
```

Phase 8 - vulnerability scan:

```json
{"tool": "nuclei", "findings": [{"severity": "high", "name": "Example Finding", "detail": "Matched template output"}]}
```

## Phase Execution Modes

Essam's `PHASE_MODES` config controls execution:

```python
PHASE_MODES = {
    "subdomain_enum": "merge",
    "permutation": "fallback",
    "dns_resolution": "fallback",
    "port_scan": "fallback",
    "crawl": "fallback",
    "historical_urls": "merge",
    "fuzzing": "fallback",
    "vulnerability_scan": "fallback",
}
```

### Merge Mode

Merge mode runs every configured tool for the phase, keeps successful non-empty outputs, deduplicates records, and returns one normalized result. It is best for passive collection phases where multiple tools add coverage, such as subdomain enumeration and historical URL discovery.

### Fallback Mode

Fallback mode runs tools in priority order. The first successful non-empty normalized result is returned. If a tool fails or returns no records, the next tool is attempted. It is best for expensive or intrusive phases where one good tool result is enough.

## Coverage Tracking

Sherif's coverage module stores tool-aware tested records.

Canonical schema:

```text
coverage(
  endpoint,
  parameter,
  vulnerability_class,
  tool_used,
  tested_status
)
```

Uniqueness is defined by:

```text
(endpoint, parameter, vulnerability_class)
```

`tool_used` is stored as a JSON list. Re-reporting the same endpoint with the same tool does not create duplicates. Reporting it later with another tool appends that tool.

Example:

```python
mark_tested("example.com", "/login", "username", "xss", "ffuf")
mark_tested("example.com", "/login", "username", "xss", "feroxbuster")
```

Stored `tool_used`:

```json
["ffuf", "feroxbuster"]
```

## Required Permissions

Only run active scanning against systems you own or are explicitly authorized to test. Several tools send high-volume traffic or raw packets.

`masscan` requires raw packet privileges. Run with root, Linux capabilities, or a container capability:

```bash
sudo masscan 192.0.2.0/24 -p80,443
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v masscan)"
```

`nmap` SYN scans (`-sS`) require raw packet privileges:

```bash
sudo nmap -sS -p80,443 example.com
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service=eip "$(command -v nmap)"
```

In Docker, grant only the capabilities needed:

```bash
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN recon-agent:latest
```

If SYN scans are not permitted, use TCP connect scans (`nmap -sT`) with the expected performance tradeoff.

## Troubleshooting

Tool not found:

* Confirm the binary is on `PATH`.
* Check `go env GOPATH` and add `$GOPATH/bin` or `%USERPROFILE%\go\bin`.
* Run the tool version command directly before running the agent.

Permission denied for `masscan`, `naabu`, or `nmap -sS`:

* Use `sudo` for a quick validation.
* Prefer `setcap` on Linux production hosts.
* Add Docker `NET_RAW` and `NET_ADMIN` capabilities when containerized.

Empty phase output:

* In fallback mode, the next configured tool should run automatically.
* In merge mode, empty outputs are ignored and successful tools are merged.
* Check wrapper logs for parsing errors or unexpected tool output changes.

Coverage rows not updating:

* Run `python -m py_compile Sherif/coverage/coverage.py` to catch syntax issues.
* Confirm `coverage.db` is writable.
* Check that wrappers pass `tool_used` when calling `mark_tested()`.

Offline demo does not call live tools:

* Set `OFFLINE_DEMO=false`.
* Provide `API_KEY`, `BASE_URL`, and `MODEL`.
* Ensure permission-gate prompts are configured for non-interactive execution if running in CI.

## Documentation

Additional project notes:

* `docs/architecture.md`
* `docs/integration_notes.md`
* `docs/deployment_guide.md`
* `docs/troubleshooting.md`
