# AI Recon Agent

AI Recon Agent is an eight-phase reconnaissance automation project. It can run a safe demo, or run real recon against an authorized target and save separated output files per domain.

Only scan assets you own or have explicit permission to test.

## Folder Layout

```text
ai-recon-agent/
  Adapter/             Backend adapter source
  Essam/               Core agent loop and multi-tool phase runner
  Haitham/             Integration entry point, config, demo runner, docs
  kero/                Recon skill/playbook markdown files
  Mazen/               Adapter deliverables
  omar/                Permission gate and gated tool execution
  Sherif/              Coverage tracker and SQLite schema
  recon_agent.py       Main CLI command
  recon_pipeline.py    Real 8-phase recon pipeline
  recon_tools.py       Tool wrappers and built-in fallbacks
```

## 1. Clone The Repo

Windows PowerShell:

```powershell
git clone https://github.com/YOUR_USERNAME/ai-recon-agent.git
cd ai-recon-agent
```

Linux/macOS:

```bash
git clone https://github.com/YOUR_USERNAME/ai-recon-agent.git
cd ai-recon-agent
```

## 2. Create Python Environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Configure Environment

Copy the example config.

Windows PowerShell:

```powershell
copy Haitham\.env.example Haitham\.env
```

Linux/macOS:

```bash
cp Haitham/.env.example Haitham/.env
```

Edit `Haitham/.env`.

For safe demo mode:

```env
API_KEY=
MODEL=gpt-4o-mini
BASE_URL=https://api.openai.com/v1
OFFLINE_DEMO=true
```

For live mode:

```env
API_KEY=your_openai_api_key_here
MODEL=gpt-4o-mini
BASE_URL=https://api.openai.com/v1
OFFLINE_DEMO=false
```

Do not commit `Haitham/.env`. It is ignored by `.gitignore`.

## 4. Run Safe Demo

Use this first to make sure the project works.

```powershell
python recon_agent.py --demo
```

Expected result:

```text
Haitham integration demo completed successfully.
```

## 5. Run Real Recon

Run this only against an authorized target:

```powershell
python recon_agent.py --target example.com --authorized
```

Replace `example.com` with your target domain:

```powershell
python recon_agent.py --target yourdomain.com --authorized
```

The `--authorized` flag is required as a safety confirmation.

## 6. Output Files

Each scan creates a folder named after the target:

```text
Haitham/outputs/example.com/
```

Important files:

```text
summary.txt
summary.json
subdomains.txt
subdomains.json
candidates.txt
candidates.json
live_hosts.txt
live_hosts.json
open_ports.txt
open_ports.json
endpoints.txt
endpoints.json
archived_urls.txt
archived_urls.json
found_paths.txt
found_paths.json
findings.txt
findings.json
errors.txt
errors.json
phase_results.json
full_report.json
full_report_<timestamp>.json
```

The latest full report is also copied to:

```text
Haitham/outputs/recon_latest.json
```

Runtime outputs, logs, databases, virtual environments, and `.env` files are ignored by Git.

## 7. Optional External Recon Tools

The agent has built-in fallbacks, but real results are much better if these tools are installed and available on `PATH`:

```text
subfinder
amass
assetfinder
alterx
dnsx
httpx
naabu
nmap
masscan
katana
gau
waybackurls
ffuf
feroxbuster
gobuster
nuclei
```

Common Go installs:

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

On Windows, make sure this is on `PATH`:

```powershell
$env:Path += ";$env:USERPROFILE\go\bin"
```

## 8. Understanding Status

`completed` means all phases produced usable results without recorded errors.

`completed_with_errors` usually means some external tools were missing or returned no data. The agent still writes all available output and fallback results.

Check:

```text
Haitham/outputs/<target>/errors.txt
Haitham/outputs/<target>/errors.json
```

## 9. Common Commands

Show help:

```powershell
python recon_agent.py --help
```

Run demo:

```powershell
python recon_agent.py --demo
```

Run real recon:

```powershell
python recon_agent.py --target example.com --authorized
```

Open latest report:

```powershell
notepad Haitham\outputs\recon_latest.json
```

## 10. Troubleshooting

If Python packages fail:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

If a tool is missing:

```powershell
where subfinder
where nuclei
where ffuf
```

Linux/macOS:

```bash
which subfinder
which nuclei
which ffuf
```

If recon returns weak results, install more external tools and rerun.

If the API fails, check:

```text
Haitham/.env
```

Make sure `API_KEY` is set and `OFFLINE_DEMO=false`.

## 11. Extra Documentation

See `Haitham/README.md` for deeper integration notes, dependency details, phase schemas, merge/fallback behavior, coverage tracking, permissions, and troubleshooting.
