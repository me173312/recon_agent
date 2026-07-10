# Deployment Guide

## Fresh Installation

1. Clone or copy the full repository (all teammate folders required).
2. Open terminal at repository root.
3. Enter Haitham deliverable folder:

```bash
cd Haitham
```

4. Create virtual environment:

```bash
python -m venv .venv
```

5. Activate environment:

```bash
.venv\Scripts\activate
```

6. Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment Setup

1. Copy template:

```bash
copy .env.example .env
```

2. Configure mode:

- Classroom/demo (no API key):
  - `OFFLINE_DEMO=true`
- Live model mode:
  - `OFFLINE_DEMO=false`
  - `API_KEY=<your-key>`
  - `BASE_URL=https://api.openai.com/v1`
  - `MODEL=gpt-4o-mini`

## Running the Demo

### Full integration entrypoint

```bash
python main.py
```

### Explicit demo runner

```bash
python demo/demo_runner.py
```

## Expected Artifacts

After successful run:

- `Haitham/outputs/integration_demo_result.json`
- `Haitham/logs/integration.log`
- `Haitham/logs/tool_gate.log`
- `sherif/coverage.db`

## Submission Packaging

Upload the `Haitham/` folder to Google Drive including:

- source files
- docs
- demo assets
- generated `outputs/` and `logs/` from a successful run

## Clean Machine Requirements

- Python 3.11+
- Internet access (for live backend mode and pip install)
- Windows/Linux/macOS shell

No absolute path configuration is required.
