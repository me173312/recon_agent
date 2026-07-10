# Recon Skill Pack — Index

> **Purpose**: This directory contains the AI agent's operating instructions for
> automated reconnaissance. Each file describes one phase of the recon
> methodology, in execution order. The agent loads each playbook when entering
> that phase.

## Execution Order

| # | Phase | Skill File | Tool |
|---|-------|-----------|------|
| 1 | Subdomain Enumeration | `01_subdomain_enumeration.md` | subfinder |
| 2 | Subdomain Permutation | `02_subdomain_permutation.md` | alterx |
| 3 | Live Host Probing | `03_live_host_probing.md` | httpx |
| 4 | Port Scanning | `04_port_scanning.md` | naabu |
| 5 | Web Crawling | `05_web_crawling.md` | katana |
| 6 | URL Harvesting (Archives) | `06_url_harvesting.md` | gau |
| 7 | Directory Fuzzing | `07_directory_fuzzing.md` | ffuf |
| 8 | Vulnerability Scanning | `08_vulnerability_scanning.md` | nuclei |

## Data Flow

```
TARGET (hostname)
  │
  ├─[1] subfinder  →  subdomains[]
  │     │
  │     └─[2] alterx  →  permutations[]
  │           │
  │           └─── merge(subdomains + permutations)
  │                    │
  │                    └─[3] httpx  →  live_hosts[] (with URLs)
  │                          │
  │                    ┌─────┴─────┐
  │                    │           │
  │                 [4] naabu   [5] katana
  │                 (ports)    (endpoints)
  │
  ├─[6] gau  →  archived_urls[]
  │
  ├─[7] ffuf  →  discovered_dirs[]
  │
  └─[8] nuclei  ←  merge(live_urls + crawled + archived + fuzzed)
                    →  vulnerabilities[]
```

