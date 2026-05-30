# SecOps-HubV2

An all-in-one, zero-dependency security operations command-line toolkit that does what most paid SOAR platforms can't: triage, CVE intelligence, detection rule authoring, and full-alert investigation — in under one second.

## Why This Exists

Security analysts spend hours every day doing the same three things: extracting IOCs from alerts, looking up CVE severities, and writing detection rules. SecOps-HubV2 automates all of it with Python standard library scripts that never crash and never require a pip install.

Built socket-to-script — every module was crafted from scratch using only `os`, `json`, `re`, `subprocess`, and `urllib`. No frameworks, no external packages, no lock-in.

## What It Does

| Script | Purpose |
|---|---|
| `triage.py` | Extract IOCs (IPs, domains, URLs, hashes) from raw alert text — including escaped JSON and structured logs. Optionally enriches via VirusTotal and AbuseIPDB. |
| `cve_lookup.py` | Query the NVD REST API for a CVE ID and return CVSS-based severity with MITRE ATT&CK mapping. |
| `detection_rule.py` | Generate a Sigma detection rule from a plain-language attack description. Content-aware keyword filtering drops noise (stopwords, IPs, URLs, CVE IDs) and keeps only behavioral indicators. |
| `investigate.py` | End-to-end orchestrator: chains triage → CVE lookup → detection rule → CISA KEV check → automated verdict (ESCALATE / MONITOR). Outputs both a Markdown report and a styled HTML file with a time-saved ROI footer. |
| `batch.py` | Bulk processor: reads `in/alerts/*.json`, runs `investigate.py` on each, classifies by verdict bucket (escalated / review / suppressed), writes case files to `out/cases/`. |

## Key Features

- **Zero external dependencies** — Python 3 stdlib only
- **Mock/offline mode** — every script has `--mock` for full offline operation
- **Graceful degradation** — if an API is unreachable, mock fallback kicks in; nothing crashes
- **CISA KEV integration** — live lookup against the Known Exploited Vulnerabilities catalog; escalates automatically when a CVE is actively exploited
- **EV detection support** — environment variables for API keys loaded from `.env` (see `.env.example`)
- **Structured input tolerant** — triage accepts raw JSON logs, escaped shell strings, and plain text equally well
- **ROI footer** on every investigation report showing analyst-minutes saved

## Quick Start

```bash
# Single‑alert investigation (mock/offline)
python scripts/investigate.py --mock "Beacon from 45.77.12.9 exploiting CVE-2024-3094 with PowerShell dropper"

# IOC triage
python scripts/triage.py --mock "Suspicious connection to 185.220.101.47 and https://evil.example/path"

# CVE severity lookup
python scripts/cve_lookup.py "CVE-2024-3094"

# Generate a Sigma detection rule
python scripts/detection_rule.py "Detect PowerShell EncodedCommand downloading from Invoke-WebRequest"

# Batch processing
python scripts/batch.py --mock
```

## Configuration

Copy `.env.example` to `.env` and add your API keys:

```
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuse_key
NVD_API_KEY=
```

The NVD key is optional (free tier doesn't require it). Keys are loaded automatically by `investigate.py` and inherited by sub-scripts.

## Directory Layout

```
secops-hub/
├── .env.example          # API key template
├── .gitignore
├── README.md
├── SKILL.md              # SOLO skill definition
├── report.html           # Generated HTML report (overwritten each run)
├── in/alerts/            # Drop alert JSON files here for batch processing
├── out/cases/            # Batch investigation case files land here
└── scripts/
    ├── triage.py
    ├── cve_lookup.py
    ├── detection_rule.py
    ├── investigate.py
    └── batch.py
```

## Contract

Every script accepts a single string argument and prints exactly one JSON object to stdout with the keys `severity`, `summary`, `mitre`, and `action`. The `investigate.py` orchestrator additionally writes a full Markdown report and a styled HTML file to the project root.
