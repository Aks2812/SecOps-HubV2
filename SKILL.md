---
name: "secops-hub"
description: "Security operations toolkit for IOC triage, CVE severity lookups, Sigma detection rule generation, and full-alert investigation. Invoke when the user pastes a raw security alert, asks to investigate or do a full workup, or needs quick triage/CVE/detection-rule tasks."
---

# secops-hub

This skill package provides four standalone scripts for common security operations workflows.

## Scripts

### triage.py

Input: free-form alert text, email body, log snippet, or analyst notes.

Output: JSON with severity, summary, MITRE ATT&CK mapping, and a concrete next action.

Optional enrichment:
- VirusTotal API key via `VIRUSTOTAL_API_KEY`
- AbuseIPDB API key via `ABUSEIPDB_API_KEY`

Usage:

```bash
python scripts/triage.py "Suspicious connection to 1.2.3.4 and hxxp://evil.example/path with SHA256 0123..."
python scripts/triage.py --mock "anything"
```

### cve_lookup.py

Looks up a CVE in NVD and returns CVSS-based severity. Uses mock fallback on errors.

Usage:

```bash
python scripts/cve_lookup.py "CVE-2024-3094"
python scripts/cve_lookup.py --mock "CVE-2024-3094"
```

### detection_rule.py

Generates a Sigma detection rule from a plain-language attack description (standard library only).

Usage:

```bash
python scripts/detection_rule.py "Detect PowerShell downloading a script via Invoke-WebRequest and executing it"
python scripts/detection_rule.py --mock "anything"
```

### investigate.py

End-to-end orchestrator. Takes a single raw alert string and chains triage → CVE lookup (if a CVE ID is present) → detection rule generation. Produces a consolidated Markdown incident report with ROI time-saved footer.

Invoke this script when the user pastes a full alert or asks to "investigate" or "do a full workup."

Manual-effort baselines used in the ROI footer:
- Triage: 12 min
- CVE research: 5 min
- Detection rule authoring: 30 min

Usage:

```bash
python scripts/investigate.py "Alert: suspicious beacon from 10.0.0.5 with CVE-2024-3094"
python scripts/investigate.py --mock "Phishing email with link to evil.com"
```
