#!/usr/bin/env python3
"""
triage.py — SecOps Hub triage capability (reviewed & fixed).

Fixes over the generated version:
  1. Domain regex no longer matches filenames (invoice.pdf, report.docx, etc.)
     — validates against a TLD allowlist and strips known file extensions.
  2. --mock now still extracts IOCs from the input and returns a rich verdict.
  3. MITRE default is "N/A" when nothing is found (was misleadingly "phishing").

Contract (unchanged): single string arg -> ONE JSON object to stdout with keys
  severity / summary / mitre / action.  Never crashes (mock fallback on error).
"""

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request


# A pragmatic TLD allowlist — enough to separate real domains from filenames.
# Extend as needed; the point is to reject .pdf/.exe/.docx/etc.
COMMON_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "mil", "int", "biz", "info",
    "xyz", "online", "site", "top", "ru", "cn", "uk", "de", "fr", "jp", "br",
    "id", "in", "us", "ca", "au", "nl", "se", "no", "es", "it", "pl", "tv",
    "me", "app", "dev", "cloud", "ai", "tech", "live", "club", "vip", "cc",
}

# Extensions we must NEVER treat as domains.
FILE_EXTENSIONS = {
    "exe", "dll", "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "zip",
    "rar", "7z", "txt", "log", "json", "xml", "csv", "ps1", "bat", "sh", "py",
    "js", "vbs", "jar", "dmg", "iso", "img", "bin", "dat", "tmp", "png", "jpg",
    "jpeg", "gif", "msi", "lnk", "scr", "html", "htm", "yaml", "yml", "md",
}

IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
}


def _http_get_json(url, headers=None, timeout_s=8):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _is_real_domain(candidate: str) -> bool:
    """Reject filenames; accept only names whose last label is a known TLD."""
    last_label = candidate.rsplit(".", 1)[-1].lower()
    if last_label in FILE_EXTENSIONS:
        return False
    return last_label in COMMON_TLDS


def _extract_iocs(text):
    extracted = {k: [] for k in IOC_PATTERNS.keys()}
    for kind, pat in IOC_PATTERNS.items():
        extracted[kind] = pat.findall(text or "")

    # FIX 1: filter domain candidates against TLD allowlist / file extensions
    extracted["domain"] = [d for d in extracted["domain"] if _is_real_domain(d)]

    # Drop domains that are just the host of an already-captured URL
    domains = set(extracted["domain"])
    for u in set(extracted["url"]):
        try:
            host = urllib.parse.urlparse(u).hostname
        except Exception:
            host = None
        if host:
            domains.discard(host)
    extracted["domain"] = sorted(domains)

    for k in list(extracted.keys()):
        extracted[k] = sorted(set(extracted[k]))
    return extracted


def _collect_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        result = []
        for v in obj.values():
            result.extend(_collect_strings(v))
        return result
    if isinstance(obj, list):
        result = []
        for item in obj:
            result.extend(_collect_strings(item))
        return result
    return []


def _preprocess_text(raw: str) -> str:
    cleaned = raw or ""
    cleaned = cleaned.replace('\\"', '"').replace("\\\\", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)

    stripped = cleaned.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            strings = _collect_strings(parsed)
            if strings:
                cleaned = " ".join(strings)
        except Exception:
            pass

    return cleaned


def _keyword_score(text):
    t = (text or "").lower()
    score = 0
    if any(k in t for k in ["ransomware", "encrypt", "extortion"]):
        score += 6
    if any(k in t for k in ["phish", "credential", "login", "oauth", "mfa"]):
        score += 4
    if any(k in t for k in ["c2", "command and control", "beacon", "callback"]):
        score += 4
    if any(k in t for k in ["dropper", "payload", "malware", "trojan"]):
        score += 4
    return score


def _mock_score(iocs):
    score = 0
    if any(iocs.values()):
        score = 4
    if iocs.get("ip"):
        score = max(score, 6)
    if iocs.get("url") or iocs.get("domain"):
        score = max(score, 7)
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        score = max(score, 8)
    return score


def _map_severity(score):
    if score >= 9: return "Critical"
    if score >= 7: return "High"
    if score >= 4: return "Medium"
    if score >= 2: return "Low"
    return "Info"


def _map_mitre(text, iocs):
    t = (text or "").lower()
    has_net = bool(iocs.get("url") or iocs.get("domain"))
    if any(k in t for k in ["phish", "spearphish", "credential", "login"]) and has_net:
        return "T1566.002 Spearphishing Link"
    if any(k in t for k in ["c2", "command and control", "beacon", "callback"]) and (iocs.get("ip") or has_net):
        return "T1071.001 Application Layer Protocol: Web Protocols"
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        return "T1204.002 User Execution: Malicious File"
    if has_net:
        return "T1105 Ingress Tool Transfer"
    if iocs.get("ip"):
        return "T1090 Proxy"
    # FIX 3: honest default instead of a misleading phishing technique
    return "N/A"


def _build_action(iocs, severity):
    flat = [f"{k}:{v}" for k in ["ip", "domain", "url", "md5", "sha1", "sha256"] for v in iocs.get(k, [])]
    if not flat:
        return "Collect more context (full headers/log lines), then rerun triage with the complete text."
    items = ", ".join(flat[:20])
    if severity in {"Critical", "High"}:
        return f"Block and hunt immediately for these IOCs ({items}); pivot to endpoint/network logs and quarantine affected hosts if confirmed."
    if severity == "Medium":
        return f"Add these IOCs to monitoring and run a quick retrospective search ({items}); escalate if repeated."
    if severity == "Low":
        return f"Monitor these IOCs and enrich with additional telemetry ({items}); keep for correlation."
    return f"Record the IOCs for context and correlation ({items})."


# --- optional live enrichment (unchanged behavior; skipped without keys) ------

def _vt_enrich(iocs, api_key):
    headers = {"x-apikey": api_key}
    matches = 0
    targets = [
        (iocs.get("sha256", [])[:3], "files", lambda h: h),
        (iocs.get("domain", [])[:3], "domains", lambda d: d),
        (iocs.get("ip", [])[:3], "ip_addresses", lambda i: i),
        (iocs.get("url", [])[:3], "urls", _vt_url_id),
    ]
    for values, path, conv in targets:
        for v in values:
            try:
                d = _http_get_json(f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(conv(v))}", headers=headers)
                stats = (((d or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                if int(stats.get("malicious", 0) or 0) > 0:
                    matches += 1
            except Exception:
                continue
    return {"available": True, "matches": matches}


def _abuse_enrich(iocs, api_key):
    headers = {"Key": api_key, "Accept": "application/json"}
    hits = 0
    for ip in iocs.get("ip", [])[:3]:
        try:
            q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
            d = _http_get_json(f"https://api.abuseipdb.com/api/v2/check?{q}", headers=headers)
            if int(((d or {}).get("data") or {}).get("abuseConfidenceScore", 0) or 0) >= 50:
                hits += 1
        except Exception:
            continue
    return {"available": True, "hits": hits}


def _triage(text, force_mock):
    text = _preprocess_text(text)
    iocs = _extract_iocs(text)
    base = 0
    base += sum(1 for k, v in iocs.items() if k in {"ip", "domain", "url"} and v)
    base += sum(1 for k, v in iocs.items() if k in {"md5", "sha1", "sha256"} and v)
    base += _keyword_score(text)

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    vt = {"available": False, "matches": 0}
    abuse = {"available": False, "hits": 0}

    # FIX 2: mock still uses extracted IOCs for a rich, realistic verdict
    if force_mock or (not vt_key and not abuse_key):
        score = max(base, _mock_score(iocs))
        enrich_note = "mock/fallback"
    else:
        score = base
        try:
            if vt_key:
                vt = _vt_enrich(iocs, vt_key)
                score += vt["matches"] * 5
        except Exception:
            pass
        try:
            if abuse_key:
                abuse = _abuse_enrich(iocs, abuse_key)
                score += abuse["hits"] * 3
        except Exception:
            pass
        enrich_note = None

    severity = _map_severity(score)
    mitre = _map_mitre(text, iocs)

    counts = {k: len(v) for k, v in iocs.items() if v}
    parts = ["IOCs: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))] if counts else ["No IOCs extracted"]
    if vt.get("available"):
        parts.append(f"VirusTotal matches={vt['matches']}")
    if abuse.get("available"):
        parts.append(f"AbuseIPDB hits={abuse['hits']}")
    if enrich_note:
        parts.append(f"Enrichment: {enrich_note}")

    return {"severity": severity, "summary": "; ".join(parts), "mitre": mitre, "action": _build_action(iocs, severity)}


def _parse_args(argv):
    force_mock, args = False, []
    for a in argv:
        if a == "--mock":
            force_mock = True
        else:
            args.append(a)
    return force_mock, " ".join(args).strip()


def main():
    force_mock, text = _parse_args(sys.argv[1:])
    try:
        out = _triage(text, force_mock)
    except Exception:
        out = {
            "severity": "Info",
            "summary": "Mock fallback: triage failed to process input or reach enrichment services.",
            "mitre": "N/A",
            "action": "Rerun with --mock or provide more context; verify network access and API keys.",
        }
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())