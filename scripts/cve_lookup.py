#!/usr/bin/env python3
import json
import os
import re
import stat
import sys
import urllib.parse
import urllib.request


def _ensure_executable(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        return


def _http_get_json(url: str, timeout_s: int = 10) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def _pick_cvss(metrics: dict) -> tuple[float | None, str]:
    if not isinstance(metrics, dict):
        return None, "Unknown"

    for key, label in [
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ]:
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            item = arr[0] or {}
            cvss_data = item.get("cvssData") or {}
            base_score = cvss_data.get("baseScore")
            if base_score is None:
                base_score = item.get("baseScore")
            try:
                return float(base_score), label
            except Exception:
                return None, label

    return None, "Unknown"


def _mock_result(cve_id: str) -> dict:
    return {
        "severity": "Medium",
        "summary": f"Mock fallback for {cve_id}: NVD lookup unavailable; using conservative default severity.",
        "mitre": "T1190 Exploit Public-Facing Application",
        "action": "Validate the affected product/version, apply vendor patches or compensating controls, and monitor for exploitation attempts.",
    }


def _lookup(cve_id: str, force_mock: bool) -> dict:
    if force_mock:
        return _mock_result(cve_id)

    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id or "", re.IGNORECASE):
        return {
            "severity": "Info",
            "summary": "Input is not a valid CVE identifier (expected CVE-YYYY-NNNN...).",
            "mitre": "T1592 Gather Victim Host Information",
            "action": "Provide a valid CVE ID such as CVE-2024-3094, or run with --mock.",
        }

    q = urllib.parse.urlencode({"cveId": cve_id.upper()})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}"
    data = _http_get_json(url)

    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return {
            "severity": "Info",
            "summary": f"No NVD record found for {cve_id.upper()}.",
            "mitre": "T1592 Gather Victim Host Information",
            "action": "Confirm the CVE ID, or check whether NVD has published the record yet.",
        }

    cve = (vulns[0] or {}).get("cve") or {}
    descs = cve.get("descriptions") or []
    desc = ""
    for d in descs:
        if (d or {}).get("lang") == "en":
            desc = (d or {}).get("value") or ""
            break
    if not desc and descs:
        desc = (descs[0] or {}).get("value") or ""

    metrics = cve.get("metrics") or {}
    score, cvss_label = _pick_cvss(metrics)
    severity = _severity_from_cvss(score)

    score_txt = "unknown" if score is None else f"{score:.1f}"
    summary = f"{cve_id.upper()} {cvss_label} baseScore={score_txt}. {desc}".strip()
    mitre = "T1190 Exploit Public-Facing Application"
    action = "Prioritize patching based on exposure; add detection for exploitation indicators and verify remediation."

    return {"severity": severity, "summary": summary, "mitre": mitre, "action": action}


def _parse_args(argv: list[str]) -> tuple[bool, str]:
    force_mock = False
    args = []
    for a in argv:
        if a == "--mock":
            force_mock = True
        else:
            args.append(a)
    cve_id = " ".join(args).strip()
    return force_mock, cve_id


def main() -> int:
    _ensure_executable(__file__)
    force_mock, cve_id = _parse_args(sys.argv[1:])
    try:
        out = _lookup(cve_id, force_mock)
    except Exception:
        out = _mock_result((cve_id or "CVE-0000-0000").upper())
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
