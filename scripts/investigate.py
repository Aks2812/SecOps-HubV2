#!/usr/bin/env python3
import html
import json
import os
import re
import stat
import subprocess
import sys
import time


PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _load_env() -> None:
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                if key and val and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        return


def _ensure_executable(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        return


SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

TRIAGE = [sys.executable, os.path.join(SCRIPTS_DIR, "triage.py")]
CVE_LOOKUP = [sys.executable, os.path.join(SCRIPTS_DIR, "cve_lookup.py")]
DETECTION_RULE = [sys.executable, os.path.join(SCRIPTS_DIR, "detection_rule.py")]

MANUAL_MINUTES = {"triage": 12, "cve": 5, "detection": 30}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MOCK_KEV = {"CVE-2024-3094", "CVE-2021-44228", "CVE-2022-30190", "CVE-2023-23397"}


def _check_kev(cve_id: str, force_mock: bool) -> tuple[bool, list[str]]:
    if not cve_id:
        return False, []
    decisions: list[str] = []
    if force_mock:
        if cve_id in _MOCK_KEV:
            decisions.append(f"{cve_id} found in CISA KEV → active exploitation flagged")
            return True, decisions
        decisions.append(f"{cve_id} not in CISA KEV (mock set) → no active exploitation flagged")
        return False, decisions
    try:
        import urllib.request as _ur
        import urllib.parse as _up
        req = _ur.Request(_KEV_URL, method="GET")
        with _ur.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        vulns = (data or {}).get("vulnerabilities") or []
        for entry in vulns:
            if (entry or {}).get("cveID", "").upper() == cve_id:
                decisions.append(f"{cve_id} found in CISA KEV → active exploitation flagged")
                return True, decisions
        decisions.append(f"{cve_id} not in CISA KEV → no active exploitation flagged")
        return False, decisions
    except Exception:
        decisions.append(f"CISA KEV lookup failed (offline/unreachable) → could not verify KEV status for {cve_id}")
        return False, decisions


def _compute_verdict(overall_severity: str, cve_id: str | None, in_kev: bool) -> tuple[str, list[str]]:
    decisions: list[str] = []
    if overall_severity == "Critical":
        decisions.append(f"Severity {overall_severity} → escalated")
        return "ESCALATE", decisions
    if in_kev:
        decisions.append(f"{cve_id} in CISA KEV → escalated (active exploitation)")
        return "ESCALATE", decisions
    if overall_severity == "High":
        decisions.append(f"Severity {overall_severity} → ESCALATE (review required)")
        return "ESCALATE (review)", decisions
    decisions.append(f"Severity {overall_severity}, no KEV match → MONITOR / CLOSE")
    return "MONITOR / CLOSE", decisions


def _draft_escalation(verdict: str, triage_result: dict | None, cve_id: str | None, in_kev: bool, text: str) -> str:
    lines: list[str] = []
    lines.append("## Escalation Handoff")
    lines.append("")
    if triage_result:
        summary = triage_result.get("summary", "N/A")
        lines.append(f"- **Source Alert**: {text[:200]}{'...' if len(text or '') > 200 else ''}")
        ioc_line = summary.replace("IOCs: ", "").split(";")[0] if summary.startswith("IOCs:") else "See IOC Triage section"
        lines.append(f"- **IOCs**: {ioc_line}")
        if "ip:" in summary:
            pass
    if cve_id:
        kev_tag = " \u26a0 ACTIVELY EXPLOITED" if in_kev else ""
        lines.append(f"- **CVE**: {cve_id}{kev_tag}")
    lines.append(f"- **Verdict**: {verdict}")
    lines.append(f"- **Immediate Action**: Isolate affected hosts, block identified IOCs at perimeter, initiate incident response playbook{' and apply vendor patch for ' + cve_id if cve_id else ''}.")
    lines.append("")
    return "\n".join(lines)


def _run_subprocess(cmd: list[str]) -> dict | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return json.loads(proc.stdout.strip())
    except Exception:
        return None


def _extract_cve(text: str) -> str | None:
    m = CVE_PATTERN.search(text or "")
    return m.group(0).upper() if m else None


def _highest_severity(*labels: str) -> str:
    best = "Info"
    best_order = 1
    for label in labels:
        order = SEVERITY_ORDER.get(label, 1)
        if order > best_order:
            best = label
            best_order = order
    return best


def _build_html(data: dict) -> str:
    e = html.escape
    sev_colors = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", "Info": "#6b7280"}
    sev = data["overall_severity"]
    sev_color = sev_colors.get(sev, "#6b7280")
    verdict = data["verdict"]
    is_escalate = "ESCALATE" in verdict
    banner_bg = "#dc2626" if is_escalate else "#16a34a"
    banner_text = "#ffffff"

    parts: list[str] = []
    parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secops-hub Incident Report</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f3f4f6; color: #1f2937; line-height: 1.6; }
.card { max-width: 820px; margin: 24px auto; background: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }
.verdict-banner { padding: 24px 32px; color: """ + e(banner_text) + """; background: """ + e(banner_bg) + """; }
.verdict-banner h1 { font-size: 20px; font-weight: 700; }
.verdict-banner .sub { font-size: 14px; opacity: .85; margin-top: 4px; }
.decision-box { margin: 16px 32px; padding: 16px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; }
.decision-box h2 { font-size: 14px; font-weight: 700; color: #92400e; margin-bottom: 8px; }
.decision-box ol { padding-left: 20px; font-size: 13px; color: #78350f; }
.decision-box li { margin-bottom: 4px; }
.section { padding: 16px 32px; border-bottom: 1px solid #e5e7eb; }
.section:last-of-type { border-bottom: none; }
.section h2 { font-size: 16px; font-weight: 700; margin-bottom: 10px; color: #111827; }
.section p, .section li { font-size: 14px; margin-bottom: 6px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: #fff; }
table.kv { width: 100%; border-collapse: collapse; }
table.kv td { padding: 4px 0; font-size: 14px; vertical-align: top; }
table.kv td:first-child { font-weight: 600; color: #374151; width: 160px; }
pre.rule { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 6px; font-size: 13px; line-height: 1.5; overflow-x: auto; margin-top: 8px; }
.actions ol { padding-left: 20px; }
.actions li { margin-bottom: 8px; }
.roi-footer { padding: 16px 32px; background: #f9fafb; font-size: 13px; color: #6b7280; text-align: center; border-top: 1px solid #e5e7eb; }
.roi-footer strong { color: #374151; }
</style>
</head>
<body>
<div class="card">
<div class="verdict-banner">
<h1>VERDICT: """ + e(verdict) + """</h1>
<div class="sub">Overall Severity: """ + e(sev) + """ &middot; Mode: """ + e(data["mode_label"]) + """</div>
</div>
""")

    dl = data.get("decision_log") or []
    if dl:
        parts.append('<div class="decision-box"><h2>Decision Log</h2><ol>')
        for entry in dl:
            parts.append(f"<li>{e(entry)}</li>")
        parts.append("</ol></div>")

    parts.append('<div class="section"><h2>Incident Summary</h2>')
    parts.append(f'<table class="kv"><tr><td>Overall Severity</td><td><span class="badge" style="background:{e(sev_color)}">{e(sev)}</span></td></tr>')
    parts.append(f'<tr><td>VERDICT</td><td><strong>{e(verdict)}</strong></td></tr>')
    parts.append(f'<tr><td>Input</td><td><code>{e(data["text"][:200])}</code></td></tr>')
    parts.append(f'<tr><td>Mode</td><td>{e(data["mode_label"])}</td></tr></table></div>')

    parts.append('<div class="section"><h2>IOC Triage</h2>')
    if data["triage_error"]:
        parts.append(f"<p>WARNING: triage.py failed to produce a result.</p>")
    else:
        parts.append(f'<table class="kv"><tr><td>Severity</td><td><span class="badge" style="background:{e(sev_colors.get(data["triage_severity"], "#6b7280"))}">{e(data["triage_severity"])}</span></td></tr>')
        parts.append(f'<tr><td>MITRE ATT&amp;CK</td><td>{e(data["triage_mitre"])}</td></tr>')
        parts.append(f'<tr><td>Summary</td><td>{e(data["triage_summary"])}</td></tr>')
        parts.append(f'<tr><td>Action</td><td>{e(data["triage_action"])}</td></tr></table>')
    parts.append("</div>")

    if data.get("cve_id"):
        parts.append('<div class="section"><h2>CVE Context</h2>')
        if data["cve_error"]:
            parts.append(f"<p>WARNING: cve_lookup.py failed for {e(data['cve_id'])}.</p>")
        else:
            parts.append(f'<table class="kv"><tr><td>CVE ID</td><td><strong>{e(data["cve_id"])}</strong></td></tr>')
            parts.append(f'<tr><td>Severity</td><td><span class="badge" style="background:{e(sev_colors.get(data["cve_severity"], "#6b7280"))}">{e(data["cve_severity"])}</span></td></tr>')
            if data.get("in_kev"):
                parts.append(f'<tr><td>CISA KEV</td><td><span class="badge" style="background:#dc2626">⚠ ACTIVELY EXPLOITED</span></td></tr>')
            parts.append(f'<tr><td>MITRE ATT&amp;CK</td><td>{e(data["cve_mitre"])}</td></tr>')
            parts.append(f'<tr><td>Summary</td><td>{e(data["cve_summary"])}</td></tr>')
            parts.append(f'<tr><td>Action</td><td>{e(data["cve_action"])}</td></tr></table>')
        parts.append("</div>")

    parts.append('<div class="section"><h2>Suggested Detection Rule</h2>')
    if data["detection_error"]:
        parts.append("<p>WARNING: detection_rule.py failed to produce a result.</p>")
    else:
        parts.append(f'<table class="kv"><tr><td>Severity</td><td><span class="badge" style="background:{e(sev_colors.get(data["detection_severity"], "#6b7280"))}">{e(data["detection_severity"])}</span></td></tr>')
        parts.append(f'<tr><td>MITRE ATT&amp;CK</td><td>{e(data["detection_mitre"])}</td></tr>')
        parts.append(f'<tr><td>Summary</td><td>{e(data["detection_summary"])}</td></tr></table>')
        rule_text = data.get("detection_rule_text") or ""
        parts.append(f"<pre class=\"rule\">{e(rule_text.strip())}</pre>")
    parts.append("</div>")

    actions = data.get("actions") or []
    parts.append('<div class="section actions"><h2>Recommended Actions</h2><ol>')
    for label, act in actions:
        parts.append(f"<li><strong>{e(label)}</strong>: {e(act)}</li>")
    parts.append("</ol></div>")

    if data.get("has_escalation"):
        parts.append('<div class="section"><h2>Escalation Handoff</h2>')
        parts.append(f'<table class="kv"><tr><td>Source Alert</td><td><code>{e(data["escalation_source"])}</code></td></tr>')
        parts.append(f'<tr><td>IOCs</td><td>{e(data["escalation_iocs"])}</td></tr>')
        cv = e(data["escalation_cve"] or "")
        if data.get("in_kev") and cv:
            cv += ' <span class="badge" style="background:#dc2626">⚠ ACTIVELY EXPLOITED</span>'
        parts.append(f'<tr><td>CVE</td><td>{cv}</td></tr>')
        parts.append(f'<tr><td>Verdict</td><td><strong>{e(data["escalation_verdict"])}</strong></td></tr>')
        parts.append(f'<tr><td>Immediate Action</td><td>{e(data["escalation_action"])}</td></tr></table>')
        parts.append("</div>")

    parts.append(f'<div class="roi-footer">Manual effort (equivalent): <strong>{data["manual_minutes"]} min</strong> &middot; Automated wall-clock time: <strong>{data["automated_seconds"]}s</strong> &middot; <strong>{data["manual_minutes"]} analyst-minutes of work completed in {data["automated_seconds"]} seconds</strong></div>')

    parts.append("</div>\n</body>\n</html>")
    return "\n".join(parts)


def _run_investigation(text: str, force_mock: bool) -> tuple[str, dict]:
    t_start = time.perf_counter()

    mock_flag = ["--mock"]
    triage_arg = [text] if text else ["N/A"]

    triage_cmd = TRIAGE + (mock_flag if force_mock else []) + triage_arg
    triage_result = _run_subprocess(triage_cmd)
    triage_error = triage_result is None

    cve_id = _extract_cve(text)
    cve_result = None
    cve_error = False
    if cve_id:
        cve_cmd = CVE_LOOKUP + (mock_flag if force_mock else []) + [cve_id]
        cve_result = _run_subprocess(cve_cmd)
        cve_error = cve_result is None

    detection_cmd = DETECTION_RULE + (mock_flag if force_mock else []) + triage_arg
    detection_result = _run_subprocess(detection_cmd)
    detection_error = detection_result is None

    t_end = time.perf_counter()
    automated_seconds = round(t_end - t_start, 1)

    manual_minutes = MANUAL_MINUTES["triage"]
    steps_run = 1
    if cve_id:
        manual_minutes += MANUAL_MINUTES["cve"]
        steps_run += 1
    manual_minutes += MANUAL_MINUTES["detection"]
    steps_run += 1

    overall_severity = _highest_severity(
        triage_result.get("severity", "Info") if triage_result else "Info",
        cve_result.get("severity", "Info") if cve_result else "Info",
        detection_result.get("severity", "Info") if detection_result else "Info",
    )

    decision_log: list[str] = []
    in_kev = False
    if cve_id:
        in_kev, kev_decisions = _check_kev(cve_id, force_mock)
        decision_log.extend(kev_decisions)
    verdict, verdict_decisions = _compute_verdict(overall_severity, cve_id, in_kev)
    decision_log.extend(verdict_decisions)
    escalation_note = _draft_escalation(verdict, triage_result, cve_id, in_kev, text) if "ESCALATE" in verdict else ""

    lines: list[str] = []
    lines.append("# Incident Investigation Report")
    lines.append("")

    lines.append("## Incident Summary")
    lines.append("")
    lines.append(f"- **Overall Severity**: {overall_severity}")
    lines.append(f"- **VERDICT**: {verdict}")
    lines.append(f"- **Input**: `{text[:200]}{'...' if len(text or '') > 200 else ''}`")
    mode_label = "mock (offline)" if force_mock else "live"
    lines.append(f"- **Mode**: {mode_label}")
    lines.append("")

    lines.append("## IOC Triage")
    lines.append("")
    if triage_error:
        lines.append("WARNING: triage.py failed to produce a result.")
        lines.append("")
    else:
        lines.append(f"- **Severity**: {triage_result.get('severity', 'N/A')}")
        lines.append(f"- **MITRE ATT&CK**: {triage_result.get('mitre', 'N/A')}")
        lines.append(f"- **Summary**: {triage_result.get('summary', 'N/A')}")
        lines.append(f"- **Action**: {triage_result.get('action', 'N/A')}")
        lines.append("")

    if cve_id:
        lines.append("## CVE Context")
        lines.append("")
        if cve_error:
            lines.append(f"WARNING: cve_lookup.py failed for {cve_id}.")
            lines.append("")
        else:
            lines.append(f"- **CVE ID**: {cve_id}")
            lines.append(f"- **Severity**: {cve_result.get('severity', 'N/A')}")
            lines.append(f"- **MITRE ATT&CK**: {cve_result.get('mitre', 'N/A')}")
            lines.append(f"- **Summary**: {cve_result.get('summary', 'N/A')}")
            lines.append(f"- **Action**: {cve_result.get('action', 'N/A')}")
            lines.append("")

    lines.append("## Suggested Detection Rule")
    lines.append("")
    if detection_error:
        lines.append("WARNING: detection_rule.py failed to produce a result.")
        lines.append("")
    else:
        lines.append(f"- **Severity**: {detection_result.get('severity', 'N/A')}")
        lines.append(f"- **MITRE ATT&CK**: {detection_result.get('mitre', 'N/A')}")
        lines.append(f"- **Summary**: {detection_result.get('summary', 'N/A')}")
        lines.append("")
        rule_text = detection_result.get("action", "")
        lines.append("```yaml")
        lines.append(rule_text.strip())
        lines.append("```")
        lines.append("")

    lines.append("## Recommended Actions")
    lines.append("")
    actions = []
    if triage_result and not triage_error:
        actions.append(("Triage", triage_result.get("action", "")))
    if cve_result and not cve_error:
        actions.append(("CVE Response", cve_result.get("action", "")))
    if detection_result and not detection_error:
        actions.append(("Detection Engineering", "Deploy and tune the suggested Sigma rule above; validate against your SIEM and adjust false-positive filters."))
    if not actions:
        actions.append(("Notice", "All sub-scripts failed. Re-run with --mock or check your environment."))
    for idx, (label, act) in enumerate(actions, start=1):
        lines.append(f"{idx}. **{label}**: {act}")
    lines.append("")

    if escalation_note:
        lines.append(escalation_note)

    lines.append("## Decision Log")
    lines.append("")
    if decision_log:
        for i, entry in enumerate(decision_log, start=1):
            lines.append(f"{i}. {entry}")
    else:
        lines.append("No decision rules fired.")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## ROI: Time Saved")
    lines.append("")
    lines.append(f"- Manual effort (equivalent): **{manual_minutes} min**")
    lines.append(f"- Automated wall-clock time: **{automated_seconds}s**")
    lines.append(f"- **{manual_minutes} analyst-minutes of work completed in {automated_seconds} seconds**")
    lines.append("")

    triage_ok = triage_result and not triage_error
    cve_ok = cve_result and not cve_error
    detection_ok = detection_result and not detection_error
    detection_rule_text = detection_result.get("action", "") if detection_ok else ""

    esc_source = text[:200] + ("..." if len(text or "") > 200 else "")
    esc_iocs = ""
    if triage_ok:
        summary = triage_result.get("summary", "")
        esc_iocs = summary.replace("IOCs: ", "").split(";")[0] if summary.startswith("IOCs:") else "See IOC Triage section"

    actions_for_data = []
    if triage_ok:
        actions_for_data.append(("Triage", triage_result.get("action", "")))
    if cve_ok:
        actions_for_data.append(("CVE Response", cve_result.get("action", "")))
    if detection_ok:
        actions_for_data.append(("Detection Engineering", "Deploy and tune the suggested Sigma rule above; validate against your SIEM and adjust false-positive filters."))
    if not actions_for_data:
        actions_for_data.append(("Notice", "All sub-scripts failed. Re-run with --mock or check your environment."))

    esc_action = f"Isolate affected hosts, block identified IOCs at perimeter, initiate incident response playbook{' and apply vendor patch for ' + cve_id if cve_id else ''}."

    data = {
        "verdict": verdict,
        "overall_severity": overall_severity,
        "text": text or "",
        "mode_label": mode_label,
        "decision_log": decision_log,
        "triage_error": triage_error,
        "triage_severity": triage_result.get("severity", "N/A") if triage_result else "N/A",
        "triage_mitre": triage_result.get("mitre", "N/A") if triage_result else "N/A",
        "triage_summary": triage_result.get("summary", "N/A") if triage_result else "N/A",
        "triage_action": triage_result.get("action", "N/A") if triage_result else "N/A",
        "cve_id": cve_id,
        "cve_error": cve_error,
        "cve_severity": cve_result.get("severity", "N/A") if cve_result else "N/A",
        "cve_mitre": cve_result.get("mitre", "N/A") if cve_result else "N/A",
        "cve_summary": cve_result.get("summary", "N/A") if cve_result else "N/A",
        "cve_action": cve_result.get("action", "N/A") if cve_result else "N/A",
        "detection_error": detection_error,
        "detection_severity": detection_result.get("severity", "N/A") if detection_result else "N/A",
        "detection_mitre": detection_result.get("mitre", "N/A") if detection_result else "N/A",
        "detection_summary": detection_result.get("summary", "N/A") if detection_result else "N/A",
        "detection_rule_text": detection_rule_text,
        "actions": actions_for_data,
        "has_escalation": "ESCALATE" in verdict,
        "escalation_source": esc_source,
        "escalation_iocs": esc_iocs,
        "escalation_cve": cve_id or "",
        "escalation_verdict": verdict,
        "escalation_action": esc_action,
        "in_kev": in_kev,
        "manual_minutes": manual_minutes,
        "automated_seconds": automated_seconds,
    }

    return "\n".join(lines), data


def _parse_args(argv: list[str]) -> tuple[bool, str]:
    force_mock = False
    args = []
    for a in argv:
        if a == "--mock":
            force_mock = True
        else:
            args.append(a)
    return force_mock, " ".join(args).strip()


def main() -> int:
    _ensure_executable(__file__)
    _load_env()
    force_mock, text = _parse_args(sys.argv[1:])
    try:
        report, data = _run_investigation(text, force_mock)
    except Exception:
        report = (
            "# Incident Investigation Report\n\n"
            "## Incident Summary\n\n"
            "WARNING: The orchestrator encountered an unexpected error. "
            "Re-run with --mock or check the environment.\n"
        )
        data = None
    sys.stdout.write(report)
    sys.stdout.flush()
    if data:
        try:
            html_content = _build_html(data)
            html_path = os.path.join(PROJECT_ROOT, "report.html")
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            sys.stdout.write(f"\n\nHTML report written to: {os.path.abspath(html_path)}\n")
        except Exception:
            sys.stdout.write("\n\nWARNING: Failed to write HTML report.\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
