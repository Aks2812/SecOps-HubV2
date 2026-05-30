#!/usr/bin/env python3
import datetime as _dt
import json
import os
import re
import stat
import sys
import uuid


def _ensure_executable(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        return


def _severity_from_text(text: str) -> str:
    t = (text or "").lower()
    if any(k in t for k in ["ransomware", "encrypt", "extortion", "wiper"]):
        return "High"
    if any(k in t for k in ["credential", "dump", "lsass", "mimikatz"]):
        return "High"
    if any(k in t for k in ["c2", "beacon", "command and control"]):
        return "Medium"
    return "Medium" if text.strip() else "Info"


def _mitre_from_text(text: str) -> str:
    t = (text or "").lower()
    if "powershell" in t:
        return "T1059.001 Command and Scripting Interpreter: PowerShell"
    if any(k in t for k in ["cmd.exe", "command prompt", "windows shell"]):
        return "T1059.003 Command and Scripting Interpreter: Windows Command Shell"
    if "rundll32" in t:
        return "T1218.011 Signed Binary Proxy Execution: Rundll32"
    if any(k in t for k in ["wmi", "wmic"]):
        return "T1047 Windows Management Instrumentation"
    if "scheduled task" in t or "schtasks" in t:
        return "T1053.005 Scheduled Task/Job: Scheduled Task"
    if "registry" in t or "reg add" in t:
        return "T1112 Modify Registry"
    if any(k in t for k in ["download", "curl", "wget", "invoke-webrequest", "bitsadmin"]):
        return "T1105 Ingress Tool Transfer"
    return "T1059 Command and Scripting Interpreter"


_STOPWORDS = {
    "detect", "detected", "detection", "alert",
    "outbound", "inbound", "port", "connection", "connect", "connects", "connected",
    "from", "to", "over", "with", "the", "and", "possible",
    "exploiting", "exploit", "exploitation",
    "downloading", "downloads", "upload", "uploading",
    "suspicious", "suspected", "suspect",
    "sending", "receiving", "received", "sent",
    "into", "for", "that", "when", "this", "using",
    "attack", "adversary", "activity",
    "execution", "running", "runs", "run",
    "process", "command", "line",
    "windows", "linux",
    "traffic", "network", "host", "file", "files",
    "user", "users", "machine", "system",
    "address", "protocol", "service", "packet", "packets",
    "beacon", "beaconing",
    "through", "during", "after", "before",
    "dropper", "payload",
}

_BEHAVIORAL = {
    "powershell", "pwsh",
    "encodedcommand", "-encodedcommand",
    "invoke-webrequest", "iwr",
    "invoke-expression", "iex",
    "downloadstring", "downloadfile",
    "invoke-restmethod", "irm",
    "mimikatz",
    "rundll32",
    "certutil",
    "bitsadmin",
    "wscript", "cscript",
    "cmd.exe", "cmd",
    "base64",
    "wmic",
    "schtasks",
    "reg", "regedit",
    "scrobj.dll", "mshta", "msbuild",
    "net.exe", "net1.exe",
    "nslookup",
    "-nop", "-noprofile", "-windowstyle", "hidden",
    "-executionpolicy", "bypass",
    "start-process",
    "invoke-command",
    "new-object", "net.webclient", "webclient",
    "comobject",
}

_IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_NUMERIC_PATTERN = re.compile(r"^\d+$")
_URL_STRIP_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
_CVE_ID_PATTERN = re.compile(r"^cve-\d{4}-\d+$", re.IGNORECASE)


def _pick_keywords(text: str) -> list[str]:
    t = (text or "").lower()
    t = _URL_STRIP_PATTERN.sub(" ", t)
    tokens = re.findall(r"[a-z0-9_.\\/-]{2,}", t)
    behavioral: list[str] = []
    other: list[str] = []
    seen: set[str] = set()
    for tok in tokens:
        if tok in seen:
            continue
        if _IP_PATTERN.match(tok):
            continue
        if _NUMERIC_PATTERN.match(tok):
            continue
        if _URL_PATTERN.match(tok):
            continue
        if _CVE_ID_PATTERN.match(tok):
            continue
        if tok in ("http", "https") or tok.startswith("//"):
            continue
        if tok in _BEHAVIORAL or tok.lstrip("-") in _BEHAVIORAL:
            if tok not in behavioral:
                behavioral.append(tok)
            seen.add(tok)
            continue
        if tok in _STOPWORDS:
            continue
        if tok not in other:
            other.append(tok)
        seen.add(tok)
    result = behavioral[:]
    for tok in other:
        if len(result) >= 5:
            break
        result.append(tok)
    return result


def _rule_title(text: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", text or "")
    if not words:
        return "Suspicious Activity"
    return " ".join(words[:8])


def _sigma_rule(text: str) -> str:
    title = _rule_title(text)
    rid = str(uuid.uuid4())
    date = _dt.date.today().strftime("%Y/%m/%d")
    t = (text or "").lower()
    mitre = _mitre_from_text(text)
    tags = []
    m = re.match(r"^(T\d+(?:\.\d+)?)\s+", mitre)
    if m:
        tags.append(f"attack.{m.group(1).lower()}")
    kws = _pick_keywords(text)

    image_list = []
    if "powershell" in t:
        image_list.append("\\\\powershell.exe")
        image_list.append("\\\\pwsh.exe")
    if any(k in t for k in ["cmd.exe", "command prompt", "windows shell"]):
        image_list.append("\\\\cmd.exe")
    if "rundll32" in t:
        image_list.append("\\\\rundll32.exe")
    if "wmi" in t or "wmic" in t:
        image_list.append("\\\\wmic.exe")
    if not image_list:
        image_list.append("\\\\*.exe")

    selection_lines = []
    selection_lines.append("  selection:")
    selection_lines.append("    Image|endswith:")
    for img in image_list:
        selection_lines.append(f"      - '{img}'")
    if kws:
        selection_lines.append("    CommandLine|contains:")
        for kw in kws:
            selection_lines.append(f"      - '{kw}'")
    selection_lines.append("  condition: selection")

    tag_lines = []
    if tags:
        tag_lines.append("tags:")
        for tag in tags:
            tag_lines.append(f"  - {tag}")

    rule = "\n".join(
        [
            f"title: {title}",
            f"id: {rid}",
            "status: experimental",
            f"description: Generated from plain-language description: {text.strip() or 'N/A'}",
            "author: secops-hub",
            f"date: {date}",
            *tag_lines,
            "logsource:",
            "  product: windows",
            "  category: process_creation",
            "detection:",
            *selection_lines,
            "falsepositives:",
            "  - Unknown",
            "level: medium",
        ]
    )
    return rule


def _mock_result(text: str) -> dict:
    rule = _sigma_rule(text or "PowerShell downloading and executing a remote script")
    return {
        "severity": "Medium",
        "summary": "Mock fallback: generated a generic Sigma rule from the description.",
        "mitre": _mitre_from_text(text or "powershell"),
        "action": rule,
    }


def _generate(text: str, force_mock: bool) -> dict:
    if force_mock:
        return _mock_result(text)
    if not (text or "").strip():
        return {
            "severity": "Info",
            "summary": "No description provided; unable to generate a meaningful detection rule.",
            "mitre": "T1592 Gather Victim Host Information",
            "action": "Provide a plain-language description (process, command-line, files/registry/network behaviors) or run with --mock.",
        }
    rule = _sigma_rule(text)
    severity = _severity_from_text(text)
    mitre = _mitre_from_text(text)
    summary = "Generated Sigma rule with basic process_creation matching; tune keywords and scope to your environment."
    return {"severity": severity, "summary": summary, "mitre": mitre, "action": rule}


def _parse_args(argv: list[str]) -> tuple[bool, str]:
    force_mock = False
    args = []
    for a in argv:
        if a == "--mock":
            force_mock = True
        else:
            args.append(a)
    text = " ".join(args).strip()
    return force_mock, text


def main() -> int:
    _ensure_executable(__file__)
    force_mock, text = _parse_args(sys.argv[1:])
    try:
        out = _generate(text, force_mock)
    except Exception:
        out = _mock_result(text)
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
