#!/usr/bin/env python3
import json
import os
import re
import stat
import subprocess
import sys


def _ensure_executable(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        return


SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.normpath(os.path.join(SCRIPTS_DIR, ".."))
ALERTS_DIR = os.path.join(SKILL_ROOT, "in", "alerts")
CASES_DIR = os.path.join(SKILL_ROOT, "out", "cases")
INVESTIGATE = [sys.executable, os.path.join(SCRIPTS_DIR, "investigate.py")]

VERDICT_RE = re.compile(r"\*\*VERDICT\*\*:\s*(.+)$", re.MULTILINE)


def _classify(verdict: str) -> str:
    v = verdict.strip()
    if v == "ESCALATE":
        return "escalated"
    if "review" in v.lower():
        return "review"
    return "suppressed"


def _run_batch(force_mock: bool) -> tuple[dict, list[dict]]:
    os.makedirs(CASES_DIR, exist_ok=True)
    if not os.path.isdir(ALERTS_DIR):
        result = {"total": 0, "escalated": 0, "review": 0, "suppressed": 0}
        return result, []

    alert_files = sorted(
        f for f in os.listdir(ALERTS_DIR) if f.lower().endswith(".json")
    )

    counts = {"total": 0, "escalated": 0, "review": 0, "suppressed": 0}
    rows: list[dict] = []

    for filename in alert_files:
        alert_path = os.path.join(ALERTS_DIR, filename)
        alert_id = os.path.splitext(filename)[0]
        verdict = "FAILED"
        bucket = "error"

        try:
            with open(alert_path, "r", encoding="utf-8") as fh:
                alert_data = json.load(fh)
            raw_text = (alert_data or {}).get("raw_text") or ""
            if not raw_text.strip():
                verdict = "N/A"
                bucket = "suppressed"
                rows.append({"id": alert_id, "verdict": verdict, "bucket": bucket})
                continue

            cmd = INVESTIGATE.copy()
            if force_mock:
                cmd.append("--mock")
            cmd.append(raw_text)

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            report = proc.stdout or ""

            case_path = os.path.join(CASES_DIR, f"case-{alert_id}.md")
            with open(case_path, "w", encoding="utf-8") as fh:
                fh.write(report)

            m = VERDICT_RE.search(report)
            if m:
                verdict = m.group(1).strip()
            else:
                verdict = "UNKNOWN"

            bucket = _classify(verdict)

        except Exception:
            verdict = "FAILED"
            bucket = "error"

        counts["total"] += 1
        if bucket in counts:
            counts[bucket] += 1
        rows.append({"id": alert_id, "verdict": verdict, "bucket": bucket})

    return counts, rows


def _parse_args(argv: list[str]) -> bool:
    return "--mock" in argv


def main() -> int:
    _ensure_executable(__file__)
    force_mock = _parse_args(sys.argv[1:])
    counts, rows = _run_batch(force_mock)

    summary = (
        f"Processed {counts['total']} alerts"
        f" | Escalated: {counts['escalated']}"
        f" | Review: {counts['review']}"
        f" | Suppressed: {counts['suppressed']}"
        f" | Cases in out/cases/"
    )

    result = {
        "total": counts["total"],
        "escalated": counts["escalated"],
        "review": counts["review"],
        "suppressed": counts["suppressed"],
        "summary": summary,
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()

    col_id = 12
    col_verdict = 24
    sys.stderr.write(f"{'ALERT ID':<{col_id}} {'VERDICT':<{col_verdict}} {'BUCKET'}\n")
    sys.stderr.write("-" * (col_id + col_verdict + 10) + "\n")
    for row in rows:
        sys.stderr.write(
            f"{row['id']:<{col_id}} {row['verdict']:<{col_verdict}} {row['bucket']}\n"
        )
    sys.stderr.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
