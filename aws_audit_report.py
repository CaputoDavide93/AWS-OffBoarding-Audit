#!/usr/bin/env python3
"""
aws_audit_report.py — turn raw CloudTrail output into a reviewable brief.

    python3 aws_audit_report.py aws_offboarding_audit.json \
        --user leaver@example.com \
        --notice-date 2026-07-15 --last-day 2026-08-15 \
        --org-accounts 111122223333 444455556666 777788889999 \
        --analyze

Writes <out>.html and <out>.md.

Ratings describe what an API *can* do and therefore what warrants a human check.
They are not accusations. Most flagged actions in an engineer's history are their
job, and this report is only useful if it is read that way.

Requires audit_intel.py and (for --analyze) audit_analyst.py alongside it.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

from audit_intel import (C, H, M, L, SEV_LABEL, SEV_ORDER, classify_event,
                         detect_content, detect_sequences, load_traildiscover,
                         normalize_target)

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None


# ==========================================================================
# Load and enrich
# ==========================================================================
def load_rows(path: str) -> list[dict]:
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and isinstance(value.get("events"), list):
            return value["events"]
        raise ValueError("JSON input must be an event list or an object with an events list.")
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_json_object(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def load_manifest(input_path: str, manifest_path: str | None = None) -> dict:
    if manifest_path:
        return load_json_object(manifest_path)
    root, _ = os.path.splitext(input_path)
    candidate = f"{root}.manifest.json"
    return load_json_object(candidate) if os.path.exists(candidate) else {}


def input_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def apply_current_state(rows: list[dict], state: dict) -> None:
    targets = state.get("targets", {}) if isinstance(state.get("targets", {}), dict) else {}
    events = state.get("events", {}) if isinstance(state.get("events", {}), dict) else {}
    checked_at = str(state.get("checked_at", ""))
    source = str(state.get("source", ""))
    for row in rows:
        value = events.get(row.get("event_id")) or targets.get(row.get("target_key"))
        if isinstance(value, str):
            value = {"status": value}
        value = value if isinstance(value, dict) else {}
        status = str(value.get("status", "unknown")).lower()
        row["current_state"] = status
        row["state_active"] = status in {"active", "present", "enabled", "exposed"}
        row["state_checked_at"] = str(value.get("checked_at", checked_at))
        row["state_source"] = str(value.get("source", source))
        row["state_detail"] = str(value.get("detail", ""))


def apply_baseline(rows: list[dict], baseline: dict) -> dict:
    event_specs = baseline.get("events", {}) if isinstance(baseline.get("events", {}), dict) else {}
    sample_size = int(baseline.get("sample_size", 0) or 0)
    counts = Counter(row["event_name"] for row in rows)
    elevated = []
    for event_name, count in counts.items():
        spec = event_specs.get(event_name, {})
        if isinstance(spec, (int, float)):
            spec = {"mean": float(spec), "stddev": 0.0}
        if not isinstance(spec, dict) or "mean" not in spec or sample_size < 3:
            status, ratio = "insufficient", None
        else:
            mean = max(0.0, float(spec.get("mean", 0)))
            stddev = max(0.0, float(spec.get("stddev", 0)))
            threshold = mean + max(2 * stddev, mean * 0.5, 1.0)
            status = "above" if count >= threshold else "within"
            ratio = round(count / mean, 2) if mean else None
            if status == "above":
                elevated.append(event_name)
        for row in rows:
            if row["event_name"] == event_name:
                row["baseline_status"] = status
                row["baseline_ratio"] = ratio
    return {
        "label": str(baseline.get("label", "Peer baseline")),
        "sample_size": sample_size,
        "elevated_events": sorted(elevated),
        "available": bool(event_specs),
    }


def build_report_summary(rows: list[dict], sequences: list[dict], ctx: dict) -> dict:
    return {
        "schema_version": 1,
        "report_id": ctx["report_id"],
        "input_sha256": ctx["input_sha256"],
        "generated": ctx["generated"],
        "subject": ctx["user"],
        "coverage_status": ctx.get("coverage", {}).get("status", "unknown"),
        "event_scope": ctx.get("coverage", {}).get("event_scope", "management"),
        "events": len(rows),
        "accounts": ctx["n_accounts"],
        "regions": ctx["n_regions"],
        "by_severity": dict(Counter(row["severity"] for row in rows)),
        "by_category": dict(Counter(row["category"] for row in rows)),
        "current_state": dict(Counter(row.get("current_state", "unknown") for row in rows)),
        "sequence_count": len(sequences),
        "baseline": ctx.get("baseline", {}),
    }


def enrich(rows, td, tz, notice, last_day, day_start, day_end, org_accounts):
    out = []
    for row in rows:
        try:
            ts = datetime.fromisoformat(row["time_utc"].replace("Z", "+00:00"))
        except (KeyError, ValueError, AttributeError):
            continue
        local = ts.astimezone(tz) if tz else ts
        rec = classify_event(row.get("event_name", ""), td)
        sev = base_sev = rec["severity"]

        content = detect_content(row, org_accounts)
        target = normalize_target(row)
        # A parameter-level finding is real evidence; it outranks the name-based guess.
        for cf in content:
            if SEV_ORDER[cf["severity"]] < SEV_ORDER[sev]:
                sev = base_sev = cf["severity"]

        flags = []
        if last_day and ts > last_day:
            flags.append("After last working day")
            sev = C
        elif notice and ts > notice:
            flags.append("During notice period")
        if local.weekday() >= 5:
            flags.append("Weekend")
        if not (day_start <= local.hour < day_end):
            flags.append("Outside working hours")
        if row.get("error_code"):
            flags.append(f"Failed: {row['error_code']}")

        principal_key = (row.get("principal_arn") or row.get("principal_id")
                 or row.get("matched_on") or "")
        out.append({**row, **rec, **target, "_ts": ts, "_local": local,
                "principal_key": principal_key,
                    "severity": sev, "base_severity": base_sev,
                    "content_findings": content, "flags": flags})
    out.sort(key=lambda r: (SEV_ORDER[r["severity"]], r["_ts"]))
    return out


# ==========================================================================
# Presentation
# ==========================================================================
CSS = """
:root{
    --paper:#EEF1F4; --card:#FFFFFF; --ink:#16202A; --muted:#5C6B7A;
  --rule:#D5DDE4; --rule-soft:#E7ECF0; --wash:#F4F7F9;
  --critical:#A81D26; --high:#B5641A; --medium:#1F6FB2; --low:#6A7885;
    --spine:#C3CCD5; --good:#24734C; --unknown:#6A7885; --focus:#0A5B88;
}
*{box-sizing:border-box}
body{margin:0;background-color:var(--paper);
    background-image:linear-gradient(rgba(22,32,42,.025) 1px,transparent 1px),
        linear-gradient(90deg,rgba(22,32,42,.025) 1px,transparent 1px);
    background-size:24px 24px;color:var(--ink);
  font-family:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
code,.mono,.evt{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px 96px}
a{color:var(--medium)}

header.case{border-bottom:2px solid var(--ink);padding:56px 0 24px}
.eyebrow{font-family:"IBM Plex Mono",monospace;font-size:11px;letter-spacing:.18em;
  text-transform:uppercase;color:var(--muted)}
h1{font-size:42px;line-height:1.05;margin:14px 0 6px;font-weight:600;letter-spacing:0}
h1 .subject{font-family:"IBM Plex Mono",monospace;font-weight:500;display:block;
    font-size:22px;color:var(--muted);margin-top:10px;word-break:break-all}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:20px 28px;
  margin-top:32px;padding-top:22px;border-top:1px solid var(--rule)}
.meta dt{font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--muted);margin-bottom:5px}
.meta dd{margin:0;font-size:15px;font-weight:500}
.caveat{margin-top:26px;padding:13px 16px;background:#E3E9EE;border-left:3px solid var(--medium);
  font-size:13.5px;color:#33465A}

.hr-guide{margin:28px 0 0;padding:20px 24px;background:var(--card);
  border:1px solid var(--rule);border-left:4px solid var(--good)}
.hr-guide h2{margin:0 0 12px;font-size:17px}
.hr-guide p{margin:0 0 12px;font-size:14px;line-height:1.6;color:#33465A}
.hr-guide p:last-child{margin-bottom:0;padding:12px 14px;background:var(--wash);
  border-left:3px solid var(--focus)}
.hr-guide code{background:var(--wash);padding:1px 5px;border-radius:3px}

/* Default view hides anything tagged .tech — raw event names, timestamps,
   regions, request parameters, MITRE tactics, filter tooling. Flipping the
   switch below adds .technical to <body>, which reveals it all again. This
   is presentation-only: every underlying number is identical in both modes. */
.view-switch{display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  margin:18px 0 30px;padding:14px 18px;background:var(--wash);
  border:1px solid var(--rule);border-radius:4px;font-size:13.5px}
.view-switch .vs-label{color:var(--muted)}
.view-switch .vs-mode{font-weight:600;color:var(--ink)}
.switch{position:relative;display:inline-block;width:42px;height:24px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.switch .slider{position:absolute;inset:0;background:var(--rule);border-radius:24px;
  cursor:pointer;transition:.15s}
.switch .slider:before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;
  background:#fff;border-radius:50%;transition:.15s;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.switch input:checked + .slider{background:var(--focus)}
.switch input:checked + .slider:before{transform:translateX(18px)}
.switch input:focus-visible + .slider{outline:2px solid var(--focus);outline-offset:2px}
body:not(.technical) .tech{display:none}

.tally{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);margin:36px 0 8px}
.tally div{background:var(--card);padding:18px 16px}
.tally .n{font-size:34px;font-weight:600;line-height:1;letter-spacing:0;
  font-family:"IBM Plex Mono",monospace}
.tally .k{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
  margin-top:8px;font-family:"IBM Plex Mono",monospace}
.tally .critical .n{color:var(--critical)} .tally .high .n{color:var(--high)}
.tally .medium .n{color:var(--medium)} .tally .low .n{color:var(--low)}

h2{font-size:12px;letter-spacing:.16em;text-transform:uppercase;
  font-family:"IBM Plex Mono",monospace;color:var(--muted);margin:56px 0 18px;
  padding-bottom:10px;border-bottom:1px solid var(--rule);font-weight:500}

.analyst{background:var(--ink);color:#E9EEF2;padding:28px 30px;margin:8px 0 0}
.analyst .badge{font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.14em;
  text-transform:uppercase;color:#8FA3B4}
.analyst h3{margin:12px 0 16px;font-size:21px;font-weight:600;line-height:1.3;color:#fff}
.analyst p{margin:0 0 12px;font-size:14.5px;color:#CBD6DE}
.analyst .conf{margin-top:16px;padding-top:14px;border-top:1px solid #2C3A47;
  font-size:12.5px;color:#8FA3B4}
.queue{counter-reset:q;margin:14px 0 0;padding:0;list-style:none}
.queue li{background:var(--card);border:1px solid var(--rule);padding:15px 18px 15px 56px;
  position:relative;margin-bottom:8px}
.queue li:before{counter-increment:q;content:counter(q);position:absolute;left:18px;top:15px;
  font-family:"IBM Plex Mono",monospace;font-size:17px;font-weight:600;color:var(--muted)}
.queue .act{font-size:14.5px;font-weight:500;display:block}
.queue .why{font-size:13px;color:var(--muted);margin-top:5px;display:block}
.urg{font-family:"IBM Plex Mono",monospace;font-size:9.5px;letter-spacing:.12em;
  text-transform:uppercase;padding:2px 6px;border:1px solid currentColor;margin-left:8px;
  vertical-align:2px;white-space:nowrap}
.urg.immediate{color:var(--critical)} .urg.today{color:var(--high)}
.urg.this-week{color:var(--medium)}

.spine{position:relative;padding:8px 0 8px 132px}
.spine:before{content:"";position:absolute;left:96px;top:0;bottom:0;width:1px;background:var(--spine)}
.tick{position:relative;padding:9px 0;min-height:34px}
.tick .when{position:absolute;left:-132px;width:88px;text-align:right;
  font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--muted);padding-top:2px}
.tick .dot{position:absolute;left:-40px;top:15px;width:9px;height:9px;border-radius:50%;
  background:var(--card);border:2px solid var(--spine)}
.tick.critical .dot{background:var(--critical);border-color:var(--critical);width:11px;height:11px;left:-41px}
.tick.high .dot{background:var(--high);border-color:var(--high)}
.tick.medium .dot{border-color:var(--medium)}
.tick .evt{font-size:13.5px;font-weight:500}
.tick .ctx{font-size:12px;color:var(--muted)}
.tick .hit{font-size:12px;color:var(--critical);margin-top:2px}
.boundary{position:relative;margin:22px 0;padding:7px 0}
.boundary:before{content:"";position:absolute;left:-36px;right:0;top:50%;
  border-top:1px dashed var(--critical)}
.boundary span{position:relative;background:var(--paper);padding-right:12px;
  font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--critical);font-weight:500}

.finding{background:var(--card);border:1px solid var(--rule);border-left:4px solid var(--low);
  margin-bottom:14px}
.finding.critical{border-left-color:var(--critical)}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}
.f-head{padding:16px 20px;display:flex;gap:12px;align-items:baseline;flex-wrap:wrap;
  border-bottom:1px solid var(--rule-soft)}
.sev{font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.13em;
  text-transform:uppercase;font-weight:600;padding:3px 7px;border:1px solid currentColor;
  white-space:nowrap}
.critical .sev{color:var(--critical)} .high .sev{color:var(--high)}
.medium .sev{color:var(--medium)} .low .sev{color:var(--low)}
.f-name{font-family:"IBM Plex Mono",monospace;font-size:15px;font-weight:500}
.f-cat{font-size:11.5px;color:var(--muted)}
.f-count{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--muted)}
.f-body{padding:16px 20px}
.f-body p{margin:0 0 12px}
.lead{font-size:14.5px}
.f-label{font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--muted);display:block;margin-bottom:4px}
.verify{background:var(--wash);border:1px solid var(--rule-soft);padding:12px 14px;font-size:13.5px}
.hitlist{margin:0 0 14px;padding:0;list-style:none}
.hitlist li{border-left:3px solid var(--critical);background:#FBEEEA;padding:11px 14px;
  margin-bottom:6px;font-size:13.5px}
.hitlist li.hi{border-left-color:var(--high);background:#FBF3E8}
.hitlist strong{display:block;margin-bottom:3px}
.chips{margin-top:12px;display:flex;flex-wrap:wrap;gap:6px}
.chip{font-family:"IBM Plex Mono",monospace;font-size:10.5px;padding:3px 8px;background:#EAF0F4;
  border:1px solid var(--rule);color:#40505F}
.chip.warn{background:#FBEEEA;border-color:#E8C4BA;color:var(--critical)}
.chip.wild{background:var(--ink);border-color:var(--ink);color:#fff}
.chip a{color:inherit;text-decoration:none}

table{width:100%;border-collapse:collapse;margin-top:14px;font-size:12.5px}
th{text-align:left;font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--muted);font-weight:500;padding:7px 10px 7px 0;
  border-bottom:1px solid var(--rule)}
td{padding:7px 10px 7px 0;border-bottom:1px solid var(--rule-soft);vertical-align:top}
td.mono{font-family:"IBM Plex Mono",monospace;font-size:11.5px;word-break:break-all}
.dim{color:var(--muted)}

.pattern{background:var(--card);border:1px solid var(--rule);border-top:3px solid var(--ink);
  padding:18px 20px;margin-bottom:12px}
.pattern h3{margin:0 0 8px;font-size:15px;font-weight:600}
.pattern p{margin:0 0 10px;font-size:13.5px;color:#33465A}
.pattern ul{margin:0;padding-left:20px;font-size:13.5px;color:#33465A}
.pattern li{margin-bottom:6px}
.bars td{padding:4px 10px 4px 0;border:0}
.bar{display:inline-block;height:9px;background:var(--medium);vertical-align:middle}
.bar.hot{background:var(--critical)}
.jump{display:flex;flex-wrap:wrap;gap:18px;padding:13px 0;border-bottom:1px solid var(--rule);
    position:sticky;top:0;background:rgba(238,241,244,.96);z-index:10;backdrop-filter:blur(8px)}
.jump a{font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.1em;
    text-transform:uppercase;text-decoration:none;color:var(--muted)}
.jump a:hover,.jump a:focus{color:var(--ink)}
.coverage{border-top:3px solid var(--unknown);background:var(--card);margin-top:28px}
.coverage.complete{border-top-color:var(--good)} .coverage.partial{border-top-color:var(--critical)}
.coverage-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;
    padding:18px 20px;border-bottom:1px solid var(--rule-soft)}
.coverage-head h2{margin:0;padding:0;border:0;color:var(--ink);font-size:13px}
.status{font-family:"IBM Plex Mono",monospace;font-size:10px;text-transform:uppercase;
    letter-spacing:.1em;border:1px solid currentColor;padding:4px 8px;white-space:nowrap}
.status.complete{color:var(--good)} .status.partial{color:var(--critical)}
.status.unknown{color:var(--unknown)}
.coverage-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0}
.coverage-grid>div{padding:15px 20px;border-right:1px solid var(--rule-soft)}
.coverage-grid>div:last-child{border-right:0}
.coverage-grid strong{display:block;font:600 20px/1.2 "IBM Plex Mono",monospace}
.coverage-grid span{display:block;color:var(--muted);font-size:11px;margin-top:4px}
.coverage-note{margin:0;padding:13px 20px;border-top:1px solid var(--rule-soft);
    color:var(--muted);font-size:12.5px}
.controls{position:relative;z-index:1;background:var(--card);border:1px solid var(--rule);
    padding:14px;margin:0 0 18px;box-shadow:0 8px 20px rgba(22,32,42,.08)}
.control-grid{display:grid;grid-template-columns:minmax(180px,2fr) repeat(4,minmax(130px,1fr));
    gap:10px;align-items:end}
.field label{display:block;font-family:"IBM Plex Mono",monospace;font-size:9.5px;
    text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:4px}
.field input,.field select{width:100%;height:38px;border:1px solid var(--rule);background:#fff;
    color:var(--ink);padding:0 10px;font:13px "IBM Plex Sans",sans-serif;border-radius:3px}
.field input:focus,.field select:focus,button:focus{outline:2px solid var(--focus);outline-offset:1px}
.date-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
.control-actions{display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap}
button{height:36px;border:1px solid var(--ink);background:var(--ink);color:#fff;padding:0 13px;
    border-radius:3px;font:500 12px "IBM Plex Sans",sans-serif;cursor:pointer}
button.secondary{background:#fff;color:var(--ink);border-color:var(--rule)}
button:hover{filter:brightness(.95)}
.result-count{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--muted)}
.empty-filter{display:none;border:1px dashed var(--rule);padding:30px;text-align:center;color:var(--muted)}
.state-active{background:#FBEDEC;border-color:#E0B4B0;color:var(--critical)}
.state-removed{background:#EAF4EE;border-color:#B9D7C5;color:var(--good)}
.baseline-above{background:#FFF1DB;border-color:#E6C28C;color:#86500B}
.finding{animation:reveal .22s ease both}
.finding[hidden]{display:none}
@keyframes reveal{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
footer{margin-top:64px;padding-top:20px;border-top:1px solid var(--rule);font-size:12px;
  color:var(--muted);font-family:"IBM Plex Mono",monospace;line-height:1.8}
@media(max-width:720px){
    h1{font-size:31px}h1 .subject{font-size:17px}
    .coverage-grid{grid-template-columns:1fr 1fr}.coverage-grid>div:nth-child(2){border-right:0}
    .control-grid{grid-template-columns:1fr 1fr}.control-grid .search{grid-column:1/-1}
    .controls{position:static}.result-count{width:100%;margin-left:0}
    table{display:block;max-width:100%;overflow-x:auto}
  .spine{padding-left:0}.spine:before{left:5px}
  .tick .when{position:static;width:auto;text-align:left;display:block;margin-bottom:2px}
  .tick{padding-left:26px}.tick .dot{left:1px;top:9px}.boundary:before{left:0}
  .analyst{padding:22px 20px}
}
@media print{body{background:#fff}.finding,.pattern,.queue li{break-inside:avoid}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

DASHBOARD_JS = r"""
(() => {
    const payloadNode = document.getElementById('report-data');
    if (!payloadNode) return;
    const payload = JSON.parse(payloadNode.textContent);
    const cards = Array.from(document.querySelectorAll('.finding'));
    const controls = {
        query: document.getElementById('filter-query'),
        severity: document.getElementById('filter-severity'),
        account: document.getElementById('filter-account'),
        category: document.getElementById('filter-category'),
        state: document.getElementById('filter-state'),
        from: document.getElementById('filter-from'),
        to: document.getElementById('filter-to')
    };
    const values = () => Object.fromEntries(
        Object.entries(controls).map(([key, element]) => [key, element ? element.value : ''])
    );
    const includes = (csv, value) => !value || String(csv || '').split(',').includes(value);
    const eventMatches = (event, filters) => {
        const date = String(event.time_utc || '').slice(0, 10);
        const search = JSON.stringify(event).toLowerCase();
        return (!filters.query || search.includes(filters.query.toLowerCase())) &&
            (!filters.severity || event.severity === filters.severity) &&
            (!filters.account || event.account_id === filters.account) &&
            (!filters.category || event.category === filters.category) &&
            (!filters.state || event.current_state === filters.state) &&
            (!filters.from || date >= filters.from) && (!filters.to || date <= filters.to);
    };
    const apply = () => {
        const filters = values();
        let visible = 0;
        cards.forEach(card => {
            const matches = (!filters.query || card.textContent.toLowerCase().includes(filters.query.toLowerCase())) &&
                (!filters.severity || card.dataset.severity === filters.severity) &&
                includes(card.dataset.accounts, filters.account) &&
                (!filters.category || card.dataset.category === filters.category) &&
                includes(card.dataset.states, filters.state) &&
                (!filters.from || card.dataset.end >= filters.from) &&
                (!filters.to || card.dataset.start <= filters.to);
            card.hidden = !matches;
            if (matches) visible += 1;
        });
        const count = document.getElementById('result-count');
        const empty = document.getElementById('empty-filter');
        if (count) count.textContent = `${visible} of ${cards.length} action groups shown`;
        if (empty) empty.style.display = visible ? 'none' : 'block';
    };
    Object.values(controls).forEach(control => control && control.addEventListener('input', apply));
    document.getElementById('reset-filters')?.addEventListener('click', () => {
        Object.values(controls).forEach(control => { if (control) control.value = ''; });
        apply();
    });
    document.getElementById('print-report')?.addEventListener('click', () => window.print());
    document.getElementById('export-visible')?.addEventListener('click', () => {
        const filtered = payload.events.filter(event => eventMatches(event, values()));
        const blob = new Blob([JSON.stringify({report_id: payload.report_id, events: filtered}, null, 2)],
            {type: 'application/json'});
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${payload.report_id}-visible-events.json`;
        document.body.appendChild(link);
        link.click();
        setTimeout(() => {
            URL.revokeObjectURL(link.href);
            link.remove();
        }, 0);
    });
    apply();
})();
"""

VIEW_TOGGLE_JS = r"""
(() => {
    const toggle = document.getElementById('tech-toggle');
    const label = document.getElementById('view-mode-label');
    if (!toggle || !label) return;
    const KEY = 'aws-audit-view-mode';
    const setMode = (technical) => {
        document.body.classList.toggle('technical', technical);
        toggle.checked = technical;
        label.textContent = technical ? 'Full technical detail' : 'Plain-English summary';
        try { localStorage.setItem(KEY, technical ? 'technical' : 'simple'); } catch (e) {}
    };
    let saved = 'simple';
    try { saved = localStorage.getItem(KEY) || 'simple'; } catch (e) {}
    setMode(saved === 'technical');
    toggle.addEventListener('change', () => setMode(toggle.checked));
})();
"""


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def dashboard_event(row: dict) -> dict:
    return {
        "event_id": row.get("event_id", ""),
        "time_utc": row.get("time_utc", ""),
        "account_id": row.get("account_id", ""),
        "account_name": row.get("account_name", ""),
        "region": row.get("region", ""),
        "event_source": row.get("event_source", ""),
        "event_name": row.get("event_name", ""),
        "severity": row.get("severity", ""),
        "base_severity": row.get("base_severity", ""),
        "category": row.get("category", ""),
        "target_type": row.get("target_type", "unknown"),
        "target_id": row.get("target_id", ""),
        "target_key": row.get("target_key", ""),
        "current_state": row.get("current_state", "unknown"),
        "baseline_status": row.get("baseline_status", "insufficient"),
        "flags": row.get("flags", []),
        "content_findings": row.get("content_findings", []),
        "source_ip": row.get("source_ip", ""),
        "error_code": row.get("error_code", ""),
        "resources": row.get("resources", ""),
        "request_params": row.get("request_params", ""),
    }


def json_for_html(value) -> str:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def render_filter_controls(groups, account_options, categories, states) -> str:
    return (
        "<section class='controls tech' aria-label='Finding filters'><div class='control-grid'>"
        "<div class='field search'><label for='filter-query'>Search evidence</label>"
        "<input id='filter-query' type='search' placeholder='Action, target, account, IP'></div>"
        "<div class='field'><label for='filter-severity'>Severity</label>"
        "<select id='filter-severity'><option value=''>All severities</option>"
        + "".join(f"<option value='{sev}'>{SEV_LABEL[sev]}</option>" for sev in (C, H, M, L))
        + "</select></div><div class='field'><label for='filter-account'>Account</label>"
        "<select id='filter-account'><option value=''>All accounts</option>"
        + "".join(f"<option value='{esc(account_id)}'>{esc(label)}</option>"
                  for account_id, label in account_options)
        + "</select></div><div class='field'><label for='filter-category'>Category</label>"
        "<select id='filter-category'><option value=''>All categories</option>"
        + "".join(f"<option value='{esc(category)}'>{esc(category)}</option>"
                  for category in categories)
        + "</select></div><div class='field'><label for='filter-state'>Current state</label>"
        "<select id='filter-state'><option value=''>All states</option>"
        + "".join(f"<option value='{esc(state)}'>{esc(state.capitalize())}</option>"
                  for state in states)
        + "</select></div></div>"
        "<div class='date-row'><div class='field'><label for='filter-from'>From date</label>"
        "<input id='filter-from' type='date'></div><div class='field'>"
        "<label for='filter-to'>To date</label><input id='filter-to' type='date'></div></div>"
        "<div class='control-actions'><button id='export-visible' type='button'>Export visible JSON</button>"
        "<button id='reset-filters' class='secondary' type='button'>Reset filters</button>"
        "<button id='print-report' class='secondary' type='button'>Print report</button>"
        f"<span class='result-count' id='result-count'>{len(groups)} action groups shown</span>"
        "</div></section><div class='empty-filter' id='empty-filter'>"
        "No action groups match these filters.</div>"
    )


def group_events(rows):
    """
    Group by event name, ordered by strength of evidence rather than by the
    timing-escalated severity. An action that is critical only because it
    happened after the last working day should not sit above one where the
    request parameters show an external account.
    """
    by_event = defaultdict(list)
    for r in rows:
        by_event[r["event_name"]].append(r)

    def rank(kv):
        evts = kv[1]
        return (0 if any(e.get("content_findings") for e in evts) else 1,
                SEV_ORDER[evts[0]["base_severity"]],
                -len(evts), kv[0])
    return sorted(by_event.items(), key=rank)


def employment_status(ctx) -> str:
    """Where the subject stands relative to departure, for HR-facing framing.

    Deliberately independent of per-event severity math: an "active" or
    "notice_period" subject can still have high-severity findings (a risky
    change is still worth reviewing), but nothing is escalated to critical
    purely on timing unless they have actually left. See enrich()'s
    "After last working day" flag, which this mirrors.
    """
    last_dt = ctx.get("_last_day_dt")
    notice_dt = ctx.get("_notice_dt")
    now = datetime.now(timezone.utc)
    if last_dt and now > last_dt:
        return "departed"
    if last_dt or notice_dt:
        return "notice_period"
    return "active"


EMPLOYMENT_STATUS_LABEL = {
    "active": "Currently employed",
    "notice_period": "Notice period — still employed",
    "departed": "Departed",
}


def hr_explainer_paragraphs(ctx) -> list[str]:
    """Plain-English framing for a non-technical reviewer (HR, IT lead).

    Kept separate from the technical caveat above it: that one is aimed at
    someone who already knows what an API call is. This is for someone who
    doesn't, and who will otherwise read "critical" as a verdict rather than
    a priority order.
    """
    status = employment_status(ctx)
    last_day = ctx.get("last_day") or "not supplied"
    notice = ctx.get("notice") or "not supplied"

    paras = [
        "<strong>What this report is.</strong> It lists what this person's AWS account "
        "was used to do, automatically labelled by how much damage that kind of action "
        "could cause if misused — not by whether anything was actually misused. "
        "Software cannot read intent from a log. A “critical” item means "
        "“this is worth a human asking a question,” not “this person did "
        "something wrong.”",
        "<strong>How to read the four levels.</strong> "
        "<strong>Critical</strong> — could grant lasting access or destroy something, "
        "and here it happened after they left. Ask about it the same day. "
        "<strong>High</strong> — a meaningful change to access or security settings; "
        "worth a quick check against a ticket. <strong>Medium</strong> — unusual enough "
        "to log, rarely worth a conversation on its own. <strong>Low</strong> — routine "
        "day-to-day activity.",
        "<strong>What actually makes something suspicious.</strong> Severity alone doesn't. "
        "Look for the combination: no matching change ticket or handover note, activity that "
        "doesn't match this person's normal job, denied or repeatedly-retried attempts "
        "(a sign of someone probing rather than working), and — for anyone who has left — "
        "anything at all happening after their last working day. One of these is a question. "
        "Several together are a reason to escalate.",
    ]

    if status == "active":
        paras.append(
            "<strong>Employment status: currently employed.</strong> No departure date has "
            "been given, so nothing below is measured against one. Every finding here is "
            "ordinary day-to-day activity from someone still doing their job — review it "
            "the way you would any access review, not as an offboarding investigation. "
            "Re-run this report with <code>--last-day</code> once a leaving date is confirmed."
        )
    elif status == "notice_period":
        paras.append(
            f"<strong>Employment status: notice period, still employed</strong> "
            f"(notice given {esc(notice)}, last working day {esc(last_day)}). Continued access "
            "and activity during notice is expected — this person still has a job to do "
            "until they leave. Nothing is escalated to critical purely for timing yet; that "
            "only happens for activity dated after the last working day above, which hasn't "
            "arrived. Treat findings here as normal handover work unless something is clearly "
            "outside their role."
        )
    else:
        paras.append(
            f"<strong>Employment status: departed</strong> (last working day {esc(last_day)}). "
            "Anything timestamped after that date is automatically escalated to critical and "
            "listed on the timeline below — this person should have had no work reason to "
            "touch these systems once they'd left. There are innocent explanations (a scheduled "
            "job, a shared service credential, a colleague using their own access from a similar "
            "session), but each one needs to be confirmed, not assumed."
        )
    return paras


def parse_review_date(value: str, tz, end_of_day: bool = False) -> datetime:
    """Parse a date-only CLI boundary in the report's display timezone."""
    parsed = datetime.strptime(value, "%Y-%m-%d")
    if end_of_day:
        parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed.replace(tzinfo=tz).astimezone(timezone.utc)


def render_html(rows, sequences, analysis, ctx) -> str:
    counts = Counter(r["severity"] for r in rows)
    groups = group_events(rows)
    coverage = ctx.get("coverage", {})
    coverage_status = str(coverage.get("status", "unknown")).lower()
    coverage_class = coverage_status if coverage_status in {"complete", "partial"} else "unknown"
    account_options = sorted({
        (str(row.get("account_id", "")), str(row.get("account_name") or row.get("account_id", "")))
        for row in rows if row.get("account_id")
    })
    categories = sorted({str(row.get("category", "")) for row in rows if row.get("category")})
    states = sorted({str(row.get("current_state", "unknown")) for row in rows})
    payload = {
        "schema_version": 1,
        "report_id": ctx.get("report_id", "aws-offboarding-report"),
        "input_sha256": ctx.get("input_sha256", ""),
        "coverage": coverage,
        "events": [dashboard_event(row) for row in rows],
    }

    p = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>AWS offboarding review — {esc(ctx['user'])}</title>",
         "<link rel='preconnect' href='https://fonts.googleapis.com'>",
         "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>",
         "<link href='https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600"
         "&family=IBM+Plex+Sans:wght@400;500;600&display=swap' rel='stylesheet'>",
         f"<style>{CSS}</style></head><body><div class='wrap'>"]

    p.append("<header class='case' id='overview'><div class='eyebrow'>AWS offboarding control room</div>")
    p.append(f"<h1>Access and activity review<span class='subject'>{esc(ctx['user'])}</span></h1>")
    p.append("<dl class='meta'>")
    for label, value in [("Review window", ctx["window"]),
                         ("Accounts with activity", ctx["n_accounts"]),
                         ("Regions touched", ctx["n_regions"]),
                         ("Events matched", ctx["n_events"]),
                         ("Coverage", coverage_status.capitalize()),
                         ("Event scope", str(coverage.get("event_scope", "management")).capitalize()),
                         ("Notice given", ctx["notice"] or "not supplied"),
                         ("Last working day", ctx["last_day"] or "not supplied"),
                         ("Employment status", EMPLOYMENT_STATUS_LABEL[employment_status(ctx)]),
                         ("Report generated", ctx["generated"])]:
        p.append(f"<div><dt>{esc(label)}</dt><dd>{esc(value)}</dd></div>")
    p.append("</dl>")
    p.append("<p class='caveat'>Ratings describe what an action <em>can</em> do, and therefore what "
             "warrants a human check. They are not findings of wrongdoing. Most flagged actions in "
             "an engineer's history are their job. Confirm each item against change tickets and "
             "planned work before drawing any conclusion.</p></header>")

    p.append("<section class='hr-guide' id='hr-guide'>"
             "<h2>Reading this report without a technical background</h2>")
    for para in hr_explainer_paragraphs(ctx):
        p.append(f"<p>{para}</p>")
    p.append("</section>")

    p.append(
        "<div class='view-switch'>"
        "<label class='switch'><input type='checkbox' id='tech-toggle' "
        "aria-describedby='view-mode-hint'><span class='slider'></span></label>"
        "<span class='vs-label'>Showing:</span> "
        "<span class='vs-mode' id='view-mode-label'>Plain-English summary</span>"
        "<span class='vs-label' id='view-mode-hint'>— switch on for API names, "
        "timestamps, regions, and raw request data</span>"
        "</div>")

    p.append("<nav class='jump tech' aria-label='Dashboard sections'>"
             "<a href='#overview'>Overview</a><a href='#hr-guide'>Read this first</a>"
             "<a href='#coverage'>Coverage</a>"
             "<a href='#timeline'>Timeline</a><a href='#findings'>Findings</a>"
             "<a href='#activity'>Activity</a></nav>")
    p.append(render_filter_controls(groups, account_options, categories, states))

    p.append("<div class='tally'>")
    for sev in (C, H, M, L):
        p.append(f"<div class='{sev}'><div class='n'>{counts.get(sev,0)}</div>"
                 f"<div class='k'>{SEV_LABEL[sev]}</div></div>")
    p.append(f"<div><div class='n'>{ctx['n_accounts']}</div><div class='k'>Accounts</div></div></div>")

    requested_units = coverage.get("requested_units", "unknown")
    successful_units = coverage.get("successful_units", "unknown")
    failed_units = coverage.get("failed_units", "unknown")
    truncated = coverage.get("request_params_truncated", 0)
    p.append(f"<section class='coverage tech {coverage_class}' id='coverage'>"
             "<div class='coverage-head'><div><h2>Collection coverage</h2>"
             "<div class='dim'>Completeness is evidence. Missing access is not zero activity.</div></div>"
             f"<span class='status {coverage_class}'>{esc(coverage_status)}</span></div>")
    p.append("<div class='coverage-grid'>"
             f"<div><strong>{esc(successful_units)}</strong><span>Successful units</span></div>"
             f"<div><strong>{esc(failed_units)}</strong><span>Failed or denied units</span></div>"
             f"<div><strong>{esc(requested_units)}</strong><span>Account-region units</span></div>"
             f"<div><strong>{esc(truncated)}</strong><span>Truncated parameter fields</span></div></div>")
    limitations = coverage.get("limitations") or []
    if limitations:
        p.append("<p class='coverage-note'>" + " ".join(esc(item) for item in limitations) + "</p>")
    p.append("</section>")

    if analysis:
        meta = analysis.get("_meta", {})
        searched = len(meta.get("searches", []))
        p.append("<h2>Analyst assessment</h2><div class='analyst'>")
        p.append(f"<div class='badge'>Analysis model: {esc(meta.get('model','external'))}"
                 f"{f' · {searched} web searches' if searched else ''}</div>")
        if analysis.get("headline"):
            p.append(f"<h3>{esc(analysis['headline'])}</h3>")
        for para in str(analysis.get("assessment", "")).split("\n"):
            if para.strip():
                p.append(f"<p>{esc(para.strip())}</p>")
        if analysis.get("confidence"):
            p.append(f"<div class='conf'><strong>Confidence: {esc(analysis['confidence'])}.</strong> "
                     f"{esc(analysis.get('confidence_note',''))}</div>")
        p.append("</div>")

        actions = analysis.get("priority_actions") or []
        if actions:
            p.append("<h2>Investigation queue</h2><ol class='queue'>")
            for a in sorted(actions, key=lambda x: x.get("rank", 99)):
                urg = str(a.get("urgency", "")).lower().replace(" ", "-")
                p.append(f"<li><span class='act'>{esc(a.get('action',''))}"
                         f"<span class='urg {esc(urg)}'>{esc(a.get('urgency',''))}</span></span>"
                         f"<span class='why'>{esc(a.get('rationale',''))}</span></li>")
            p.append("</ol>")

        gaps = analysis.get("blind_spots") or []
        qs = analysis.get("questions_for_the_team") or []
        if gaps or qs:
            p.append("<h2>Gaps and open questions</h2>")
            if gaps:
                p.append("<div class='pattern'><h3>What this data cannot show</h3><ul>"
                         + "".join(f"<li>{esc(g)}</li>" for g in gaps) + "</ul></div>")
            if qs:
                p.append("<div class='pattern'><h3>Questions for the team</h3><ul>"
                         + "".join(f"<li>{esc(q)}</li>" for q in qs) + "</ul></div>")

    if sequences:
        p.append("<div class='tech'><h2>Sequences worth attention</h2>")
        for s in sequences:
            p.append(f"<div class='pattern'><h3>{esc(s['title'])}</h3><p>{esc(s['body'])}</p>"
                     "<div class='chips'>"
                     f"<span class='chip'>Correlation: {esc(s.get('confidence','context'))}</span>"
                     f"<span class='chip'>{esc(s.get('target_key') or 'multiple targets')}</span>"
                     + "".join(f"<span class='chip'>{esc(e)}</span>" for e in s["events"][:8])
                     + "</div></div>")
        p.append("</div>")

    # The spine earns its place by being short. An event qualifies on its own
    # merits (curated as serious), on evidence (a parameter-level finding), or
    # because it changed something when the person should have had no access.
    # Read-only calls are excluded even post-departure: they are worth knowing
    # about, but as a count, not as fifty individual ListBuckets ticks.
    def is_read(name):
        return name.startswith(("Get", "List", "Describe", "Head", "Search", "Lookup"))

    notable = [r for r in rows
               if (r.get("curated") and r["base_severity"] in (C, H))
               or r.get("content_findings")
               or ("After last working day" in r["flags"] and not is_read(r["event_name"]))]
    post_reads = [r for r in rows
                  if "After last working day" in r["flags"] and is_read(r["event_name"])]
    notable.sort(key=lambda r: r["_ts"])
    ticks = []
    for r in notable:
        key = (r["_local"].date(), r["event_name"], r.get("account_id"))
        if ticks and ticks[-1]["key"] == key:
            ticks[-1]["n"] += 1
            ticks[-1]["regions"].add(r.get("region", ""))
        else:
            ticks.append({"key": key, "row": r, "n": 1, "regions": {r.get("region", "")}})

    p.append("<div class='tech'><h2 id='timeline'>Timeline of notable actions</h2>")
    if ticks or post_reads:
        p.append("<div class='spine'>")
        done = False
        cutoff = ctx["_last_day_dt"] or ctx["_notice_dt"]
        cut_label = "Last working day" if ctx["_last_day_dt"] else "Notice given"
        for t in ticks[:100]:
            r = t["row"]
            if cutoff and not done and r["_ts"] > cutoff:
                p.append(f"<div class='boundary'><span>{cut_label} — "
                         f"{cutoff.astimezone(ctx['tz']).strftime('%d %b %Y')}</span></div>")
                done = True
            p.append(f"<div class='tick {r['severity']}'>")
            p.append(f"<div class='when'>{r['_local'].strftime('%d %b %H:%M')}</div>"
                     "<div class='dot'></div>")
            mult = f" <span class='dim'>×{t['n']}</span>" if t["n"] > 1 else ""
            p.append(f"<div class='evt'>{esc(r['event_name'])}{mult}</div>")
            bits = [r.get("account_name") or r.get("account_id"),
                    ", ".join(sorted(x for x in t["regions"] if x))]
            if r["flags"]:
                bits.append(" · ".join(r["flags"]))
            p.append(f"<div class='ctx'>{esc(' · '.join(b for b in bits if b))}</div>")
            for cf in r.get("content_findings", [])[:2]:
                p.append(f"<div class='hit'>{esc(cf['title'])}</div>")
            p.append("</div>")
        if len(ticks) > 100:
            p.append(f"<div class='tick'><div class='ctx'>… and {len(ticks)-100} further entries</div></div>")
        if post_reads:
            top = ", ".join(n for n, _ in Counter(
                r["event_name"] for r in post_reads).most_common(4))
            p.append(f"<div class='tick critical'><div class='when'>after</div><div class='dot'></div>"
                     f"<div class='evt'>{len(post_reads)} read-only calls after the last working day</div>"
                     f"<div class='ctx'>Not listed individually. Most frequent: {esc(top)}. "
                     "Access should have been revoked by this point regardless of what was read.</div></div>")
        p.append("</div>")
    else:
        p.append("<p class='dim'>No high or critical actions in this window. The activity below "
                 "is routine change.</p>")
    p.append("</div>")

    p.append("<h2 id='findings'>Actions requiring context</h2>")
    for name, evts in groups:
        f = evts[0]
        sev = f["severity"]
        group_accounts = ",".join(sorted({str(event.get("account_id", "")) for event in evts}))
        group_states = ",".join(sorted({str(event.get("current_state", "unknown")) for event in evts}))
        group_dates = sorted(event["_local"].strftime("%Y-%m-%d") for event in evts)
        p.append(f"<article class='finding {sev}' data-event='{esc(name)}' "
                 f"data-severity='{esc(sev)}' data-accounts='{esc(group_accounts)}' "
                 f"data-category='{esc(f['category'])}' data-states='{esc(group_states)}' "
                 f"data-start='{group_dates[0]}' data-end='{group_dates[-1]}'>"
                 "<div class='f-head'>")
        p.append(f"<span class='sev'>{SEV_LABEL[sev]}</span>")
        p.append(f"<span class='f-name'>{esc(name)}</span>")
        p.append(f"<span class='f-cat'>{esc(f['category'])}</span>")
        p.append(f"<span class='f-count'>{len(evts)}×</span></div><div class='f-body'>")

        seen, hits = set(), []
        for e in evts:
            for cf in e.get("content_findings", []):
                if cf["title"] not in seen:
                    seen.add(cf["title"])
                    hits.append(cf)
        if hits:
            p.append("<ul class='hitlist'>")
            for cf in hits:
                cls = "" if cf["severity"] == C else "hi"
                p.append(f"<li class='{cls}'><strong>{esc(cf['title'])}</strong>"
                         f"{esc(cf['detail'])}</li>")
            p.append("</ul>")

        p.append(f"<p class='lead'>{esc(f['description'])}</p>")
        p.append(f"<p><span class='f-label'>Why it matters</span>{esc(f['why'])}</p>")
        p.append(f"<div class='verify'><span class='f-label'>What to verify</span>"
                 f"{esc(f['verify'])}</div>")

        chips = [f"<span class='chip tech'>MITRE: {esc(t)}</span>" for t in f.get("tactics", [])]
        if f.get("used_in_wild"):
            inc = f.get("incidents") or []
            if inc and inc[0].get("link"):
                chips.append(f"<span class='chip wild'><a href='{esc(inc[0]['link'])}' "
                             "target='_blank' rel='noopener'>Seen in real attacks ↗</a></span>")
            else:
                chips.append("<span class='chip wild'>Seen in real attacks</span>")
        for flag, n in Counter(x for e in evts for x in e["flags"]).most_common():
            warn = "warn" if ("After last" in flag or "Failed" in flag) else ""
            chips.append(f"<span class='chip {warn}'>{esc(flag)}{f' ×{n}' if n>1 else ''}</span>")
        state_counts = Counter(str(event.get("current_state", "unknown")) for event in evts)
        if state_counts.get("active"):
            chips.append(f"<span class='chip state-active'>Still active ×{state_counts['active']}</span>")
        if state_counts.get("removed"):
            chips.append(f"<span class='chip state-removed'>Removed ×{state_counts['removed']}</span>")
        if any(event.get("baseline_status") == "above" for event in evts):
            chips.append("<span class='chip baseline-above'>Above peer baseline</span>")
        if chips:
            p.append("<div class='chips'>" + "".join(chips) + "</div>")

        p.append("<div class='tech'><table><tr><th>When (local)</th><th>Account</th><th>Region</th>"
             "<th>Target</th><th>Resource / parameters</th><th>Source IP</th></tr>")
        for e in evts[:12]:
            detail = e.get("resources") or e.get("request_params") or ""
            p.append(f"<tr><td class='mono'>{e['_local'].strftime('%d %b %Y %H:%M')}</td>"
                     f"<td>{esc(e.get('account_name') or e.get('account_id'))}</td>"
                     f"<td class='mono'>{esc(e.get('region'))}</td>"
                     f"<td class='mono dim'>{esc(e.get('target_id') or 'unknown')}</td>"
                     f"<td class='mono dim'>{esc(detail[:220])}</td>"
                     f"<td class='mono dim'>{esc(e.get('source_ip'))}</td></tr>")
        p.append("</table>")
        if len(evts) > 12:
            p.append(f"<p class='dim' style='margin-top:10px;font-size:12px'>"
                     f"Showing 12 of {len(evts)}. Full detail is in the CSV.</p>")
        p.append("</div></div></article>")

    by_day = Counter(r["_local"].strftime("%Y-%m-%d") for r in rows)
    if by_day:
        peak = max(by_day.values())
        p.append("<h2 id='activity'>Activity by day</h2><table class='bars'>")
        for day in sorted(by_day):
            n = by_day[day]
            hot = "hot" if n >= peak * 0.75 else ""
            p.append(f"<tr><td class='mono' style='width:96px'>{esc(day)}</td>"
                     f"<td style='width:52px' class='mono'>{n}</td>"
                     f"<td><span class='bar {hot}' style='width:{max(2,int(320*n/peak))}px'>"
                     "</span></td></tr>")
        p.append("</table>")

    p.append("<h2>Activity by account</h2><table><tr><th>Account</th><th>Events</th>"
             "<th>Critical</th><th>High</th></tr>")
    keyed = defaultdict(list)
    for r in rows:
        keyed[f"{r.get('account_name')} ({r.get('account_id')})"].append(r)
    for acct, rs in sorted(keyed.items(), key=lambda kv: -len(kv[1])):
        c = sum(1 for r in rs if r["severity"] == C)
        h = sum(1 for r in rs if r["severity"] == H)
        p.append(f"<tr><td>{esc(acct)}</td><td class='mono'>{len(rs)}</td>"
                 f"<td class='mono'>{c or ''}</td><td class='mono'>{h or ''}</td></tr>")
    p.append("</table>")

    p.append(f"<footer>Report {esc(ctx.get('report_id',''))} · Generated {esc(ctx['generated'])} "
             f"· Times in {esc(ctx['tzname'])}<br>"
             f"Source scope: {esc(coverage.get('event_scope','management'))}. Data events are "
             "included only when explicitly present in the source manifest. Any period where logging "
             "was reduced remains a blind spot.<br>"
             "Event intelligence includes data from TrailDiscover "
             "(github.com/adanalvarez/TrailDiscover, CC BY 4.0). Technique coverage informed by "
             "Wavestone RiskInsight, Hacking the Cloud, HackTricks Cloud, and Datadog Stratus "
             "Red Team.</footer>"
             f"<script type='application/json' id='report-data'>{json_for_html(payload)}</script>"
             f"<script>{DASHBOARD_JS}</script>"
             f"<script>{VIEW_TOGGLE_JS}</script></div></body></html>")
    return "\n".join(p)


def md_escape(value) -> str:
    lines = []
    for line in str(value if value is not None else "").splitlines() or [""]:
        escaped = html.escape(line, quote=False).replace("\\", "\\\\")
        for char in ("`", "*", "_", "{", "}", "[", "]", "#", "|"):
            escaped = escaped.replace(char, f"\\{char}")
        lines.append(escaped)
    return "<br>".join(lines)


def render_markdown(rows, sequences, analysis, ctx) -> str:
    counts = Counter(r["severity"] for r in rows)
    coverage = ctx.get("coverage", {})
    out = [f"# AWS offboarding review - {md_escape(ctx['user'])}", "",
           f"- **Window:** {md_escape(ctx['window'])}",
           f"- **Accounts with activity:** {ctx['n_accounts']}",
           f"- **Events matched:** {ctx['n_events']}",
           f"- **Collection coverage:** {md_escape(coverage.get('status', 'unknown'))}",
           f"- **Event scope:** {md_escape(coverage.get('event_scope', 'management'))}",
           f"- **Notice given:** {md_escape(ctx['notice'] or 'not supplied')}",
           f"- **Last working day:** {md_escape(ctx['last_day'] or 'not supplied')}",
           f"- **Employment status:** {md_escape(EMPLOYMENT_STATUS_LABEL[employment_status(ctx)])}",
           f"- **Findings:** {counts.get(C,0)} critical, {counts.get(H,0)} high, "
           f"{counts.get(M,0)} medium, {counts.get(L,0)} low", "",
           "> Ratings describe what an action can do, not what it did. Confirm against change "
           "tickets before drawing conclusions.", "",
           "## Reading this report without a technical background", ""]
    for para in hr_explainer_paragraphs(ctx):
        # The HTML strings use <strong>/<code> for emphasis; keep Markdown legible
        # by converting those two tags rather than maintaining a second copy of the text.
        md_para = (para.replace("<strong>", "**").replace("</strong>", "**")
                        .replace("<code>", "`").replace("</code>", "`"))
        out.append(md_para)
        out.append("")

    if analysis:
        out += ["## Analyst assessment", "",
            f"**{md_escape(analysis.get('headline',''))}**", "",
            md_escape(analysis.get("assessment", "")), "",
            f"*Confidence: {md_escape(analysis.get('confidence',''))}* - "
            f"{md_escape(analysis.get('confidence_note',''))}", ""]
        if analysis.get("priority_actions"):
            out += ["### Investigation queue", ""]
            for a in sorted(analysis["priority_actions"], key=lambda x: x.get("rank", 99)):
                out.append(f"{a.get('rank','-')}. **[{md_escape(a.get('urgency',''))}]** "
                           f"{md_escape(a.get('action',''))}  \n   "
                           f"{md_escape(a.get('rationale',''))}")
            out.append("")
        for key, title in [("blind_spots", "What this data cannot show"),
                           ("questions_for_the_team", "Questions for the team")]:
            if analysis.get(key):
                out += [f"### {title}", ""] + [f"- {md_escape(x)}"
                                                   for x in analysis[key]] + [""]

    if sequences:
        out += ["## Sequences worth attention", ""]
        for s in sequences:
            out += [f"**{md_escape(s['title'])}** - {md_escape(s['body'])} "
                    f"(correlation: {md_escape(s.get('confidence', 'context'))})", ""]

    groups = group_events(rows)

    out += ["## Actions explained", ""]
    for name, evts in groups:
        f = evts[0]
        wild = " · seen in real attacks" if f.get("used_in_wild") else ""
        out += [f"### {md_escape(name)} - {SEV_LABEL[f['severity']]} - "
            f"{md_escape(f['category'])} - {len(evts)}x{wild}", ""]
        seen = set()
        for e in evts:
            for cf in e.get("content_findings", []):
                if cf["title"] not in seen:
                    seen.add(cf["title"])
                    out.append(f"> **{md_escape(cf['title'])}** - {md_escape(cf['detail'])}")
        if seen:
            out.append("")
        out += [md_escape(f["description"]), "",
            f"*Why it matters:* {md_escape(f['why'])}", "",
            f"*What to verify:* {md_escape(f['verify'])}", ""]
        if f.get("tactics"):
            out += [f"MITRE ATT&CK: {md_escape(', '.join(f['tactics']))}", ""]
        flags = Counter(x for e in evts for x in e["flags"])
        if flags:
            out += ["Flags: " + ", ".join(f"{md_escape(k)} x{v}" if v > 1 else md_escape(k)
                                          for k, v in flags.most_common()), ""]
        out += ["| When (local) | Account | Region | Target | Source IP |",
                "| --- | --- | --- | --- | --- |"]
        for e in evts[:12]:
            out.append(f"| {e['_local']:%d %b %Y %H:%M} | "
                       f"{md_escape(e.get('account_name',''))} | "
                       f"{md_escape(e.get('region',''))} | "
                       f"{md_escape(e.get('target_id','unknown'))} | "
                       f"{md_escape(e.get('source_ip',''))} |")
        if len(evts) > 12:
            out.append(f"\n_Showing 12 of {len(evts)}; see CSV for the rest._")
        out.append("")

    out += ["---", "", "Event intelligence includes data from "
            "[TrailDiscover](https://github.com/adanalvarez/TrailDiscover) (CC BY 4.0)."]
    return "\n".join(out)


# ==========================================================================
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Build an explained risk report from CloudTrail audit output.")
    ap.add_argument("input", help="aws_offboarding_audit.json (or .csv)")
    ap.add_argument("--user", help="Subject of the review (defaults to collector manifest).")
    ap.add_argument("--notice-date", help="YYYY-MM-DD notice was given.")
    ap.add_argument("--last-day", help="YYYY-MM-DD last working day. Later activity is critical.")
    ap.add_argument("--manifest", help="Collector manifest JSON (auto-detected by default).")
    ap.add_argument("--state", help="Current-state snapshot JSON keyed by normalized target.")
    ap.add_argument("--baseline", help="Peer baseline JSON with event means and sample size.")
    ap.add_argument("--sequence-hours", type=int, default=24,
                    help="Maximum ordered sequence window. Default 24 hours.")
    ap.add_argument("--org-accounts", nargs="*", default=[],
                    help="Your AWS account IDs, so references to outside accounts get flagged. "
                         "aws organizations list-accounts --query 'Accounts[].Id' --output text")
    ap.add_argument("--timezone", default="Europe/London")
    ap.add_argument("--work-start", type=int, default=8)
    ap.add_argument("--work-end", type=int, default=19)
    ap.add_argument("--no-enrich", action="store_true", help="Skip the TrailDiscover download.")
    ap.add_argument("--refresh-intel", action="store_true", help="Force-refresh the cached dataset.")
    ap.add_argument("--analyze", action="store_true", help="Run the Claude analyst pass.")
    ap.add_argument("--api-key", help="Anthropic API key (else ANTHROPIC_API_KEY).")
    ap.add_argument("--model", default="claude-sonnet-5")
    ap.add_argument("--no-search", action="store_true",
                    help="Disable web search in the analyst pass.")
    ap.add_argument("--redact", action="store_true",
                    help="Hash account IDs and IPs before sending anything to the API.")
    ap.add_argument("--out", default="aws_offboarding_report")
    args = ap.parse_args(argv)

    try:
        tz = ZoneInfo(args.timezone) if ZoneInfo else timezone.utc
    except Exception:
        ap.error(f"unknown timezone: {args.timezone}")
    tzname = args.timezone if ZoneInfo else "UTC"
    if not 0 <= args.work_start <= 23 or not 1 <= args.work_end <= 24:
        ap.error("working hours must be within 0..24")
    if args.work_start >= args.work_end:
        ap.error("--work-start must be earlier than --work-end")
    if args.sequence_hours <= 0:
        ap.error("--sequence-hours must be greater than zero")
    if any(len(account) != 12 or not account.isdigit() for account in args.org_accounts):
        ap.error("every --org-accounts value must be a 12-digit AWS account ID")

    try:
        notice_dt = parse_review_date(args.notice_date, tz) if args.notice_date else None
        last_dt = parse_review_date(args.last_day, tz, end_of_day=True) if args.last_day else None
    except ValueError:
        ap.error("--notice-date and --last-day must use YYYY-MM-DD")

    try:
        raw = load_rows(args.input)
        manifest = load_manifest(args.input, args.manifest)
        state = load_json_object(args.state)
        baseline = load_json_object(args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        ap.error(str(exc))
    if not raw and not manifest:
        sys.exit("Input contains no events and no collector manifest was found.")

    if args.no_enrich:
        print("  ! TrailDiscover enrichment disabled; using the built-in catalogue only.",
              file=sys.stderr)
        td = {}
    else:
        td = load_traildiscover(refresh=args.refresh_intel)
    if td:
        print(f"  Enriched with {len(td)} catalogued events from TrailDiscover.", file=sys.stderr)

    rows = enrich(raw, td, tz, notice_dt, last_dt, args.work_start, args.work_end,
                  set(args.org_accounts))
    if raw and not rows:
        sys.exit("No events could be parsed. Check the input file.")

    apply_current_state(rows, state)
    baseline_summary = apply_baseline(rows, baseline)
    sequences = detect_sequences(rows, max_hours=args.sequence_hours)
    times = [r["_ts"] for r in rows]
    manifest_window = manifest.get("window", {}) if isinstance(manifest.get("window", {}), dict) else {}
    if times:
        window = f"{min(times).astimezone(tz):%d %b %Y} – {max(times).astimezone(tz):%d %b %Y}"
    elif manifest_window.get("start") and manifest_window.get("end"):
        window = f"{manifest_window['start']} - {manifest_window['end']}"
    else:
        window = "No event timestamps"
    input_hash = input_sha256(args.input)
    report_contract = json.dumps({
        "input_sha256": input_hash,
        "notice": args.notice_date,
        "last_day": args.last_day,
        "timezone": args.timezone,
        "sequence_hours": args.sequence_hours,
        "state": bool(state),
        "baseline": bool(baseline),
    }, sort_keys=True, separators=(",", ":"))
    report_id = f"aws-offboarding-report-{hashlib.sha256(report_contract.encode()).hexdigest()[:16]}"
    coverage = manifest or {
        "status": "unknown",
        "event_scope": next(iter({row.get("event_scope", "management") for row in rows}),
                            "management"),
        "limitations": ["No collector manifest was supplied; collection completeness is unknown."],
    }
    ctx = {"user": args.user or manifest.get("subject") or "(unnamed)",
           "window": window,
           "n_accounts": len({r.get("account_id") for r in rows}),
           "n_regions": len({r.get("region") for r in rows}),
           "n_events": len(rows),
           "notice": args.notice_date, "last_day": args.last_day,
           "generated": datetime.now(tz).strftime("%d %b %Y %H:%M %Z"),
           "report_id": report_id, "input_sha256": input_hash,
           "coverage": coverage, "baseline": baseline_summary,
           "state_metadata": {"available": bool(state),
                              "checked_at": state.get("checked_at", ""),
                              "source": state.get("source", "")},
           "tz": tz, "tzname": tzname,
           "_notice_dt": notice_dt, "_last_day_dt": last_dt}

    analysis = None
    if args.analyze and rows:
        try:
            from audit_analyst import analyse
            analysis = analyse(rows, sequences, ctx, api_key=args.api_key, model=args.model,
                               use_search=not args.no_search, redact=args.redact)
        except Exception as exc:
            print(f"  ! Analyst pass failed: {exc}\n    Continuing without it.", file=sys.stderr)

    with open(f"{args.out}.html", "w", encoding="utf-8") as fh:
        fh.write(render_html(rows, sequences, analysis, ctx))
    with open(f"{args.out}.md", "w", encoding="utf-8") as fh:
        fh.write(render_markdown(rows, sequences, analysis, ctx))
    summary_path = f"{args.out}.summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(build_report_summary(rows, sequences, ctx), fh, indent=2, sort_keys=True)

    counts = Counter(r["severity"] for r in rows)
    n_hits = sum(1 for r in rows if r.get("content_findings"))
    print(f"{len(rows)} events · {counts.get(C,0)} critical, {counts.get(H,0)} high, "
          f"{counts.get(M,0)} medium, {counts.get(L,0)} low · "
          f"{n_hits} with parameter-level findings")
    print(f"Wrote {args.out}.html, {args.out}.md, and {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
