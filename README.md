# 🛡️ AWS Offboarding Audit

**Cross-account CloudTrail collection, backdoor detection, and a local investigation dashboard for cloud engineer offboarding.**

[![Security and tests](https://github.com/CaputoDavide93/AWS-OffBoarding-Audit/actions/workflows/security.yml/badge.svg)](https://github.com/CaputoDavide93/AWS-OffBoarding-Audit/actions/workflows/security.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![AWS CloudTrail](https://img.shields.io/badge/AWS-CloudTrail-FF9900?logo=amazonwebservices&logoColor=white)
![Read-only](https://img.shields.io/badge/AWS%20access-read--only-2E7D32)
![Secrets](https://img.shields.io/badge/Secrets-Gitleaks-2E7D32)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Read-only, by design](#-read-only-by-design)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Current-State Checks](#-current-state-checks)
- [Peer Baseline](#-peer-baseline)
- [CloudTrail Lake](#-cloudtrail-lake)
- [External Analysis](#-external-analysis)
- [Offboarding Playbook](#-offboarding-playbook)
- [Security](#-security)
- [Testing](#-testing)
- [Limits](#-limits)
- [Documentation](#-documentation)

---

## 🎯 Overview

AWS Offboarding Audit reviews a departing engineer's activity across every AWS account available
through IAM Identity Center. It collects CloudTrail events, checks request parameters for durable
access and destructive changes, and builds a portable HTML dashboard for the security or IT team.

A fully synthetic example is in [docs/example-report.html](docs/example-report.html). Download it
and open it locally to see the dashboard before running anything; no account IDs in it are real.

The report separates three different facts:

| Signal | Meaning |
| --- | --- |
| **Intrinsic severity** | What the API action can do |
| **Timing severity** | Whether it happened during notice or after the last working day |
| **Current state** | Whether the affected resource or access still exists |

Severity is a review priority, not a statement of intent. Confirm every item against change tickets
and planned work before taking action.

The report opens in plain-English mode: a short explainer for HR or an IT lead, framed by whether
the person is still employed, on notice, or already departed. A switch at the top reveals the
underlying API names, timestamps, regions, and raw request parameters for whoever needs them.

## 🔒 Read-only, by design

Every AWS call this project makes is a `Get*`, `List*`, `Describe*`, or `LookupEvents` call: the
kind you'd use to read state, never to change it. There is no `Create*`, `Put*`, `Delete*`,
`Update*`, `Terminate*`, `Modify*`, `Attach*`/`Detach*`, or `Revoke*` call anywhere in this
codebase. Running it cannot alter, disable, or delete anything in your AWS accounts.

The only network calls that leave AWS entirely are the optional [external analysis](#-external-analysis)
pass to the Anthropic API, and even that sends a bounded findings digest, never raw logs.

## ✨ Features

- 🔎 **Exact identity matching** across SSO usernames, session ARNs, principal IDs, IAM usernames,
  and Identity Center session issuers
- 🌍 **Cross-account collection** with per-account and per-region coverage, failures, denials, and
  resumable checkpoints
- 🧩 **Parameter inspection** for external trust, wildcard policies, public resources, long-lived
  credentials, open security groups, destructive lifecycle rules, and logging changes
- 🔗 **Bounded sequence correlation** requiring ordered activity from the same principal, account,
  target, and time window, with optional two-hypothesis AI interpretation
- 📊 **Paged interactive dashboard** with a 1-10 evidence review priority plus search and severity,
  account, category, date, and current-state filters
- 🧭 **Plain-language assessments** that separate likely routine activity, items to watch, and
  evidence that needs prompt investigation without claiming to infer intent
- 👔 **HR-facing by default**: a non-technical explainer opens first, framed by employment status
  (employed, on notice, or departed), with a switch to reveal full technical detail on demand
- 📋 **Evidence-aware readiness checklist** that separates report-backed checks from manual
  identity, credential, session, secret-rotation, and handover controls
- ✅ **Read-only reconciliation** for IAM users and roles, Lambda URLs, snapshots, buckets, security
  groups, KMS keys, databases, and CloudTrail trails
- 📈 **Peer baselines** built from comparable historical or colleague audit files
- 🗄️ **CloudTrail Lake support** for management and data events when the event data store records
  them
- 🔐 **Secret-safe workflow** with ignored evidence files, pre-commit and pre-push Gitleaks checks,
  and optional `age` encryption for archives

## 🏗 Architecture

```mermaid
flowchart LR
    SSO["IAM Identity Center"] --> COLLECT["Event History collector"]
    LAKE["CloudTrail Lake export/query"] --> EVENTS["Normalised event JSON"]
    COLLECT --> EVENTS
    EVENTS --> INTEL["Catalogue + parameter detectors"]
    EVENTS --> STATE["Read-only current-state checks"]
    EVENTS --> BASE["Peer baseline"]
    INTEL --> REPORT["Interactive HTML dashboard"]
    STATE --> REPORT
    BASE --> REPORT
```

Collection and reporting remain separate. You can rebuild the dashboard from saved event JSON
without querying AWS again.

## ⚡ Quick Start

### Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp audit-config.example.yaml audit-config.yaml
```

`audit-config.yaml` is ignored by Git. Store organization account IDs, SSO settings, timezone, and
working hours there. The `collector:` block controls collection; the `report:` block controls report
defaults. Command-line values override both.

### Check the scope

```bash
aws sso login --sso-session company

.venv/bin/python aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --preflight
```

Preflight discovers accounts and writes the collection plan without querying CloudTrail.

### Collect and build the dashboard

```bash
.venv/bin/python aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --out aws_offboarding_report \
  --open
```

Add `--resume` after an interrupted collection. The dashboard is a self-contained local HTML file
and does not need a web server.

## ✅ Current-State Checks

CloudTrail records a historical change. It cannot prove that the change still exists. Run the
read-only reconciler after collection:

```bash
.venv/bin/python aws_current_state.py aws_offboarding_audit.json \
  --sso-session company \
  --out aws_offboarding.state.json

.venv/bin/python aws_offboarding_dashboard.py \
  --input aws_offboarding_audit.json \
  --state aws_offboarding.state.json \
  --out aws_offboarding_report
```

An access-denied state check remains `unknown`. The tool never treats a denied check as proof that
the resource was removed.

## 📈 Peer Baseline

Use at least three comparable peer or historical collections:

```bash
.venv/bin/python audit_baseline.py peer-a.json peer-b.json peer-c.json \
  --label "Platform engineering peers" \
  --out platform.baseline.json
```

Pass the result with `--baseline platform.baseline.json`. Baseline deviation stays separate from
security severity.

## 🗄 CloudTrail Lake

Review the SQL before executing a Lake query:

```bash
.venv/bin/python aws_cloudtrail_lake.py \
  --event-data-store 12345678-1234-1234-1234-123456789012 \
  --user leaver@example.com \
  --start 2026-08-01T00:00:00Z \
  --end 2026-08-24T00:00:00Z \
  --dry-run
```

Remove `--dry-run` to execute with the active AWS credentials. `start_query`/`get_query_results` is
a read query against your event data store, still read-only, no write API involved. Existing Lake
or Athena JSON/CSV exports can be normalized with `--input <file>`.

## 🔬 External Analysis

The optional `--analyze` pass sends a bounded findings digest to the Anthropic Messages API. Raw
CloudTrail logs are not sent. Keep the API key in the process environment:

```bash
export ANTHROPIC_API_KEY="..."

.venv/bin/python aws_offboarding_dashboard.py \
  --input aws_offboarding_audit.json \
  --analyze \
  --redact
```

`--redact` hashes account IDs and IP addresses before the digest leaves the machine. The returned
JSON is schema-validated and remains advisory. For each detected activity pattern, the analyst
compares a plausible routine explanation with a concerning hypothesis and names the evidence that
would distinguish them. It does not claim to know the person's purpose or intent.

The `Current review priority` score does not require the API. It is calculated locally from timing,
request-parameter findings, same-principal/same-target patterns, current state, failed attempts,
baseline deviation, collection coverage, and identity-match quality. The number ranks evidence for
review; it is not a probability of wrongdoing or a score of the person.

## 📋 Offboarding Playbook

CloudTrail review is only one control in offboarding. Access must also be disabled in the
authoritative identity provider, active sessions addressed, standalone IAM credentials removed,
shared secrets rotated, and resources and operational duties transferred to a current owner.

Use the [AWS offboarding playbook](docs/offboarding-playbook.md) for the phased checklist, ownership
model, closure criteria, evidence boundaries, and links to the AWS guidance behind those controls.
The generated HTML and Markdown reports include a shorter readiness checklist for each run.

## 🔒 Security

Audit files can contain account IDs, ARNs, usernames, source IPs, resource names, and request
parameters. The repository ignores collector output, manifests, state files, baselines, archives,
credentials, local configuration, and private keys.

Local Git hooks run both the repository scanner and Gitleaks before commits and pushes. Use `age`
when packaging evidence:

```bash
.venv/bin/python aws_offboarding_audit.py \
  --config audit-config.yaml \
  --archive \
  --encrypt-recipient age1example
```

See [SECURITY.md](SECURITY.md) for handling and rotation guidance.

## 🧪 Testing

```bash
.venv/bin/python scripts/secret_scan.py
.venv/bin/python -m unittest discover -s tests -v
```

CI runs this same suite plus Gitleaks on every push and pull request to `main`, and can also be
triggered manually from the GitHub Actions tab.

## ⚠ Limits

- Event History covers the most recent 90 days and management events only.
- Data-event coverage depends on CloudTrail Lake or Athena selectors and retention.
- `--loose` identity matching includes events that mention the subject and can produce false
  positives.
- Collection denials and logging changes create visible coverage gaps.
- Current-state reconciliation is best effort; unsupported or denied checks remain `unknown`.

---

## 📚 Documentation

| Doc | Type | For |
| --- | --- | --- |
| [docs/tutorial-getting-started.md](docs/tutorial-getting-started.md) | Tutorial | First run, synthetic then real |
| [docs/offboarding-playbook.md](docs/offboarding-playbook.md) | Playbook | Access removal, evidence review, ownership, and closure criteria |
| [docs/howto-guide.md](docs/howto-guide.md) | How-to | Specific tasks: SSO setup, baselines, Lake, AI analysis, archiving |
| [docs/reference-cli.md](docs/reference-cli.md) | Reference | Every flag, across all six scripts |
| [docs/reference-data-contract.md](docs/reference-data-contract.md) | Reference | The event JSON schema, collector → report |
| [docs/explanation-architecture.md](docs/explanation-architecture.md) | Explanation | Pipeline design, severity model, detector internals, extension points |

Licensed under [MIT](LICENSE).
