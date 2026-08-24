# Tutorial: your first offboarding audit

You'll go from a fresh clone to a working, interactive HTML dashboard — first
against synthetic data (no AWS access needed), then against your own AWS
organization. By the end you'll have a report you can open in a browser and
filter by severity, account, and date.

## What you'll need

- Python 3.10+
- AWS SSO access to the accounts you want to audit (for the real run — the
  synthetic run needs nothing)
- An IAM Identity Center `sso-session` configured in `~/.aws/config` (see
  [How-to: configure AWS SSO access](howto-guide.md#configure-aws-sso-access))

## Step 1: Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

This creates an isolated virtual environment and installs `boto3` plus the
report's dependencies.

## Step 2: Generate a synthetic dataset

```bash
python3 test_fixture.py
```

This writes `sample.json` — 260 fabricated CloudTrail events with fake
account IDs (`111122223333` and friends), deliberately crafted to trip every
content detector in the codebase. No network calls, no AWS credentials.

## Step 3: Build your first dashboard

```bash
.venv/bin/python aws_audit_report.py sample.json \
  --user leaver@example.com \
  --notice-date 2026-07-24 --last-day 2026-08-15 \
  --org-accounts 111122223333 444455556666 777788889999 222233334444 \
  --out test_report --open
```

This should print something like:

```
260 sample events
  Enriched with 373 catalogued events from TrailDiscover.
260 events · 93 critical, 8 high, 108 medium, 51 low · 31 with parameter-level findings
Wrote test_report.html, test_report.md, and test_report.summary.json
```

`--open` launches `test_report.html` in your default browser. You now have a
working dashboard: try the severity filter, click a finding to expand its
evidence, and switch to the timeline view.

## Step 4: Point it at real AWS

Once the shape is familiar, swap the fixture for a live collection. Log in,
discover your accounts, then collect and build in one command:

```bash
aws sso login --sso-session <your-session-name>

.venv/bin/python aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --preflight   # discovers accounts, makes no CloudTrail calls
```

Review the account list it prints, then drop `--preflight` and add your
audit window:

```bash
.venv/bin/python aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --out aws_offboarding_report \
  --open
```

## What you built

A self-contained HTML dashboard summarizing every CloudTrail event tied to
one identity across every account you can reach, ranked by what the action
could do and whether it happened before or after the person's last working
day. Every AWS call involved was read-only — see
[Explanation: why this is read-only by design](explanation-architecture.md#read-only-by-design).

Next steps:
- [How-to guide](howto-guide.md) for current-state checks, peer baselines, CloudTrail Lake, and the optional AI analysis pass
- [CLI reference](reference-cli.md) for every flag across all six scripts
- [Data contract reference](reference-data-contract.md) if you're consuming the JSON output directly
