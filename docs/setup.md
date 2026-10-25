# Setup

Install the tool, try it on synthetic data, then point it at your own AWS organisation. The synthetic run needs no AWS access and takes about a minute.

## Before you start

| You need | Why |
|---|---|
| Python 3.10 or newer | Runs every script |
| An IAM Identity Center (AWS SSO) sign-in with a permission set such as `SecurityAudit` or `ReadOnlyAccess` in each account to review | The collector signs in to each account with short-lived credentials and only reads |
| An `sso-session` block in `~/.aws/config` | See [How-to: configure AWS SSO access](howto-guide.md#configure-aws-sso-access) |
| The AWS CLI | Only for `aws sso login` |

The synthetic run needs only Python.

## 1. Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

This installs `boto3` and `PyYAML` into a local virtual environment.

## 2. Try it on synthetic data

```bash
mkdir -p working
python3 tests/fixtures/gen_sample.py
.venv/bin/python src/aws_audit_report.py sample.json \
  --user leaver@example.com \
  --notice-date 2026-07-24 --last-day 2026-08-15 \
  --org-accounts 111122223333 444455556666 777788889999 222233334444 \
  --out working/demo --open
```

`gen_sample.py` writes 260 invented CloudTrail events for the user `leaver@example.com`. The report script writes `working/demo.html`, a Markdown copy and a JSON summary, and `--open` shows the HTML in your browser. Git ignores the `working/` folder. Without `--no-enrich` the report downloads the pinned TrailDiscover catalogue from GitHub; add `--no-enrich` to stay offline.

<img src="assets/screenshots/report-summary-light.png" width="100%" alt="The Summary page of the report for the synthetic user: review window, accounts, events matched and a 10 out of 10 review priority with the reasons behind it.">

The Summary page opens first. It shows the review window, the number of events matched and a review priority from 1 to 10 with the reasons behind it.

## 3. Configure your organisation

```bash
cp audit-config.example.yaml audit-config.yaml
```

Edit `audit-config.yaml`: the SSO session name, your timezone, working hours and your organisation's account IDs (`report.org_accounts`). Git ignores this file. Command-line flags override it.

## 4. Check the scope before collecting

```bash
aws sso login --sso-session <your-session-name>

.venv/bin/python src/aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --preflight
```

Preflight lists the accounts and roles your sign-in reaches and writes the collection plan. It makes no CloudTrail calls. If an account you expected is missing, fix access first (see [troubleshooting](troubleshooting.md#an-account-is-missing-from-the-plan)).

## 5. Collect and build the dashboard

```bash
mkdir -p working
.venv/bin/python src/aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --user leaver@example.com \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --out working/aws_offboarding_report \
  --open
```

Add `--resume` if the collection stops part way. The result is one HTML file you can open without a web server.

<img src="assets/screenshots/report-findings-light.png" width="100%" alt="The Actions and evidence page: detected activity patterns followed by flagged actions, each rated critical, high, medium or low.">

The Actions and evidence page lists detected patterns and each flagged action with why it matters and what to verify. A switch on that page reveals API names, timestamps and raw request parameters.

## 6. Check whether flagged changes still exist (optional)

CloudTrail records that something changed, not that it is still there. See [How-to: reconcile current state](howto-guide.md#reconcile-whether-a-flagged-change-still-exists).

## What was tested

Steps 1 and 2 are exercised by the test suite and by `make screenshots`, on Python 3.11 (CI, Linux) and Python 3.14 (macOS). Steps 3 to 5 need a real AWS organisation and were not run as part of this documentation pass. Report what you find in an [issue](../CONTRIBUTING.md#reporting-an-environment-we-have-not-tested).
