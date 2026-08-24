# How-to guide

Task-oriented recipes. Each assumes you've already done the
[getting-started tutorial](tutorial-getting-started.md) and have a working
`.venv`.

## Configure AWS SSO access

1. Add an `sso-session` block to `~/.aws/config`:

   ```ini
   [sso-session my-session]
   sso_start_url = https://your-org.awsapps.com/start
   sso_region = eu-west-1
   sso_registration_scopes = sso:account:access
   ```

2. Log in:

   ```bash
   aws sso login --sso-session my-session
   ```

3. Verify: `--sso-session my-session` should now work on any script below.

**Verification:** `aws sso login` prints `Successfully logged into Start
URL: ...` and opens a browser tab for approval.

**Troubleshooting:** if login hangs, open the printed URL manually. If the
CLI reports no matching cache entry, the collector will still discover
accounts correctly — it re-derives the cache key from `sso_start_url` and
`sso_region`, not the session name alone.

## Set organization defaults once

```bash
cp audit-config.example.yaml audit-config.yaml
```

Edit it with your subject, SSO session, and preferred defaults:

```yaml
collector:
  user: leaver@example.com
  sso_session: my-session
  days: 30
  all_regions: true
  include_reads: false
  loose: false
  role_preference:
    - SecurityAudit
    - ReadOnlyAccess
  account_concurrency: 4
  region_concurrency: 3
  request_params_limit: 32768
  out: aws_offboarding_audit
```

`audit-config.yaml` is gitignored — it's expected to hold real account IDs
and identities you don't want in source control.

**Verification:** `aws_offboarding_dashboard.py --config audit-config.yaml
--preflight` should list your accounts without asking for any flag you
already set in the file.

## Preview scope before querying CloudTrail

```bash
.venv/bin/python aws_offboarding_dashboard.py --config audit-config.yaml --preflight
```

Writes `<out>.preflight.json` — the account list, role names, and audit
window it would use. Makes zero CloudTrail calls; useful for confirming
you have access to the right accounts before spending an hour on collection.

## Run a full collection and build the dashboard

```bash
.venv/bin/python aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --out aws_offboarding_report \
  --open
```

Omit `--notice-date`/`--last-day` if the person hasn't left yet — the report
just won't escalate anything to "after last working day."

**Troubleshooting:** if collection is interrupted (network drop, laptop
sleep, Ctrl-C), re-run the same command with `--resume` appended. It resumes
from `<out>.checkpoint.json` rather than re-querying accounts and regions
already swept.

## Reconcile whether a flagged change still exists

CloudTrail proves something happened once; it can't prove the change is
still in place. Run the read-only reconciler after collection:

```bash
.venv/bin/python aws_current_state.py aws_offboarding_audit.json \
  --sso-session my-session \
  --out aws_offboarding.state.json

.venv/bin/python aws_offboarding_dashboard.py \
  --input aws_offboarding_audit.json \
  --state aws_offboarding.state.json \
  --out aws_offboarding_report
```

**Verification:** open the rebuilt dashboard and check the "current state"
column — entries should read `active`, `present`, `removed`, or `unknown`.

**Troubleshooting:** an access-denied check always reports `unknown`, never
`removed`. The tool never infers absence from a denial.

## Compare against peer or historical baselines

Requires at least three comparable audit files (peers, or the same person's
past reviews):

```bash
.venv/bin/python audit_baseline.py peer-a.json peer-b.json peer-c.json \
  --label "Platform engineering peers" \
  --out platform.baseline.json
```

Then pass it into the report:

```bash
.venv/bin/python aws_audit_report.py aws_offboarding_audit.json \
  --baseline platform.baseline.json \
  --out aws_offboarding_report
```

Baseline deviation is reported as its own signal (`baseline_status`), never
folded into severity.

## Query CloudTrail Lake instead of Event History

Event History caps out at 90 days and management events only. If your
organization has a CloudTrail Lake event data store, you can go further back
and optionally include data events:

```bash
.venv/bin/python aws_cloudtrail_lake.py \
  --event-data-store 12345678-1234-1234-1234-123456789012 \
  --user leaver@example.com \
  --start 2026-08-01T00:00:00Z \
  --end 2026-08-24T00:00:00Z \
  --dry-run
```

Always run with `--dry-run` first — it prints the generated SQL without
executing it. Drop the flag once you've reviewed it. Add
`--scope management-and-data` to include data events if your event data
store records them.

Already have a Lake or Athena export as JSON/CSV? Normalize it directly
instead of querying live:

```bash
.venv/bin/python aws_cloudtrail_lake.py --input export.csv --user leaver@example.com \
  --start 2026-08-01T00:00:00Z --end 2026-08-24T00:00:00Z
```

## Run the optional AI analysis pass

```bash
export ANTHROPIC_API_KEY="..."

.venv/bin/python aws_offboarding_dashboard.py \
  --input aws_offboarding_audit.json \
  --analyze \
  --redact
```

Sends a bounded findings digest (not raw logs) to the Anthropic Messages
API and folds a schema-validated, advisory analysis back into the report.

`--redact` salts and hashes account IDs and IP addresses before anything
leaves your machine — use it whenever you're not comfortable sending real
identifiers externally.

**Troubleshooting:** missing API key or no network access both degrade
gracefully — the report still builds, with a printed warning instead of the
analyst section.

## Package evidence for handoff

```bash
.venv/bin/python aws_offboarding_audit.py \
  --config audit-config.yaml \
  --archive \
  --encrypt-recipient age1example
```

Produces an `age`-encrypted archive of the collector output. See
[SECURITY.md](../SECURITY.md) for the full data-handling policy before you
share anything.

## Run the test suite

```bash
.venv/bin/python scripts/secret_scan.py
.venv/bin/python -m unittest discover -s tests -v
```

CI runs the same two commands, plus Gitleaks, on every push and pull request
to `main`.
