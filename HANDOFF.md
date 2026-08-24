# AWS Offboarding Audit: Engineering Notes

These notes document the collector and reporting contracts for maintainers. Several constraints
below preserve fixes for attribution, ranking, and report-volume problems found during development.

---

## 1. What this is

A defensive collection and dashboard pipeline that answers: *"what did this
departing engineer do across our AWS accounts, what coverage do we actually
have, and what needs a human check?"*

```text
  AWS (many accounts, IAM Identity Center / Azure-federated SSO)
        │
        │  aws_offboarding_audit.py     ← collector
        ▼
  aws_offboarding_audit.{json,csv,txt,manifest.json,summary.json}
        │
        │  aws_audit_report.py          ← orchestrator + renderer
        │    ├── audit_intel.py         ← knowledge layer (catalogue, detectors)
        │    └── audit_analyst.py       ← optional Claude API pass
        ▼
  aws_offboarding_report.{html,md,summary.json}
```

Stage 1 and stage 2 are decoupled by a JSON file. The report can be rebuilt
without querying AWS again; the collector is rate-limited and the repository
includes a deterministic fixture for report work. The optional
`aws_cloudtrail_lake.py`, `aws_current_state.py`, and `audit_baseline.py` inputs
all normalize into the same dashboard contract.

### Review framing

The report rates what an API **can** do, which is a proxy for "a human should
check this". It is not a finding of wrongdoing. Most flagged actions in a
competent engineer's final weeks are their job. Keep this qualification in the
HTML, Markdown, and analyst prompt because HR or management may review the output.

---

## 2. Files

| File | Responsibility | Depends on |
| --- | --- | --- |
| `aws_offboarding_audit.py` | Collector. Enumerates accounts via SSO token, sweeps CloudTrail `lookup-events`, writes CSV/JSON/TXT. | `boto3` |
| `audit_intel.py` | Knowledge layer. Curated catalogue, TrailDiscover enrichment, content detectors, sequence detection. | stdlib only |
| `audit_analyst.py` | Optional Claude API analysis pass. Builds a token-bounded digest, calls the Messages API with web search, parses JSON back. | stdlib only |
| `aws_audit_report.py` | Loads, enriches, and renders the interactive HTML dashboard, Markdown brief, and machine summary. | the two above |
| `aws_offboarding_dashboard.py` | One-command collection and dashboard workflow. | collector + report |
| `aws_cloudtrail_lake.py` | CloudTrail Lake query/import path, including data events when the event data store records them. | `boto3` |
| `aws_current_state.py` | Optional read-only reconciliation of high-risk targets against current AWS state. | `boto3` |
| `audit_baseline.py` | Builds peer/historical event baselines. | stdlib only |
| `tests/` | Regression suite for collection, detectors, correlation, rendering, Lake, state, baseline, and degradation. | `boto3`, stdlib |

`audit_intel.py` and `audit_analyst.py` intentionally use only the standard
library so the report stage can run on a bare Python 3.10+ installation.

---

## 3. Data contract

The collector emits a list of flat dicts. This is the interface between stages;
changing it breaks the report.

```python
{
  "event_id":     "b76d...",
  "time_utc":      "2026-08-14T09:21:33+00:00",  # ISO 8601, UTC, required
  "account_id":    "111122223333",
  "account_name":  "prod-platform",
  "region":        "eu-west-1",
  "event_source":  "ec2.amazonaws.com",
  "event_name":    "ModifySnapshotAttribute",     # required
  "matched_on":    "leaver@example.com",
  "match_mode":    "exact",                       # exact or explicit loose fallback
  "principal_arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_.../leaver@example.com",
  "principal_id":  "ARO...:leaver@example.com",
  "source_ip":     "82.14.9.201",
  "user_agent":    "aws-cli/2.15.0",              # truncated to 120 chars
  "error_code":    "",                            # "" or e.g. "AccessDenied"
  "resources":     "snap-0a1b2c3d",               # "; "-joined, ≤400 chars
  "resources_json": "[{...}]",
  "request_params": "{...}",                      # compact JSON, default ≤32768 chars
  "request_params_truncated": false,
  "request_params_original_length": 312,
  "event_scope": "management"                     # or data from Lake
}
```

`request_params` is the most valuable field and remains bounded because policies
can be large. The default is 32 KiB and the collector records when truncation
occurred. It is truncated in `sweep_region`, not the reporter.

The flat event JSON remains backward compatible. Collection completeness lives
in `<out>.manifest.json`; never infer that an empty event list means successful
coverage without reading the manifest. Checkpoints and summaries are sidecars.

After `enrich()` each row additionally carries:

```python
"_ts"              # datetime, tz-aware UTC
"_local"           # datetime in the display timezone
"severity"         # after timing escalation — for display
"base_severity"    # before timing escalation — for ranking. See §4.1
"category"         # Persistence / Privilege escalation / ...
"description", "why", "verify"
"curated"          # bool: came from CURATED_CATALOG vs a prefix guess
"tactics"          # MITRE tactic names from TrailDiscover
"used_in_wild"     # bool
"incidents"        # [{description, link}], ≤3
"content_findings" # [{severity, title, detail}] from request-parameter analysis
"flags"            # ["After last working day", "Weekend", "Failed: AccessDenied", ...]
"principal_key"    # best available stable principal identifier
"target_type", "target_id", "target_key" # normalized target for filters/correlation
"current_state"    # active / present / removed / unknown when a state file is supplied
"baseline_status"  # above / within / insufficient when a baseline is supplied
```

---

## 4. Design invariants

These invariants preserve attribution accuracy, evidence ordering, and a reviewable report size.

### 4.1 `base_severity` vs `severity`

Timing escalation (activity after the last working day → critical) inflates
routine events. If you sort or filter on `severity`, `ListBuckets` outranks a
trust policy naming an external account.

- **`severity`** — display only. Drives colour and the tally.
- **`base_severity`** — intrinsic risk (catalogue + content detectors). Drives
  all ordering and filtering.

`group_events()` in `aws_audit_report.py` and `rank()` in
`audit_analyst.build_digest()` both implement the same evidence-first sort:
*parameter findings first, then `base_severity`, then frequency.* Keep them
consistent.

### 4.2 Escaped JSON defeats substring matching

IAM policy documents arrive as JSON strings nested inside JSON, sometimes doubly
escaped. `"NotAction"` appears in the raw text as `\"NotAction\"`, so a check for
`'"notaction"' in raw` does not match.

`_inflate()` recursively parses embedded JSON strings (depth-capped at 4) and
`_params()` re-serialises the result, so detectors see clean text and real
structure. **Always match against the flattened output of `_params()`, never the
raw field.**

### 4.3 `used_in_wild` is nearly meaningless on read APIs

TrailDiscover flags 276 of 381 events as seen in real attacks, including
`DescribeInstances` and `ListBuckets`, because attackers enumerate before acting.
Using that flag alone produces too many read-only findings.

Current rule in `classify_event()`: escalate only to **medium**, only when the
event is not a read (`Get`/`List`/`Describe`/`Head`/`Search`/`Lookup`), and only
when its MITRE tactics intersect `{Persistence, Privilege Escalation, Defense
Evasion, Exfiltration, Impact, Credential Access}`.

### 4.4 The timeline is valuable because it is short

Everything shown there must earn its place. Qualifying conditions:

1. `curated` **and** `base_severity` in (critical, high), or
2. has `content_findings`, or
3. changed something after the last working day (reads excluded).

Post-departure read-only calls collapse into a single summary tick. Consecutive
identical `(date, event_name, account_id)` triples collapse with a `×n` count.
Hard cap of 100 ticks.

If you add a qualifying condition, re-run the fixture and eyeball the spine
length. Above roughly 60 entries it stops being readable.

### 4.5 Content findings outrank name-based guesses

A parameter-level detection is evidence; a catalogue entry is a prior. In
`enrich()`, a content finding whose severity exceeds the catalogue severity
raises **both** `severity` and `base_severity`.

---

## 5. Extension points

### Add a catalogue entry

`audit_intel.CURATED_CATALOG`, keyed on CloudTrail `eventName`:

```python
"PutBucketNotification": (H, PERSIST,
    "Configured an S3 event notification.",                    # what it does
    "Notifications can invoke a Lambda on every object write, "
    "which is durable execution triggered by normal business activity.",  # why it matters
    "Check the destination ARN and whether the target is a "
    "function you recognise."),                                 # what to verify
```

Write for an IT lead who knows AWS but is not a threat analyst. Say what the
attack actually achieves. Avoid "could be used maliciously" — that is true of
everything and helps nobody.

Unmatched events fall through `PREFIX_RULES`, then to TrailDiscover wording.

### Add a content detector

In `detect_content()`. Use `_walk(parsed, key_predicate)` for structural
lookups, `raw` (already flattened) for substring checks.

```python
if name == "PutBucketNotification":
    for cfg in _walk(parsed, lambda k: k.lower() == "lambdafunctionconfiguration"):
        arn = (cfg or {}).get("lambdaFunctionArn", "")
        if arn and not any(a in arn for a in org_accounts):
            add(C, "S3 notification targets a Lambda in another account",
                "Every matching object write invokes a function outside your "
                "organisation. Verify the destination account.")
```

Severity ladder: **critical** = works without credentials and survives
offboarding, or destroys data. **high** = meaningful exposure needing prompt
review. **medium** = worth a question. Do not inflate; the report only works if
critical means something.

### Add a sequence

`audit_intel.SEQUENCES` — tuples of event names that must all be present:

```python
(("CreateVirtualMFADevice", "EnableMFADevice"),
 "MFA device created and enabled",
 "If enrolled on another user's account, whoever holds the device can satisfy "
 "MFA-conditional policies as that user."),
```

Sequences are ordered and bounded (24 hours by default), and require the same
account and principal. When both events expose a normalized target, the targets
must match and the correlation is labelled strong. Missing target information
can produce a moderate correlation; never present that as parameter-level proof.

---

## 6. Running and testing

```bash
# One-time setup
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Collector (needs real AWS; run locally, never in CI)
aws sso login --sso-session <session>
.venv/bin/python aws_offboarding_dashboard.py --config audit-config.yaml --preflight
.venv/bin/python aws_offboarding_dashboard.py --config audit-config.yaml \
  --notice-date 2026-07-15 --last-day 2026-08-15 --open

# Report
.venv/bin/python aws_audit_report.py aws_offboarding_audit.json \
  --user leaver@example.com \
  --notice-date 2026-07-15 --last-day 2026-08-15 \
  --org-accounts 111122223333 444455556666 \
  --analyze

# Automated regression suite (no AWS access required)
.venv/bin/python -m unittest discover -s tests -v

# Fixture-driven iteration, no AWS required
python3 test_fixture.py && python3 aws_audit_report.py sample.json \
  --user leaver@example.com --notice-date 2026-07-24 --last-day 2026-08-15 \
  --org-accounts 111122223333 444455556666 777788889999 222233334444 \
  --out test_report
```

`test_fixture.py` generates 260 synthetic events seeded deterministically,
including request parameters crafted to trip every content detector. After any
change to `audit_intel.py`, confirm all detectors still fire:

```bash
grep -o '^> \*\*[^*]*\*\*' test_report.md | sort | uniq -c | sort -rn
```

Expected (9 distinct detectors): external account reference, snapshot shared
externally, NotAction with Allow, SSH open to the internet, one-day lifecycle
expiry, Lambda layer attached, unauthenticated Function URL, database deleted
with no final snapshot, AdministratorAccess attached.

Useful smoke checks in addition to the automated suite:

```bash
python3 -m py_compile audit_intel.py audit_analyst.py aws_audit_report.py aws_offboarding_audit.py
python3 aws_audit_report.py sample.json --user t --no-enrich --out /tmp/t   # offline degradation
python3 aws_audit_report.py sample.json --user t --analyze --out /tmp/t     # no API key → warns, continues
```

Both degradation paths must print a warning and still produce a report. Never
let a missing network or API key abort the run.

---

## 7. Constraints and limitations

**Hard limits of the data source.** `cloudtrail lookup-events` returns
management events only, 90 days maximum, throttled around 2 req/sec per account
per region. Data events — S3 object access, Lambda invocations — are absent, so
the report can show that a bucket was made public but never whether anything was
read from it. Say so rather than implying coverage that does not exist.

**Blind spots are load-bearing.** If `StopLogging` or `PutEventSelectors` appear,
some window is unaudited. The report surfaces this as a sequence finding.
CloudTrail Event History retains 90 days independently and cannot be disabled,
so it is the cross-check; AWS Config history and Cost Explorer catch resources
that appeared without a creation event.

**Identity matching is approximate.** For Identity Center sessions the CloudTrail
`Username` is the role session name — usually the email, not always. The
collector matches across `Username`, `userIdentity.arn`, `principalId`,
`userName`, and `sessionContext.sessionIssuer.userName`. `--also` adds further
identifiers; `--loose` matches anywhere in the event body (catches events
performed *on* the user, at the cost of false positives).

**The analyst pass sends data to the Anthropic API.** Roughly 5k tokens of
structured digest — never raw logs. Includes account IDs, ARNs, source IPs.
`--redact` salted-hashes account IDs and IPs first. Its output is advisory and
must never be the sole basis for an accusation or HR decision; the system prompt
instructs the model to assess artifacts rather than intent, and to state plainly
when evidence is thin.

**Cross-file consistency.** `SEV_ORDER`, `SEV_LABEL`, and the severity constants
`C/H/M/L` live in `audit_intel.py` and are imported everywhere. The CSS class
names in `aws_audit_report.CSS` match those constant *values* (`critical`,
`high`, `medium`, `low`) — renaming a constant silently breaks the styling.

---

## 8. Backlog, roughly by value

1. **Event data store discovery.** Detect eligible organization CloudTrail Lake
  stores and show their selectors/retention before the operator chooses one.
2. **Athena import profiles.** Lake is supported; add first-class SQL profiles
  for common organization-trail partition layouts.
3. **Broader current-state reconciliation.** Expand read-only checks across more
  resource-policy APIs and compare exact policy statements, not only presence.
4. **Stratus Red Team validation.** Detonate the matching techniques in a
   sandbox account and assert the pipeline catches each one. Turns the detector
   list from assertion into evidence.
5. **Richer baselines.** Event-name means exist; add category, account, region,
  working-hours, source-IP, and target-type distributions with provenance.
6. **Multi-pass analyst.** Per-cluster analysis then synthesis, for large
   estates where 55 finding groups exceed a useful single-prompt digest.

---

## 9. References

Technique coverage is drawn from these; consult them before adding detectors.

- **TrailDiscover** — 381 CloudTrail events, MITRE-mapped, real-incident links.
  CC BY 4.0. Cached weekly to `~/.cache/aws-offboarding-audit/`.
  <https://github.com/adanalvarez/TrailDiscover> · also exposes an MCP server at
  `https://mcp.traildiscover.cloud/mcp`, which is worth wiring into the agent
  loop directly.
- **AWSDoor / Wavestone RiskInsight** — the persistence taxonomy most of the
  detectors implement: access key injection, trust policy backdooring, NotAction
  abuse, poisoned Lambda layers, event selector tampering, S3 lifecycle shadow
  deletion, `LeaveOrganization`.
  <https://www.riskinsight-wavestone.com/en/2025/09/awsdoor-persistence-on-aws/>
  · tool: <https://github.com/OtterHacker/AWSDoor>
- **Datadog Stratus Red Team** — granular, safe detonation of these techniques.
  Use for validation. <https://github.com/DataDog/stratus-red-team>
- **Hacking the Cloud** — IAM persistence catalogue.
  <https://hackingthe.cloud/aws/post_exploitation/iam_persistence/>
- **HackTricks Cloud** — Lambda, EC2, and ECS persistence, including the
  version-qualifier and recursion-config techniques.
  <https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-persistence/>
- **TrailAlerts** — Sigma-rule-based CloudTrail detection, useful prior art if
  this ever needs to run continuously rather than on demand.
  <https://github.com/adanalvarez/TrailAlerts>
