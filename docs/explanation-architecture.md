# Explanation: architecture and design invariants

## The problem

When someone leaves — voluntarily or not — the question is always the same:
*"what did this engineer do across our AWS accounts, what coverage do we
actually have, and what needs a human to check it?"* Answering that by hand
means paging through CloudTrail across dozens of accounts and regions,
knowing which of hundreds of API calls actually matter, and not conflating
"this is technically possible" with "this person did something wrong."

Most flagged actions in a competent engineer's final weeks are their job.
The report's purpose is to rank what deserves a human look, not to accuse.

## The approach: a two-stage, decoupled pipeline

```text
  AWS (many accounts, IAM Identity Center / federated SSO)
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

Stage 1 (collect) and stage 2 (report) are decoupled by a JSON file on
purpose. The report can be rebuilt any number of times — different
severity tuning, a newly added baseline, a re-run analyst pass — without
touching AWS again. `aws_cloudtrail_lake.py`, `aws_current_state.py`, and
`audit_baseline.py` all produce or consume inputs that normalize into the
same event contract, so they compose freely. See the
[data contract reference](reference-data-contract.md) for the exact shape.

`audit_intel.py` and `audit_analyst.py` intentionally depend only on the
Python standard library, so the report stage runs on a bare Python 3.10+
install with no AWS SDK required.

## Read-only by design

Every AWS SDK call in this codebase is a `Get*`, `List*`, `Describe*`,
`LookupEvents`, or a read-side `start_query`/`get_query_results` against a
CloudTrail Lake event data store. There is no `Create*`, `Put*`, `Delete*`,
`Update*`, `Terminate*`, `Modify*`, `Attach*`/`Detach*`, or `Revoke*` call
anywhere. This is a deliberate constraint, not an accident of what got
built first: an offboarding audit tool that could itself change account
state would be a liability during exactly the moment it's meant to reduce
risk. The only data that leaves the machine at all is the bounded,
optionally redacted digest sent to the Anthropic API during the
[external analysis pass](howto-guide.md#run-the-optional-ai-analysis-pass) —
never raw CloudTrail logs.

## Trade-offs

**Two severities, not one.** Timing escalation — activity after the last
working day — inflates otherwise routine events into something urgent. If
you sort or filter on a single severity field, a bulk `ListBuckets` call
made on the wrong afternoon outranks a trust policy that names an external
AWS account.

- `severity` — display only, drives color and the tally shown at the top.
- `base_severity` — intrinsic risk from the catalogue and content
  detectors, drives *all* ordering and filtering.

`group_events()` in `aws_audit_report.py` and `rank()` in
`audit_analyst.build_digest()` both implement the same evidence-first sort:
parameter findings first, then `base_severity`, then frequency. The two
must stay consistent, or the dashboard and the AI analyst will disagree on
what matters most.

**Escaped JSON defeats substring matching.** IAM policy documents arrive as
JSON strings nested inside JSON, sometimes doubly escaped — `"NotAction"`
shows up in the raw text as `\"NotAction\"`, so a naive
`'"notaction"' in raw` check silently never matches. `_inflate()`
recursively parses embedded JSON strings (depth-capped at 4) and
`_params()` re-serializes the result, so every detector sees clean,
structured text. Detectors must always match against the output of
`_params()`, never the raw field — the trade-off is a bit more parsing
overhead per event, in exchange for detectors that actually fire.

**`used_in_wild` is a weak signal on its own.** TrailDiscover flags 276 of
381 cataloged events as "seen in a real attack," including
`DescribeInstances` and `ListBuckets` — attackers enumerate before they
act, so almost anything qualifies. Using the flag alone would flood the
report with read-only noise. The current rule in `classify_event()`
escalates only to **medium**, only for non-read events (excluding
`Get`/`List`/`Describe`/`Head`/`Search`/`Lookup`), and only when the
event's MITRE tactics intersect `{Persistence, Privilege Escalation,
Defense Evasion, Exfiltration, Impact, Credential Access}`.

**The timeline stays short on purpose.** A spine with hundreds of entries
is unreadable, so an event only earns a place on it if: it's curated *and*
`base_severity` is critical/high, or it has parameter-level findings, or it
changed something after the last working day (reads excluded).
Post-departure read-only calls collapse into a single summary tick, and
identical `(date, event_name, account_id)` triples collapse with a `×n`
count, hard-capped at 100 ticks. Past roughly 60 entries the spine stops
being something a human will actually scan — if you add a qualifying
condition, re-run the fixture and eyeball the length.

**Content findings outrank name-based guesses.** A parameter-level
detection is direct evidence; a catalogue entry keyed on event name is a
prior. In `enrich()`, when a content finding's severity exceeds the
catalogue's guess, it raises *both* `severity` and `base_severity` — the
report trusts what it actually read in the request over what an event name
usually implies.

## Employment status frames the report, timing escalates individual events

These are two different mechanisms and it's worth keeping them separate.

**Timing escalation** (in `enrich()`) is per-event: any single action
timestamped after `--last-day` gets `severity` bumped to critical and the
`"After last working day"` flag, regardless of what else is going on. This
is unconditional — it doesn't ask whether the person has *actually* left
yet, only whether the timestamp is later than the date you supplied.

**Employment status** (`employment_status()` in `aws_audit_report.py`) is
report-wide framing for a non-technical reader, computed from the same two
dates against the real clock at report-build time:

| Status | Condition | What the report tells HR |
| --- | --- | --- |
| `active` | no `--notice-date` or `--last-day` supplied | Nothing is measured against a departure date. Treat this as an ordinary access review. |
| `notice_period` | a date is supplied, but "now" is still before it | Continued activity is expected — they still have a job to do. Nothing is escalated on timing yet. |
| `departed` | `--last-day` is supplied and has passed | Post-departure activity has no ordinary work justification and is the one thing worth chasing immediately. |

This status renders as a plain-English section titled "Reading this report
without a technical background" at the top of both the HTML and Markdown
report — see `hr_explainer_paragraphs()`. It exists because severity labels
alone read as verdicts to someone who doesn't know what an API call is;
this section is the difference between "critical" meaning "call security"
and meaning "worth one Slack message to check."

If you change the wording, keep it in `hr_explainer_paragraphs()` only —
both renderers call it, so there is exactly one copy of this text to keep
accurate.

## Extending the detectors

**Add a catalogue entry** in `audit_intel.CURATED_CATALOG`, keyed on
CloudTrail `eventName`:

```python
"PutBucketNotification": (H, PERSIST,
    "Configured an S3 event notification.",                    # what it does
    "Notifications can invoke a Lambda on every object write, "
    "which is durable execution triggered by normal business activity.",  # why it matters
    "Check the destination ARN and whether the target is a "
    "function you recognise."),                                 # what to verify
```

Write for an IT lead who knows AWS but isn't a threat analyst. Say what the
action actually achieves; avoid "could be used maliciously" — that's true
of almost everything and tells nobody anything useful. Unmatched events
fall through `PREFIX_RULES`, then to TrailDiscover's own wording.

**Add a content detector** in `detect_content()`. Use `_walk(parsed,
key_predicate)` for structural lookups, or the already-flattened `raw` for
substring checks:

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
offboarding, or destroys data. **high** = meaningful exposure needing
prompt review. **medium** = worth a question. Don't inflate it — the
report only earns trust if "critical" reliably means something.

**Add a sequence** to `audit_intel.SEQUENCES` — event names that must all
appear, in order, from the same principal and account:

```python
(("CreateVirtualMFADevice", "EnableMFADevice"),
 "MFA device created and enabled",
 "If enrolled on another user's account, whoever holds the device can satisfy "
 "MFA-conditional policies as that user."),
```

Sequences are bounded to a 24-hour window by default. When both events
expose a normalized target, the targets must match for the correlation to
be labelled "strong"; missing target information can still produce a
"moderate" correlation, but it must never be presented as parameter-level
proof.

## Constraints and limitations

- **Hard limits of the data source.** `cloudtrail lookup-events` returns
  management events only, 90 days maximum, throttled around 2 req/sec per
  account per region. Data events — S3 object reads, Lambda invocations —
  are absent unless you're using CloudTrail Lake, so the report can show a
  bucket was made public but never whether anything was actually read from
  it.
- **Blind spots are load-bearing, not just noted.** If `StopLogging` or
  `PutEventSelectors` appear, some window is genuinely unaudited — the
  report surfaces this as a sequence finding rather than staying silent.
  CloudTrail Event History itself retains 90 days independently and can't
  be disabled, which is why it's the cross-check; AWS Config history and
  Cost Explorer can catch resources that appeared with no creation event.
- **Identity matching is approximate.** For Identity Center sessions, the
  CloudTrail `Username` field is the role session name — usually the
  person's email, but not guaranteed. The collector matches across
  `Username`, `userIdentity.arn`, `principalId`, `userName`, and
  `sessionContext.sessionIssuer.userName`; `--also` adds further
  identifiers, and `--loose` matches anywhere in the event body (catches
  events performed *on* the subject, at the cost of false positives).
- **The analyst pass is advisory, never a verdict.** Its system prompt
  instructs the model to assess artifacts rather than intent and to say
  plainly when evidence is thin — its output must never be the sole basis
  for an HR or disciplinary decision.
- **Constants are cross-file.** `SEV_ORDER`, `SEV_LABEL`, and the severity
  constants `C`/`H`/`M`/`L` live in `audit_intel.py` and are imported
  everywhere. The CSS class names in `aws_audit_report.CSS` match those
  constant *values* (`critical`, `high`, `medium`, `low`) — renaming a
  constant silently breaks the dashboard's styling.

## Backlog, roughly by value

1. **Event data store discovery** — detect eligible organization CloudTrail
   Lake stores and show their selectors/retention before the operator picks one.
2. **Athena import profiles** — first-class SQL profiles for common
   organization-trail partition layouts.
3. **Broader current-state reconciliation** — more resource-policy APIs,
   comparing exact policy statements rather than just presence.
4. **Stratus Red Team validation** — detonate the matching techniques in a
   sandbox account and assert the pipeline catches each one.
5. **Richer baselines** — category, account, region, working-hours,
   source-IP, and target-type distributions with provenance, not just
   event-name means.
6. **Multi-pass analyst** — per-cluster analysis then synthesis, for large
   estates where 55+ finding groups exceed a useful single-prompt digest.

## References

Technique coverage is drawn from these; consult them before adding a
detector:

- **TrailDiscover** — 381 CloudTrail events, MITRE-mapped, real-incident
  links. CC BY 4.0, cached weekly to `~/.cache/aws-offboarding-audit/`.
  <https://github.com/adanalvarez/TrailDiscover> — also exposes an MCP
  server at `https://mcp.traildiscover.cloud/mcp`.
- **AWSDoor / Wavestone RiskInsight** — the persistence taxonomy most
  detectors implement: access key injection, trust policy backdooring,
  `NotAction` abuse, poisoned Lambda layers, event selector tampering, S3
  lifecycle shadow deletion, `LeaveOrganization`.
  <https://www.riskinsight-wavestone.com/en/2025/09/awsdoor-persistence-on-aws/> ·
  <https://github.com/OtterHacker/AWSDoor>
- **Datadog Stratus Red Team** — granular, safe detonation of these
  techniques, useful for validation.
  <https://github.com/DataDog/stratus-red-team>
- **Hacking the Cloud** — IAM persistence catalogue.
  <https://hackingthe.cloud/aws/post_exploitation/iam_persistence/>
- **HackTricks Cloud** — Lambda, EC2, and ECS persistence, including
  version-qualifier and recursion-config techniques.
  <https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-persistence/>
- **TrailAlerts** — Sigma-rule-based CloudTrail detection, useful prior art
  if this ever needs to run continuously rather than on demand.
  <https://github.com/adanalvarez/TrailAlerts>

## Testing this yourself

```bash
# Automated regression suite, no AWS access required
.venv/bin/python -m unittest discover -s tests -v

# Fixture-driven iteration
python3 test_fixture.py && python3 aws_audit_report.py sample.json \
  --user leaver@example.com --notice-date 2026-07-24 --last-day 2026-08-15 \
  --org-accounts 111122223333 444455556666 777788889999 222233334444 \
  --out test_report
```

`test_fixture.py` generates 260 synthetic events seeded deterministically,
crafted to trip every content detector. After any change to
`audit_intel.py`, confirm all detectors still fire:

```bash
grep -o '^> \*\*[^*]*\*\*' test_report.md | sort | uniq -c | sort -rn
```

Expect 9 distinct detectors: external account reference, snapshot shared
externally, `NotAction` with `Allow`, SSH open to the internet, one-day
lifecycle expiry, Lambda layer attached, unauthenticated function URL,
database deleted with no final snapshot, `AdministratorAccess` attached.

Useful smoke checks alongside the automated suite:

```bash
python3 -m py_compile audit_intel.py audit_analyst.py aws_audit_report.py aws_offboarding_audit.py
python3 aws_audit_report.py sample.json --user t --no-enrich --out /tmp/t   # offline degradation
python3 aws_audit_report.py sample.json --user t --analyze --out /tmp/t     # no API key → warns, continues
```

Both degradation paths must print a warning and still produce a report —
never let a missing network connection or API key abort the run.

## Related

- [Data contract reference](reference-data-contract.md)
- [CLI reference](reference-cli.md)
- [How-to guide](howto-guide.md)
