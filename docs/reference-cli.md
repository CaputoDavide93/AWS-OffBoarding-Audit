# CLI reference

Complete flag listing for every script, pulled directly from each
`argparse` definition. All AWS-facing flags shown here map onto `Get*`,
`List*`, `Describe*`, or `LookupEvents` calls only — see
[Explanation: read-only by design](explanation-architecture.md#read-only-by-design).

## `aws_offboarding_dashboard.py` — one-command collect + report

The orchestrator most people should run. Wraps the collector and reporter
so you never manually pass audit JSON between the two.

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--input` | path | — | Existing collector/Lake JSON; skips collection entirely |
| `--config` | path | — | YAML file with `collector:` and `report:` defaults (see [audit-config.example.yaml](../audit-config.example.yaml)); CLI flags override it |
| `--user` | str | — | Departing engineer identifier (email, IAM username, or principal fragment) |
| `--sso-session` | str | — | `sso-session` name from `~/.aws/config` |
| `--start-url` | str | — | SSO start URL, alternative to `--sso-session` |
| `--also` | str, repeatable | `[]` | Extra identifiers that should also match this subject |
| `--days` | int | — | Lookback window in days (management events cap at 90) |
| `--start` / `--end` | ISO 8601 | — | Explicit UTC window (both required together) |
| `--regions` | str list | — | Explicit region list |
| `--all-regions` | flag | off | Sweep every enabled region |
| `--include-reads` | flag | off | Include `Get*`/`List*`/`Describe*` events (usually noise) |
| `--loose` | flag | off | Match the subject anywhere in the event body, not just identity fields — catches more, more false positives |
| `--accounts` | str list | — | Restrict collection to these account IDs |
| `--request-params-limit` | int | 32768 | Max stored size of `request_params` per event, in characters |
| `--resume` | flag | off | Resume from `<raw-out>.checkpoint.json` |
| `--preflight` | flag | off | Discover accounts and print the plan; makes no CloudTrail calls |
| `--raw-out` | str | `aws_offboarding_audit` | Prefix for collector output files |
| `--notice-date` | `YYYY-MM-DD` | — | When notice was given |
| `--last-day` | `YYYY-MM-DD` | — | Last working day; later activity escalates to critical |
| `--org-accounts` | str list | `[]` | Known org account IDs, used to flag references to accounts outside this list |
| `--timezone` | str | `Europe/London` | Display timezone for timing checks |
| `--work-start` | int | 8 | Start of expected business hours (24h) |
| `--work-end` | int | 19 | End of expected business hours (24h) |
| `--state` | path | — | Current-state snapshot from `aws_current_state.py` |
| `--baseline` | path | — | Peer baseline from `audit_baseline.py` |
| `--sequence-hours` | int | 24 | Max gap between events for sequence correlation |
| `--no-enrich` | flag | off | Skip the TrailDiscover catalogue download |
| `--analyze` | flag | off | Run the optional Claude API analysis pass |
| `--no-search` | flag | off | Disable web search in the analyst pass |
| `--redact` | flag | off | Hash account IDs and IPs before the analyst digest leaves the machine |
| `--model` | str | — | Override the analyst model |
| `--out` | str | `aws_offboarding_report` | Prefix for report output files |
| `--open` | flag | off | Open the HTML report when done |

## `aws_offboarding_audit.py` — collector only

Direct CloudTrail collection without building a report. Use when you only
want the raw event JSON, or need `--archive`/`--encrypt-recipient`.

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--config` | path | — | YAML defaults |
| `--user` | str | — | Departing engineer identifier |
| `--also` | str, repeatable | `[]` | Extra identifiers to also match |
| `--sso-session` | str | — | SSO session name |
| `--start-url` | str | — | SSO start URL |
| `--days` | int | 30 | Lookback window |
| `--start` / `--end` | ISO 8601 | — | Explicit window (requires both) |
| `--regions` | str list | — | Explicit region list |
| `--all-regions` | flag | off | Sweep every enabled region |
| `--include-reads` | flag | off | Include read-only events |
| `--loose` | flag | off | Loose identity matching |
| `--role-preference` | str list | — | SSO role names to try, in order |
| `--accounts` | str list | — | Restrict to these account IDs |
| `--account-concurrency` | int | 4 | Parallel accounts swept at once |
| `--region-concurrency` | int | 3 | Parallel regions swept per account |
| `--request-params-limit` | int | — | Max stored `request_params` size |
| `--preflight` | flag | off | Print the plan, make no CloudTrail calls |
| `--resume` | flag | off | Resume from a checkpoint |
| `--checkpoint` | path | `<out>.checkpoint.json` | Checkpoint file path |
| `--archive` | flag (optional value) | — | Package output into a `tar.gz`; pass a path or leave as `auto` |
| `--encrypt-recipient` | str | — | `age` public key to encrypt the archive for |
| `--out` | str | `aws_offboarding_audit` | Output file prefix (writes `.json`, `.csv`, `.txt`, `.manifest.json`, `.summary.json`) |

## `aws_audit_report.py` — report builder

Builds the dashboard from an existing collector/Lake JSON file. Called
internally by `aws_offboarding_dashboard.py`; run directly when iterating
on report rendering (e.g. against `sample.json`).

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `input` (positional) | path | — | `aws_offboarding_audit.json` (or `.csv`) |
| `--user` | str | manifest subject | Subject of the review |
| `--notice-date` | `YYYY-MM-DD` | — | Notice date |
| `--last-day` | `YYYY-MM-DD` | — | Last working day |
| `--manifest` | path | auto-detected | Collector manifest JSON |
| `--state` | path | — | Current-state snapshot |
| `--baseline` | path | — | Peer baseline |
| `--sequence-hours` | int | 24 | Sequence correlation window |
| `--org-accounts` | str list | `[]` | Known org account IDs |
| `--timezone` | str | `Europe/London` | Display timezone |
| `--work-start` | int | 8 | Start of business hours (24h) |
| `--work-end` | int | 19 | End of business hours (24h) |
| `--no-enrich` | flag | off | Skip TrailDiscover download |
| `--refresh-intel` | flag | off | Force-refresh the cached TrailDiscover dataset |
| `--analyze` | flag | off | Run the Claude analyst pass |
| `--api-key` | str | `$ANTHROPIC_API_KEY` | Anthropic API key |
| `--model` | str | `claude-sonnet-5` | Analyst model |
| `--no-search` | flag | off | Disable web search in the analyst pass |
| `--redact` | flag | off | Hash identifiers before sending to the analyst |
| `--out` | str | `aws_offboarding_report` | Output file prefix |

## `aws_current_state.py` — read-only reconciliation

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `input` (positional) | path | — | Collector JSON event list |
| `--sso-session` | str | — | SSO session name |
| `--start-url` | str | — | SSO start URL |
| `--role-preference` | str list | — | SSO role names to try, in order |
| `--out` | path | `aws_offboarding_state.json` | Output snapshot path |

Checks IAM users/roles, Lambda function URLs, EBS snapshots, S3 buckets,
security groups, KMS keys, RDS instances/clusters, and CloudTrail trails —
all via `Get*`/`List*`/`Describe*` calls.

## `aws_cloudtrail_lake.py` — Lake query / import

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--event-data-store` | str | — | Lake event data store ID or ARN (mutually exclusive with `--input`) |
| `--input` | path | — | Existing Lake/Athena JSON or CSV export (mutually exclusive with `--event-data-store`) |
| `--user` | str | *(required)* | Subject identifier |
| `--also` | str, repeatable | `[]` | Extra identifiers |
| `--start` | ISO 8601 | *(required)* | Window start |
| `--end` | ISO 8601 | *(required)* | Window end |
| `--region` | str | `eu-west-1` | Region for the query |
| `--include-reads` | flag | off | Include read-only events |
| `--loose` | flag | off | Loose identity matching |
| `--scope` | `management` \| `management-and-data` | `management` | Whether to include data events |
| `--request-params-limit` | int | — | Max stored `request_params` size |
| `--dry-run` | flag | off | Print the generated SQL, run nothing |
| `--out` | str | `aws_offboarding_audit` | Output file prefix |

## `audit_baseline.py` — peer baseline builder

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `inputs` (positional, one or more) | path | — | Peer or historical collector files |
| `--label` | str | `Peer baseline` | Label shown in the report |
| `--out` | path | `aws_offboarding.baseline.json` | Output baseline path |

## Related

- [How-to guide](howto-guide.md) for task-oriented recipes using these flags
- [Data contract reference](reference-data-contract.md) for the shape of the JSON these scripts read and write
