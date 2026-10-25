# FAQ

## Can this tool change anything in my AWS accounts?

No. Every AWS call it makes reads state: it never creates, modifies or deletes anything. The full list of calls is in the [README](../README.md).

## What does the tool do?

It collects the CloudTrail events tied to one departing person across the AWS accounts reachable through IAM Identity Center, checks request parameters for durable access and destructive changes, and builds one self-contained HTML report.

## Does it prove that someone did something wrong?

No. Severity ranks what an action can do, not why it was done, and the review priority is a score for ordering evidence, not a probability of wrongdoing. Confirm each item against change tickets and planned work.

## How far back can it look?

Up to 90 days with CloudTrail Event History, management events only. For longer ranges or data events, query CloudTrail Lake with `src/aws_cloudtrail_lake.py` if your event data store records them.

## Does it send my data anywhere?

By default the only outbound request is a download of the pinned TrailDiscover event catalogue from GitHub, verified by SHA-256 (`--no-enrich` skips it). An optional `--analyze` pass sends a bounded findings digest to an external analysis API, with account IDs and IP addresses hashed unless you pass `--no-redact`. The HTML report links web fonts from Google Fonts when you open it.

## Do I need an AWS account to try it?

No. `tests/fixtures/gen_sample.py` writes 260 invented events, and the [setup guide](setup.md#2-try-it-on-synthetic-data) builds a report from them. A finished synthetic report is also in the repository: [docs/assets/example-report.html](assets/example-report.html).

## Which AWS permissions does it need?

A read-only permission set in each account, such as `SecurityAudit` or `ReadOnlyAccess`, assigned through IAM Identity Center. The collector tries the names in `role_preference` in order.

## Does it work without IAM Identity Center?

The collector discovers accounts through Identity Center. You can still build a report from event JSON gathered another way, if it follows the [data contract](reference-data-contract.md), or normalise a CloudTrail Lake or Athena export with `src/aws_cloudtrail_lake.py --input`.

## Is the dashboard safe to share?

Treat it as confidential. It can contain account IDs, ARNs, usernames, source IPs and request parameters. Use the `--archive` option with `--encrypt-recipient` to package evidence with `age` encryption. See [SECURITY.md](../SECURITY.md).

## Does it cover offboarding beyond AWS?

Only as a checklist. The report includes a readiness checklist, and the [offboarding playbook](offboarding-playbook.md) covers identity provider, sessions, credentials, secrets and handover.

## Which operating systems does it run on?

Anything that runs Python 3.10 or newer. The test suite runs in CI on Linux with Python 3.11 and was run on macOS with Python 3.14. Windows is untested.

## How do I report a problem or an untested environment?

Follow [CONTRIBUTING](../CONTRIBUTING.md).
