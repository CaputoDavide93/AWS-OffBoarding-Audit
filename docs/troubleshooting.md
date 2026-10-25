# Troubleshooting

Find your symptom, then follow the fix. The messages quoted below are the ones the scripts print.

## "No valid SSO token found"

The collector found no unexpired IAM Identity Center sign-in. Run `aws sso login --sso-session <your-session-name>`, then repeat the command. The error message prints that line with your session name filled in when you passed `--sso-session`.

## "Multiple valid SSO tokens found. Pass --sso-session or --start-url explicitly."

You are signed in to more than one Identity Center portal. Add `--sso-session <name>` (or set `sso_session` in `audit-config.yaml`) so the collector knows which one to use.

## "No reachable accounts found."

Your sign-in reached no account with a role the collector can use. Check that your permission set in each account is one of the names in `role_preference` (default order: `SecurityAudit`, `ReadOnlyAccess`), or pass `--role-preference` with the permission set you do have. Run with `--preflight` to see what is reachable.

## An account is missing from the plan

The account is not assigned to you in IAM Identity Center, or none of its roles match `role_preference`. Ask the Identity Center administrator to assign a read-only permission set, or name the right one with `--role-preference`.

## "boto3 is required"

The script ran outside the virtual environment. Use `.venv/bin/python`, or install the dependencies with `python3 -m pip install -r requirements.txt`.

## The report shows "unknown" for the current state of a change

The state check was denied or is not supported for that resource type. The tool never treats a denied check as proof that a resource was removed. Re-run `src/aws_current_state.py` with a role that has read access to that service, or verify the resource by hand.

## The report has fewer events than expected

- CloudTrail Event History covers the last 90 days and management events only. Older activity or data events need [CloudTrail Lake](howto-guide.md#query-cloudtrail-lake-instead-of-event-history).
- By default only `us-east-1`, `eu-west-1` and `eu-west-2` are searched. Add `--all-regions` or list regions with `--regions`.
- Read-only events are skipped unless you pass `--include-reads`.
- The report lists collection denials and logging changes as coverage gaps. Look for them on the Summary page.

## Too many events match

`--loose` matches the identifier anywhere in the event body, which includes events performed on the person by someone else. Remove it for exact identity matching.

## An interrupted collection

Run the same command again with `--resume`. It reuses the units that finished successfully from the checkpoint file (`<out>.checkpoint.json`).

## The report page has no fonts or looks different offline

The HTML links IBM Plex from Google Fonts. Without internet access the browser falls back to a system font. Nothing else in the report needs a network.

## `--analyze` fails

The optional analysis pass needs `ANTHROPIC_API_KEY` in the process environment. The report builds without it. See [How-to: the optional analysis pass](howto-guide.md#run-the-optional-ai-analysis-pass).

## Still stuck

Open an issue with the diagnostics listed in [CONTRIBUTING](../CONTRIBUTING.md#what-to-attach). Do not paste account IDs, audit output or credentials into a public issue.
