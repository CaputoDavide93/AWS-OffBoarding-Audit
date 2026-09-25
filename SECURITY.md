# Security and Data Handling

## Sensitive Data

Collector output and dashboards can contain AWS account IDs, ARNs, source IP addresses, usernames,
resource names, and request parameters. Treat all generated audit artifacts as confidential even
when they do not contain credentials.

Do not commit:

- `.env` files, AWS credential files, private keys, certificates, or API keys;
- `audit-config.yaml` or other organization-specific local configuration;
- collector JSON/CSV/TXT output, manifests, summaries, checkpoints, state snapshots, or baselines;
- generated evidence archives unless they are encrypted and stored outside source control.

The repository `.gitignore` blocks these common paths. Local commit and push hooks run the
repository scanner and Gitleaks. Review `git diff --cached` before every push.

## API Keys

Provide `ANTHROPIC_API_KEY` through the process environment. Do not pass it through chat, commit it,
store it in YAML, or include it in issue and pull-request text.

## If A Secret Is Exposed

1. Revoke or rotate the credential immediately. Removing it from Git is not sufficient.
2. Disable affected AWS access keys or API tokens and inspect their usage history.
3. Remove the value from the working tree and repository history.
4. Re-run the local scanner and GitHub secret scanning before restoring access.
5. Record the exposure through the organization's incident process without copying the secret.

## Reporting A Vulnerability

Use a private repository security advisory or contact the repository owner privately. Do not open
a public issue containing account identifiers, audit evidence, or credentials.
