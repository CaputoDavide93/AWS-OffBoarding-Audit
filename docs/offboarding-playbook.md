# AWS offboarding playbook

This playbook separates two jobs that are often confused:

1. **Access removal** stops a person from using AWS.
2. **Activity review** checks what happened before and after departure.

AWS Offboarding Audit performs the second job with read-only APIs. It does not disable users,
revoke sessions, delete credentials, or change resources. Assign an owner to every manual control
below and keep the completion record with the report.

## Assign owners

| Responsibility | Typical owner |
| --- | --- |
| Departure trigger, last working day, and legal hold | People/HR |
| Authoritative identity provider and device access | IT or identity team |
| IAM Identity Center and standalone IAM access | Cloud/IAM team |
| CloudTrail coverage and finding investigation | Security team |
| Workload, resource, and on-call handover | Line manager or service owner |
| Evidence retention and exception approval | Security or compliance owner |

Use role names that match your organization. The important part is that no checklist item is left
with an implied owner.

## Before the access cutoff

- Record the person's primary email, old usernames, IAM usernames, role-session names, and any
  automation identities they owned. Add known aliases with `--also`; do not use `--loose` unless
  you accept more false positives.
- Confirm the notice date, exact last working day, timezone, and access cutoff time. The report
  cannot identify post-departure activity without this boundary.
- Run `--preflight` and confirm every expected AWS account and Region is in scope. Decide whether
  Event History's 90-day management-event view is sufficient or CloudTrail Lake/data events are
  required.
- Inventory IAM Identity Center group and direct assignments. Also search every account for
  standalone IAM users because those credentials are independent of the central identity source.
- Identify resources, deployment jobs, repositories, alerts, billing contacts, break-glass duties,
  and on-call rotations owned by the person. Assign a new owner before disabling access.
- Identify shared passwords, tokens, access keys, signing keys, and secrets the person knew. Plan
  rotation even when the credential is not named after them.

## At the access cutoff

1. Disable the person in the authoritative identity provider. For an external identity source,
   make the change there rather than relying only on an IAM Identity Center user record.
2. Remove direct and group-based AWS assignments, then revoke active IAM Identity Center sessions.
   Follow the AWS session-revocation procedure and account for already-issued AWS role sessions;
   deleting a portal session is not evidence that every role session has expired.
3. For every standalone IAM user, deactivate console and programmatic access. Check the console
   password, both access-key slots, MFA devices, signing certificates, SSH public keys, and
   service-specific credentials. Deactivate first when your incident or rollback policy requires a
   reversible step; delete after the retention decision is made.
4. Revoke or rotate non-IAM access: source-control tokens, CI/CD secrets, VPN credentials,
   database accounts, Kubernetes credentials, SaaS integrations, and shared team secrets.
5. Transfer workloads and operational ownership. Confirm that scheduled jobs and service accounts
   do not depend on a personal credential before removing it.
6. Complete device retrieval, remote wipe, email/file retention, and physical-access tasks in the
   appropriate IT/HR process. These are outside this repository's AWS evidence.

## After the cutoff

- Collect through a risk-appropriate period after the last working day. Treat collection denials,
  disabled logging, and missing Regions as blind spots, not as proof of no activity.
- Build the report with the notice and last-day dates. Review `Investigate now` first, then `Keep an
  eye on`; `Likely routine` means no warning signal was found in the available evidence, not that
  the action was approved.
- Run the current-state reconciler. A historical `CreateRole`, policy change, public endpoint, or
  shared snapshot matters differently if it has already been removed, but an `unknown` state is
  never evidence of removal.
- Explain every post-departure event. Common benign causes include scheduled automation, a shared
  credential, delayed delivery, or an incorrectly attributed session. Record the evidence for the
  explanation rather than assuming it.
- Preserve the report, collector manifest, accepted blind spots, ticket links, control owners, and
  completion timestamps according to your retention policy.

## Configure an environment once

Keep organization defaults in the ignored `audit-config.yaml` file. Dates can remain on the CLI
when they change per person.

```yaml
collector:
  user: leaver@example.com
  sso_session: company
  days: 30
  all_regions: true
  include_reads: false
  role_preference:
    - SecurityAudit
    - ReadOnlyAccess
  out: aws_offboarding_audit

report:
  timezone: Europe/London
  work_start: 8
  work_end: 19
  org_accounts:
    - "111122223333"
    - "444455556666"
  sequence_hours: 24
```

Run the review:

```bash
aws sso login --sso-session company

.venv/bin/python src/aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --preflight

.venv/bin/python src/aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --open
```

After collection, attach a current-state snapshot and rebuild the report:

```bash
.venv/bin/python src/aws_current_state.py aws_offboarding_audit.json \
  --sso-session company \
  --out aws_offboarding.state.json

.venv/bin/python src/aws_offboarding_dashboard.py \
  --config audit-config.yaml \
  --input aws_offboarding_audit.json \
  --state aws_offboarding.state.json \
  --notice-date 2026-07-24 \
  --last-day 2026-08-15 \
  --open
```

## Exit criteria

An AWS offboarding review is ready to close when:

- the authoritative identity is disabled and its completion is recorded;
- AWS assignments are removed and session revocation/expiry has been addressed;
- standalone IAM users and every associated credential type are disabled or deleted;
- shared credentials known to the person are rotated or have an accepted exception;
- resources, automation, alerts, and operational duties have a current owner;
- collection coverage is complete, or every blind spot has a named risk owner;
- no post-departure event remains unexplained;
- active, present, and unknown current-state findings are resolved or accepted; and
- evidence, tickets, exceptions, and retention decisions are stored in the case record.

## AWS guidance used

- [SEC02-BP05: Audit and rotate credentials periodically](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_audit.html)
- [SEC02-BP06: Employ user groups and attributes](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_user_groups.html)
- [Revoke an IAM Identity Center user session](https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-session.html)
- [Remove or deactivate an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_remove.html)
- [Find unused AWS credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html)
- [Automate user offboarding from multiple AWS accounts](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automate-user-offboarding-from-multiple-aws-accounts-by-using-aws-sso.html)

Review these sources against your identity source, session duration, regulatory duties, and incident
response policy. This playbook is operational guidance, not legal advice.
