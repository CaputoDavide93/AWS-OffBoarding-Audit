"""
audit_intel.py — the knowledge layer behind the offboarding report.

Three sources of signal, in increasing order of usefulness:

1. CURATED_CATALOG  — hand-written entries for the actions that matter most in an
   offboarding context, with plain-English explanations and verification steps.
2. TrailDiscover    — 380+ community-catalogued CloudTrail events with MITRE
   ATT&CK mappings and links to real incidents where the API was abused.
   https://github.com/adanalvarez/TrailDiscover  (CC BY 4.0)
3. CONTENT_DETECTORS — inspect the request parameters, not just the event name.
   This is where the real findings are: CreateRole is boring, CreateRole with a
   trust policy naming an outside account is not.

Technique coverage informed by:
  - AWSDoor / Wavestone RiskInsight, "AWSDoor: Persistence on AWS" (2025)
  - Hacking the Cloud, AWS IAM persistence methods
  - HackTricks Cloud, AWS persistence (Lambda, EC2, ECS)
  - Datadog Stratus Red Team attack techniques
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from datetime import timedelta

C, H, M, L = "critical", "high", "medium", "low"

PERSIST = "Persistence"
PRIVESC = "Privilege escalation"
EVASION = "Covering tracks"
EXFIL = "Data exposure"
DESTROY = "Destruction"
CREDS = "Credential access"
NETWORK = "Network exposure"
CHANGE = "Infrastructure change"
RECON = "Reconnaissance"

SEV_ORDER = {C: 0, H: 1, M: 2, L: 3}
SEV_LABEL = {C: "Critical", H: "High", M: "Medium", L: "Low"}


# ==========================================================================
# 1. Curated catalogue
# eventName -> (severity, category, what it does, why it matters, what to verify)
# ==========================================================================
CURATED_CATALOG: dict[str, tuple] = {
    # ---- Persistence: access that outlives SSO deprovisioning
    "CreateAccessKey": (C, PERSIST,
        "Created a long-lived IAM access key.",
        "Access keys never expire and are not revoked when Entra/Identity Center access is removed. In an SSO-managed organisation, a human access key is a common way for access to survive offboarding.",
        "Identify the target IAM user. If it is not a documented service account, deactivate and delete the key, then review everything it has been used for since creation."),
    "UpdateAccessKey": (H, PERSIST,
        "Enabled or disabled an existing IAM access key.",
        "Re-activating a dormant key restores access without creating anything new, so it does not show up in 'recently created credentials' reviews.",
        "Check whether Status was set to Active and whether the key belongs to a human."),
    "DeleteAccessKey": (M, PERSIST,
        "Deleted an IAM access key.",
        "Ordinarily hygiene. In an attack chain it is the step that frees up a slot, since a user can only hold two keys — delete the stale one, create your own.",
        "Check whether a CreateAccessKey for the same user follows shortly after."),
    "CreateLoginProfile": (C, PERSIST,
        "Set a console password on an IAM user.",
        "Grants password-based console access that bypasses SSO entirely and survives Entra deprovisioning.",
        "Confirm the target. Unless it is a documented break-glass account, delete the login profile."),
    "UpdateLoginProfile": (H, PERSIST,
        "Changed an IAM user's console password.",
        "Resetting another principal's password is an account-takeover pattern.",
        "Confirm whose password changed and whether they requested it."),
    "CreateUser": (H, PERSIST,
        "Created a new IAM user.",
        "In an SSO-managed organisation, new standalone IAM users are unusual and are the classic backdoor identity.",
        "Check whether the user was requested, what policies it holds, and whether it has keys or a console password."),
    "CreateRole": (M, PERSIST,
        "Created a new IAM role.",
        "Routine on its own. The risk lives entirely in the trust policy attached to it.",
        "Read the AssumeRolePolicyDocument. Any principal outside your organisation is a finding."),
    "UpdateAssumeRolePolicy": (C, PRIVESC,
        "Changed which principals may assume a role.",
        "Trust-policy backdooring is the stealthiest AWS persistence technique in common use. It stores no credentials in your environment, survives every key rotation, and lets an outside account assume the role directly. Reviewers who focus on access keys miss it entirely.",
        "Diff the trust policy against its previous state. Any AWS account ID that is not yours, and any wildcard principal, should be treated as an active backdoor."),
    "CreateServiceSpecificCredential": (H, PERSIST,
        "Created a service-specific credential (CodeCommit, Keyspaces, etc.).",
        "Another long-lived credential type that survives SSO removal and is almost never audited.",
        "Delete unless tied to a documented service need."),
    "CreateSAMLProvider": (C, PERSIST,
        "Created a SAML identity provider.",
        "A rogue IdP can mint federated sessions completely independently of your Azure tenant.",
        "Verify against your known Entra federation. Anything else is a serious finding."),
    "UpdateSAMLProvider": (C, PERSIST,
        "Modified a SAML provider's metadata.",
        "Swapping IdP metadata redirects trust to a provider someone else controls.",
        "Compare the metadata document against your Entra configuration."),
    "CreateOpenIDConnectProvider": (H, PERSIST,
        "Created an OIDC identity provider.",
        "Legitimate for GitHub Actions federation, but equally a way to grant an external system durable, credential-less access.",
        "Confirm the provider URL, thumbprint, and audience match a known CI/CD integration."),
    "CreateVirtualMFADevice": (M, PERSIST,
        "Created a virtual MFA device.",
        "Registering MFA on another user's behalf can satisfy an MFA condition on a policy the attacker wants to use, without that user's knowledge.",
        "Check which principal it was subsequently enabled for."),
    "EnableMFADevice": (H, PERSIST,
        "Enabled an MFA device on a user.",
        "Enrolling MFA on someone else's account lets the enroller satisfy MFA-conditional policies as that user.",
        "Confirm the user enrolled their own device."),

    # ---- Privilege escalation
    "AttachUserPolicy": (H, PRIVESC, "Attached a managed policy to an IAM user.",
        "Grants new permissions immediately. AdministratorAccess or any iam:* policy is outright escalation.",
        "Check which policy and to whom. Flag anything granting iam:*, sts:AssumeRole on wildcards, or *:*."),
    "AttachRolePolicy": (H, PRIVESC, "Attached a managed policy to a role.",
        "Same escalation risk, applied to a role that may be assumable by the leaver or an external principal.",
        "Check the policy ARN, then check who can assume the role."),
    "AttachGroupPolicy": (H, PRIVESC, "Attached a managed policy to a group.",
        "Escalates every member of the group at once, which is easy to overlook.",
        "Review group membership as well as the policy."),
    "PutUserPolicy": (H, PRIVESC, "Wrote an inline policy directly onto an IAM user.",
        "Inline policies do not appear in the IAM Policies console panel and are routinely missed in access reviews. Attackers prefer them for exactly that reason.",
        "Read the document in full. Look for NotAction, wildcards, and iam:PassRole."),
    "PutRolePolicy": (H, PRIVESC, "Wrote an inline policy onto a role.",
        "Same visibility gap as inline user policies, applied to an assumable identity.",
        "Read the document. iam:PassRole combined with a compute service is a full escalation chain."),
    "PutGroupPolicy": (H, PRIVESC, "Wrote an inline policy onto a group.",
        "Broad, low-visibility permission grant.",
        "Read the document and check group membership."),
    "CreatePolicy": (M, PRIVESC, "Created a customer-managed policy.",
        "Only takes effect once attached, but a permissive policy sitting ready is worth noting — especially one using NotAction.",
        "Review the document and check whether it has since been attached."),
    "CreatePolicyVersion": (H, PRIVESC, "Published a new version of a managed policy.",
        "Silently changes permissions everywhere the policy is attached, with no attachment event to notice.",
        "Diff the new version against the previous default."),
    "SetDefaultPolicyVersion": (H, PRIVESC, "Switched a managed policy to a different version.",
        "Activates a previously staged permissive version without editing anything.",
        "Compare the newly active version against the prior one."),
    "AddUserToGroup": (M, PRIVESC, "Added an IAM user to a group.",
        "Inherits everything the group grants, instantly.",
        "Check what the group grants."),
    "CreateAccessEntry": (H, PRIVESC, "Granted a principal access to an EKS cluster.",
        "Kubernetes-level access sits outside normal IAM review and is frequently forgotten at offboarding.",
        "Check the associated access policy and Kubernetes group mapping."),
    "AssociateAccessPolicy": (H, PRIVESC, "Associated an access policy with an EKS access entry.",
        "Cluster-admin scope is equivalent to full control of everything running on the cluster.",
        "Check whether the policy is cluster-admin."),
    "PutResourcePolicy": (H, PRIVESC, "Set a resource-based policy.",
        "Resource policies grant cross-account access with no corresponding IAM change in your account, so they do not show up in identity-centric reviews.",
        "Look for external account IDs or wildcard principals."),
    "AddPermission": (H, PRIVESC, "Added a permission to a Lambda function or SNS topic policy.",
        "Can allow an external account to invoke a function. When scoped to a specific version via a qualifier, it grants access to a hidden backdoored version while the main alias stays clean.",
        "Check the principal and whether a Qualifier restricts it to a non-current version."),
    "PutRolePermissionsBoundary": (M, PRIVESC, "Set or changed a role's permissions boundary.",
        "Boundaries cap effective permissions. Widening one is an escalation.",
        "Compare against the previous boundary."),
    "DeleteRolePermissionsBoundary": (H, PRIVESC, "Removed a role's permissions boundary.",
        "Lifts the ceiling on what the role can do.",
        "Confirm intent and re-apply if not."),
    "DeleteUserPermissionsBoundary": (H, PRIVESC, "Removed a user's permissions boundary.",
        "Lifts the ceiling on what the user can do.",
        "Confirm intent and re-apply."),

    # ---- Covering tracks
    "StopLogging": (C, EVASION, "Stopped a CloudTrail trail from recording.",
        "There is essentially no legitimate reason to stop audit logging. Everything during the gap is invisible to this report and to your SIEM.",
        "Establish exactly when logging stopped and restarted. Treat the gap as unaudited and reconstruct it from Config history, VPC flow logs, billing data, and the 90-day Event History, which cannot be disabled."),
    "DeleteTrail": (C, EVASION, "Deleted a CloudTrail trail.",
        "Destroys the audit pipeline outright.",
        "Determine what the trail covered and whether the S3 objects already delivered still exist."),
    "UpdateTrail": (H, EVASION, "Reconfigured a CloudTrail trail.",
        "Can narrow scope, redirect delivery, or turn off multi-region coverage while the trail still shows as active.",
        "Diff the configuration, especially IsMultiRegionTrail and the S3 destination."),
    "PutEventSelectors": (C, EVASION, "Changed which events a trail records.",
        "The quiet version of StopLogging: the trail still appears healthy in the console while recording nothing useful. A common trick is pointing data-event selectors at a resource that does not exist so the config looks populated.",
        "Read the selectors. Check whether management events were excluded or scoped to non-existent resources."),
    "DeleteFlowLogs": (H, EVASION, "Deleted VPC flow logs.",
        "Removes the network-level evidence you would need to prove or disprove data movement.",
        "Note the window lost and which VPC is affected."),
    "DeleteLogGroup": (H, EVASION, "Deleted a CloudWatch log group.",
        "Destroys application and access logs permanently.",
        "Identify what it held and whether it was exported or subscribed anywhere."),
    "DeleteLogStream": (M, EVASION, "Deleted a CloudWatch log stream.",
        "Targeted removal of a subset of logs.",
        "Check which stream and what it recorded."),
    "PutRetentionPolicy": (M, EVASION, "Changed log retention.",
        "Shortening retention makes evidence age out on its own, after the person has gone.",
        "Compare the old and new retention values."),
    "StopConfigurationRecorder": (H, EVASION, "Stopped AWS Config recording.",
        "Removes the configuration history you would otherwise use to reconstruct exactly what changed.",
        "Restart it and note the blind window."),
    "DeleteConfigurationRecorder": (C, EVASION, "Deleted the AWS Config recorder.",
        "Permanently ends configuration history for the account.",
        "Recreate and investigate the gap."),
    "DeleteDetector": (C, EVASION, "Deleted the GuardDuty detector.",
        "Disables threat detection for that region entirely.",
        "Recreate immediately and review findings from before the deletion."),
    "UpdateDetector": (H, EVASION, "Changed GuardDuty detector settings.",
        "Can disable detection or strip data sources while the detector still exists.",
        "Check whether Enable was set false or data sources were turned off."),
    "CreateFilter": (M, EVASION, "Created a GuardDuty filter.",
        "Suppression rules hide matching findings from reviewers indefinitely.",
        "Read the criteria and check whether the action is ARCHIVE."),
    "DeleteMembers": (H, EVASION, "Removed member accounts from a security service.",
        "Detaches accounts from centralised monitoring.",
        "Re-enrol the accounts."),
    "DisassociateFromMasterAccount": (H, EVASION, "Detached an account from its security administrator.",
        "Removes centralised visibility over that account.",
        "Re-associate and review activity during the gap."),
    "DeleteAlarms": (M, EVASION, "Deleted CloudWatch alarms.",
        "Removes alerting that would otherwise have flagged unusual activity or spend.",
        "Identify which alarms and restore them."),
    "DisassociateWebACL": (H, EVASION, "Detached a WAF web ACL from a resource.",
        "Leaves the resource unfiltered while the ACL still appears to exist.",
        "Reattach and review access logs for the exposure window."),
    "LeaveOrganization": (C, EVASION, "Removed the account from the AWS Organization.",
        "Strips every SCP, centralised log, and governance control at once. Critically, you also lose administrative authority over the account — you cannot shut it down, suspend billing, or terminate its resources from the management account. The workloads keep running under someone else's sole control.",
        "Treat as a live incident. Contact AWS Support to recover control. Apply an SCP denying organizations:LeaveOrganization at the org root so it cannot recur."),
    "RemoveAccountFromOrganization": (C, EVASION, "Removed a member account from the organisation.",
        "Same loss of central control and visibility.",
        "Re-invite and audit the account fully."),
    "DetachPolicy": (H, EVASION, "Detached a policy from an OU or account.",
        "If it was an SCP, this lifts guardrails for everything beneath that target.",
        "Reattach and review activity during the gap."),
    "DisablePolicyType": (C, EVASION, "Disabled a policy type across the organisation.",
        "Turns off an entire class of guardrail, such as all SCPs, in one call.",
        "Re-enable immediately and audit every account for changes made while it was off."),

    # ---- Data exposure
    "ModifySnapshotAttribute": (C, EXFIL, "Changed who can access an EBS snapshot.",
        "Sharing a snapshot with an outside account exports the entire disk with one API call, leaves the original untouched, and produces no network transfer for EDR or DLP tools to inspect.",
        "Check the userId on the createVolumePermission. Anything outside your organisation, or 'all', is a serious finding. Revoke, then scope what was on that volume."),
    "ModifyImageAttribute": (C, EXFIL, "Changed who can access an AMI.",
        "An AMI is a full disk image. Sharing it externally exports everything baked in, including any embedded credentials.",
        "Check launch permissions. Revoke external sharing and rotate anything the image may contain."),
    "ModifyDBSnapshotAttribute": (C, EXFIL, "Changed who can restore an RDS snapshot.",
        "Exposes the entire database contents to whoever is named.",
        "Check the account IDs on the restore attribute. Revoke and scope the data involved."),
    "ModifyDBClusterSnapshotAttribute": (C, EXFIL, "Changed who can restore an Aurora cluster snapshot.",
        "Same full-database exposure.",
        "Revoke external access and scope the data."),
    "PutBucketPolicy": (H, EXFIL, "Changed an S3 bucket policy.",
        "Bucket policies can grant public or cross-account read to everything in the bucket.",
        "Read the policy. Look for Principal '*' or unknown account IDs."),
    "PutBucketAcl": (H, EXFIL, "Changed an S3 bucket ACL.",
        "The legacy route to making a bucket world-readable.",
        "Check for AllUsers or AuthenticatedUsers grants."),
    "DeleteBucketPolicy": (H, EXFIL, "Removed an S3 bucket policy.",
        "If the policy was the control restricting access, removing it opens the bucket up.",
        "Determine what it enforced and restore it."),
    "PutBucketPublicAccessBlock": (H, EXFIL, "Changed a bucket's public access block.",
        "This is the guardrail preventing accidental public exposure. Turning it off is deliberate.",
        "Check whether the settings were set false and whether the bucket then became public."),
    "DeletePublicAccessBlock": (C, EXFIL, "Removed the public access block entirely.",
        "Removes the last safety net against public S3 exposure.",
        "Restore immediately and check access logs for the exposure window."),
    "PutAccountPublicAccessBlock": (C, EXFIL, "Changed the account-wide S3 public access block.",
        "Affects every bucket in the account at once.",
        "Restore and audit all buckets."),
    "PutBucketReplication": (C, EXFIL, "Configured S3 replication.",
        "Replication continuously copies objects to another bucket, potentially in an account you do not control, with no further API calls. It keeps working indefinitely after the person leaves and generates no ongoing signal.",
        "Check the destination bucket and its owning account. Remove if external."),
    "PutBucketVersioning": (M, DESTROY, "Changed bucket versioning.",
        "Suspending versioning means subsequent deletions cannot be undone.",
        "Check whether versioning was suspended and what was deleted afterwards."),
    "PutBucketLifecycle": (H, DESTROY, "Set an S3 lifecycle rule.",
        "Lifecycle expiry is a delayed-action delete that fires long after the person has gone.",
        "Read the rule. Short expiration on important prefixes is a finding."),
    "PutBucketLifecycleConfiguration": (H, DESTROY, "Set an S3 lifecycle configuration.",
        "Lifecycle rules bypass the slow, noisy path of recursive object deletion: AWS applies expiry internally and retroactively, so a one-day rule can empty a bucket with no DeleteObject events attributed to anyone. It is the quietest way to destroy an S3 bucket, and defenders typically have under a day to catch it.",
        "Read the expiration rules and affected prefixes. If expiry is set to the minimum, remove the rule immediately and restore from delete markers or backup."),
    "CreateSnapshot": (M, EXFIL, "Created an EBS snapshot.",
        "Routine with backup automation, which is exactly why attackers mimic it. It is the first half of snapshot exfiltration.",
        "Check whether this snapshot was subsequently shared or copied. Compare against your backup tooling's tagging convention."),
    "CopySnapshot": (H, EXFIL, "Copied a snapshot, possibly cross-region.",
        "Staging data in a region you do not monitor is a common pre-exfiltration step.",
        "Check the destination region against the regions you normally use."),
    "CopyImage": (H, EXFIL, "Copied an AMI to another region.",
        "Same staging pattern.",
        "Check the destination region."),
    "CreateDBSnapshot": (M, EXFIL, "Created an RDS snapshot.",
        "Routine, but the first half of a database export.",
        "Check whether it was subsequently shared or copied."),
    "ExportImage": (H, EXFIL, "Exported a VM image to S3.",
        "Produces a downloadable copy of a full machine image.",
        "Check the destination bucket and whether the object was retrieved."),
    "CreateExportTask": (M, EXFIL, "Exported CloudWatch logs to S3.",
        "Bulk log extraction, which frequently contains sensitive data.",
        "Check the destination bucket's owner."),
    "SharedSnapshotVolumeCreated": (H, EXFIL, "A volume was created from a snapshot shared by another account.",
        "The receiving end of snapshot exfiltration.",
        "Identify the source snapshot and sharing account."),

    # ---- Credential access
    "GetSecretValue": (M, CREDS, "Read a secret from Secrets Manager.",
        "Normal for applications. A human reading secrets shortly before leaving is a rotation trigger regardless of intent.",
        "Note which secrets. Rotate anything read close to the departure date."),
    "BatchGetSecretValue": (H, CREDS, "Bulk-read multiple secrets.",
        "Bulk retrieval by a human is rarely operational and closely matches credential harvesting.",
        "Rotate everything in the batch."),
    "GetParameter": (L, CREDS, "Read an SSM parameter.",
        "Routine unless it is a SecureString.",
        "Check whether SecureString parameters were involved."),
    "GetParameters": (M, CREDS, "Read multiple SSM parameters.",
        "Bulk reads of SecureString values are credential harvesting.",
        "Rotate any SecureString values retrieved."),
    "GetParametersByPath": (M, CREDS, "Enumerated and read a whole SSM parameter path.",
        "Retrieves an entire configuration namespace in one call, which often includes credentials.",
        "Check whether decryption was requested and rotate anything sensitive."),
    "GetPasswordData": (H, CREDS, "Retrieved the Windows administrator password for an EC2 instance.",
        "Provides direct administrative access to the instance.",
        "Confirm operational need and rotate the local administrator password."),
    "PutKeyPolicy": (H, PRIVESC, "Changed a KMS key policy.",
        "Key policies can grant an external account the ability to decrypt your data.",
        "Look for external principals."),
    "ScheduleKeyDeletion": (C, DESTROY, "Scheduled a KMS key for deletion.",
        "When the key goes, everything encrypted with it is permanently unrecoverable. The mandatory waiting period means it detonates well after the person has left.",
        "Cancel the deletion now unless you are certain. Identify everything the key encrypts."),
    "DisableKey": (H, DESTROY, "Disabled a KMS key.",
        "Immediately breaks decryption for everything using it.",
        "Re-enable unless there is a documented reason."),
    "DisableKeyRotation": (M, CREDS, "Turned off automatic key rotation.",
        "Keeps key material static, which benefits anyone holding a copy.",
        "Re-enable rotation."),

    # ---- Network exposure
    "AuthorizeSecurityGroupIngress": (H, NETWORK, "Opened an inbound port on a security group.",
        "Opening a port to 0.0.0.0/0 — particularly SSH, RDP, or a database port — creates a durable public entry point that persists indefinitely.",
        "Check the CIDR and port. Anything open to the internet needs written justification."),
    "AuthorizeSecurityGroupEgress": (M, NETWORK, "Opened an outbound security group rule.",
        "Broad egress enables data to be pushed to arbitrary destinations.",
        "Check the destination CIDR."),
    "RevokeSecurityGroupIngress": (M, NETWORK, "Removed an inbound rule.",
        "Usually hygiene, but can also remove a restriction that was doing real work.",
        "Check what was removed."),
    "ModifyNetworkAclEntry": (M, NETWORK, "Changed a network ACL rule.",
        "Subnet-level filtering change that can widen exposure.",
        "Check direction and CIDR."),
    "CreateVpcPeeringConnection": (H, NETWORK, "Created a VPC peering connection.",
        "Peering to an external account bridges your private network somewhere else.",
        "Verify the peer account is one of yours."),
    "AcceptVpcPeeringConnection": (H, NETWORK, "Accepted a VPC peering request.",
        "Completes a network bridge, potentially to an outside party.",
        "Verify the requester account."),
    "CreateClientVpnEndpoint": (H, NETWORK, "Created a Client VPN endpoint.",
        "Remote network access into the VPC that persists independently of SSO.",
        "Verify authorisation rules and client certificates. Remove if undocumented."),
    "ModifyVpcEndpointServicePermissions": (H, NETWORK, "Changed who can connect to a VPC endpoint service.",
        "Can expose an internal service to an outside account.",
        "Check the allowed principals."),
    "CreateInternetGateway": (M, NETWORK, "Created an internet gateway.",
        "Can make a previously private subnet internet-facing.",
        "Check whether it was attached, and to what."),
    "ChangeResourceRecordSets": (M, NETWORK, "Changed DNS records.",
        "Repointing a record redirects traffic, including mail.",
        "Diff the change, especially MX, NS, and production A/CNAME records."),

    # ---- Execution and resource-based persistence
    "CreateFunction": (M, PERSIST, "Created a Lambda function.",
        "A function with a schedule, trigger, or public URL is a dormant backdoor that keeps running long after departure — no credentials required, and it executes with whatever role is attached.",
        "Review the code, the attached role, any layers, and every trigger including Function URLs and API Gateway."),
    "UpdateFunctionCode": (M, PERSIST, "Changed a Lambda function's code.",
        "Inserts behaviour into an existing trusted function. If the deployment did not come from CI, the code may exist nowhere else.",
        "Diff the deployed code against the repository. Check for published versions beyond $LATEST."),
    "UpdateFunctionConfiguration": (M, PERSIST, "Changed a Lambda function's configuration.",
        "This is the event that records a layer being attached. A poisoned layer overrides a standard library (a backdoored requests.get, for example) and gives code execution every invocation — and the console shows only the layer's name, never its contents, so it survives casual review.",
        "Check whether Layers changed. If so, download the layer ZIP and inspect it. Also check for changed environment variables and execution role."),
    "PublishLayerVersion": (H, PERSIST, "Published a new Lambda layer version.",
        "Layers are the standard hiding place for Lambda backdoors precisely because their contents are not visible in the console.",
        "Download and inspect the layer contents. Confirm it came from CI."),
    "CreateFunctionUrlConfig": (H, PERSIST, "Created a public URL for a Lambda function.",
        "Exposes the function directly to the internet. With AuthType NONE it is an unauthenticated remote-execution endpoint.",
        "Check AuthType. If NONE, treat as a live backdoor and delete it."),
    "AddLayerVersionPermission": (H, PERSIST, "Shared a Lambda layer with another account.",
        "Cross-account layer sharing can pull external code into your functions.",
        "Check the principal."),
    "PutFunctionRecursionConfig": (H, PERSIST, "Allowed a Lambda function to invoke itself recursively.",
        "AWS normally breaks recursive loops. Allowing them lets a single seed invocation create a self-sustaining heartbeat with no scheduler and no EventBridge rule to find.",
        "Set back to Terminate and review the function's code and destinations."),
    "PutRule": (M, PERSIST, "Created or updated an EventBridge rule.",
        "Scheduled rules provide timed execution that persists after departure.",
        "Check the schedule expression and target."),
    "PutTargets": (M, PERSIST, "Added a target to an EventBridge rule.",
        "Connects a trigger to something that runs. Also the step that arms a scheduled ECS task or Lambda.",
        "Check what the target is and what role it passes."),
    "RegisterTaskDefinition": (M, PERSIST, "Registered an ECS task definition.",
        "A task definition pointing at an external image, combined with a scheduled rule, is container-based persistence.",
        "Check the container image source and the task role."),
    "SendCommand": (H, PERSIST, "Ran a command on EC2 instances via SSM.",
        "Remote code execution on instances without any network access. Frequently used to plant SSH keys or open reverse tunnels. CloudTrail does not record the command body, so the log alone cannot tell you what ran.",
        "You will not see the command in CloudTrail. Check SSM Run Command history, the instance's own logs, authorized_keys, and outbound connections."),
    "StartSession": (M, PERSIST, "Opened an interactive SSM session to an instance.",
        "Interactive shell access. Console-initiated sessions log this event; CLI-initiated ones may only surface as GetCommandInvocation.",
        "Correlate with instance-side logs. CloudTrail will not show what was typed."),
    "ReplaceRootVolume": (H, PERSIST, "Replaced an EC2 instance's root volume.",
        "Can swap in a modified image while the instance ID, IP, and tags all stay the same, so nothing downstream looks changed.",
        "Compare the replacement AMI or snapshot against what you expect."),
    "ModifyInstanceAttribute": (M, PERSIST, "Changed an EC2 instance attribute.",
        "Changing user data means the new script runs on next boot — delayed execution that fires after departure.",
        "Check whether userData or the IAM instance profile changed."),
    "RunInstances": (L, CHANGE, "Launched EC2 instances.",
        "Routine, unless the instance type or region is unusual — large GPU instances in unused regions are the crypto-mining pattern.",
        "Check instance type and region."),

    # ---- Destruction
    "TerminateInstances": (H, DESTROY, "Terminated EC2 instances.",
        "Irreversible unless volumes were retained.",
        "Check which instances and whether their volumes were set to delete on termination."),
    "DeleteDBInstance": (C, DESTROY, "Deleted an RDS database instance.",
        "Permanent data loss if no final snapshot was taken.",
        "Check SkipFinalSnapshot in the request parameters. If true, the data is gone."),
    "DeleteDBCluster": (C, DESTROY, "Deleted an Aurora cluster.",
        "Same permanent-loss risk.",
        "Check whether a final snapshot was taken."),
    "DeleteBucket": (C, DESTROY, "Deleted an S3 bucket.",
        "A bucket must be emptied first, so this usually follows bulk object deletion or a lifecycle expiry.",
        "Determine what it held and whether versioning or backup existed."),
    "DeleteObjects": (H, DESTROY, "Bulk-deleted S3 objects.",
        "Recoverable only if versioning was on.",
        "Check versioning and restore from delete markers where possible."),
    "DeleteStack": (C, DESTROY, "Deleted a CloudFormation stack.",
        "Removes every resource the stack managed in one action.",
        "Identify the resources and confirm the template is still in source control."),
    "DeleteFunction": (H, DESTROY, "Deleted a Lambda function.",
        "Removes code that may exist nowhere else.",
        "Check whether the source is in version control."),
    "DeleteTable": (C, DESTROY, "Deleted a DynamoDB table.",
        "Permanent unless point-in-time recovery or a backup existed.",
        "Check for PITR and restore if available."),
    "DeleteCluster": (C, DESTROY, "Deleted a cluster (EKS, ECS, Redshift, or similar).",
        "Removes the platform and everything running on it.",
        "Identify which service and what was hosted."),
    "DeleteRepository": (C, DESTROY, "Deleted a code or container repository.",
        "Potential permanent loss of source or images.",
        "Check for mirrors, local clones, or registry replication."),
    "DeleteVolume": (H, DESTROY, "Deleted an EBS volume.",
        "Permanent unless a snapshot exists.",
        "Check for snapshots."),
    "DeleteSnapshot": (H, DESTROY, "Deleted a snapshot.",
        "Removes a recovery point — most serious if it was the backup for something else deleted nearby.",
        "Correlate with other deletions in the timeline."),
    "DeleteBackupVault": (C, DESTROY, "Deleted an AWS Backup vault.",
        "Destroys the backups themselves — the thing you would rely on to recover from everything else on this list.",
        "Treat as a serious incident. Check for vault lock and cross-account copies."),
    "DeleteRecoveryPoint": (C, DESTROY, "Deleted a backup recovery point.",
        "Targeted destruction of a specific restore point.",
        "Check what it protected and whether other copies exist."),
    "DeleteSecret": (H, DESTROY, "Deleted a secret from Secrets Manager.",
        "Deletion is delayed by a recovery window, so it is often still reversible.",
        "Restore if within the recovery window."),
    "DeleteHostedZone": (C, DESTROY, "Deleted a Route 53 hosted zone.",
        "Takes down DNS for the domain and everything depending on it.",
        "Restore records urgently from backup or IaC."),
    "DeleteUser": (M, CHANGE, "Deleted an IAM user.",
        "Routine cleanup, or removal of the evidence of a backdoor account.",
        "Check whether the user was one created recently by the same person."),
    "DeleteRole": (M, CHANGE, "Deleted an IAM role.",
        "Usually cleanup. Worth checking if the role was recently created.",
        "Cross-reference against role creations in this report."),

    # ---- Account level
    "UpdateAccountPasswordPolicy": (M, PRIVESC, "Changed the account password policy.",
        "Weakening password rules assists password-based access.",
        "Compare against your standard."),
    "DeleteAccountPasswordPolicy": (H, PRIVESC, "Removed the account password policy.",
        "Drops password requirements to AWS defaults.",
        "Restore your policy."),
    "EnableRegion": (M, CHANGE, "Enabled an AWS region.",
        "Newly enabled regions typically sit outside existing monitoring, trails, and GuardDuty coverage, which makes them a convenient place to run things unnoticed.",
        "Check for resources there and confirm CloudTrail and GuardDuty coverage."),
    "PutAccountSetting": (M, CHANGE, "Changed an account-level setting.",
        "Some settings affect security defaults.",
        "Check which setting changed."),
    "ConsoleLogin": (L, RECON, "Signed in to the AWS console.",
        "Baseline activity, useful for establishing working patterns and spotting logins after the last working day.",
        "Check the source IP and whether MFA was used."),
    "GetFederationToken": (M, CREDS, "Generated federated console credentials.",
        "Can produce a console sign-in URL usable from anywhere, decoupled from the SSO session.",
        "Check the policy passed and the session duration."),
}

PREFIX_RULES = [
    (("Delete", "Terminate", "Destroy", "Purge"), H, DESTROY,
     "Deleted or destroyed a resource.",
     "Not individually catalogued, but deletions close to a departure date should be confirmed as intentional.",
     "Identify the resource and confirm the deletion was planned work."),
    (("Revoke", "Detach", "Disable", "Remove", "Stop", "Suspend"), M, CHANGE,
     "Removed, detached, or disabled something.",
     "Either routine cleanup or the removal of a control.",
     "Check what was removed and whether it was a security control."),
    (("Create", "Put", "Add", "Attach", "Associate", "Enable", "Register", "Publish"), M, CHANGE,
     "Created or attached a resource or setting.",
     "Routine change. Review if it touches access, networking, or data movement.",
     "Confirm it matches known planned work."),
    (("Update", "Modify", "Set", "Change", "Replace", "Import"), M, CHANGE,
     "Modified an existing resource or configuration.",
     "Configuration drift from a departing engineer should be reconciled against your IaC.",
     "Diff against the expected configuration."),
    (("Get", "List", "Describe", "Head", "Search", "Lookup", "Select", "Query", "Scan"), L, RECON,
     "Read or listed resources.",
     "Read activity is normally benign, but broad enumeration shortly before departure can be reconnaissance.",
     "Investigate only if the volume or breadth is unusual."),
]


# ==========================================================================
# 2. TrailDiscover enrichment
# ==========================================================================
TRAILDISCOVER_URL = "https://raw.githubusercontent.com/adanalvarez/TrailDiscover/main/docs/events.json"
CACHE_PATH = os.path.expanduser("~/.cache/aws-offboarding-audit/traildiscover.json")
CACHE_TTL = 7 * 24 * 3600


def load_traildiscover(refresh: bool = False, quiet: bool = False) -> dict[str, dict]:
    """Fetch the TrailDiscover event corpus, cached locally for a week."""
    data = None
    if not refresh and os.path.exists(CACHE_PATH):
        if time.time() - os.path.getmtime(CACHE_PATH) < CACHE_TTL:
            try:
                with open(CACHE_PATH, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError):
                data = None
    if data is None:
        try:
            with urllib.request.urlopen(TRAILDISCOVER_URL, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
            with open(CACHE_PATH, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except Exception as exc:
            if not quiet:
                print(f"  ! TrailDiscover enrichment unavailable ({type(exc).__name__}); "
                      f"using the built-in catalogue only.")
            return {}

    index: dict[str, dict] = {}
    for entry in data:
        name = entry.get("eventName")
        if not name:
            continue
        index[name] = {
            "service": entry.get("awsService", ""),
            "aws_description": entry.get("description", ""),
            "tactics": [t.split(" - ", 1)[-1] for t in entry.get("mitreAttackTactics", [])],
            "techniques": entry.get("mitreAttackTechniques", []),
            "used_in_wild": bool(entry.get("usedInWild")),
            "incidents": entry.get("incidents", [])[:3],
            "implications": entry.get("securityImplications", ""),
        }
    return index


def classify_event(name: str, td: dict[str, dict] | None = None) -> dict:
    """Resolve one event name to a full intelligence record."""
    if name in CURATED_CATALOG:
        sev, cat, desc, why, verify = CURATED_CATALOG[name]
        curated = True
    else:
        curated = False
        for prefixes, sev, cat, desc, why, verify in PREFIX_RULES:
            if name.startswith(prefixes):
                break
        else:
            sev, cat = M, CHANGE
            desc = "Performed an action not in the reference catalogue."
            why = "Unrecognised actions still represent a change made by the leaver."
            verify = "Look this API up in the AWS documentation and confirm it was expected work."

    rec = {"severity": sev, "category": cat, "description": desc, "why": why,
           "verify": verify, "curated": curated, "tactics": [], "used_in_wild": False,
           "incidents": [], "service": "", "implications": ""}

    extra = (td or {}).get(name)
    if extra:
        rec["tactics"] = extra["tactics"]
        rec["used_in_wild"] = extra["used_in_wild"]
        rec["incidents"] = extra["incidents"]
        rec["service"] = extra["service"]
        rec["implications"] = extra["implications"]
        if not curated:
            # Prefer TrailDiscover's wording over a generic prefix guess.
            if extra["aws_description"]:
                rec["description"] = extra["aws_description"]
            if extra["implications"]:
                rec["why"] = extra["implications"]
            # "Used in the wild" is true of almost every read API, because
            # attackers enumerate before they act. Escalating on that alone
            # floods the report with DescribeInstances. Only bump events whose
            # mapped tactics are actually offensive, and never a read call.
            offensive = {"Persistence", "Privilege Escalation", "Defense Evasion",
                         "Exfiltration", "Impact", "Credential Access"}
            is_read = name.startswith(("Get", "List", "Describe", "Head", "Search", "Lookup"))
            if (extra["used_in_wild"] and not is_read
                    and offensive & set(extra["tactics"])
                    and SEV_ORDER[rec["severity"]] > SEV_ORDER[M]):
                rec["severity"] = M
                rec["verify"] = ("This API has been observed in real-world attacks. Confirm this "
                                 "instance was planned work, using the linked incidents for context.")
    return rec


# ==========================================================================
# 3. Content detectors — inspect request parameters, not just event names
# ==========================================================================
ACCOUNT_RE = re.compile(r"\b(\d{12})\b")
OPEN_CIDR = ("0.0.0.0/0", "::/0")
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
               27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5439: "Redshift",
               11211: "Memcached", 2375: "Docker API", 445: "SMB"}


def _inflate(obj, depth=0):
    """
    Policy documents arrive as JSON strings nested inside JSON, sometimes doubly
    escaped. Parse them in place so structural checks see the real shape rather
    than a wall of backslashes — escaped quotes silently defeat naive matching.
    """
    if depth > 4:
        return obj
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(("{", "[")) and len(s) > 2:
            try:
                return _inflate(json.loads(s), depth + 1)
            except (json.JSONDecodeError, ValueError):
                return obj
        return obj
    if isinstance(obj, dict):
        return {k: _inflate(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_inflate(v, depth + 1) for v in obj]
    return obj


def _params(row) -> tuple[dict, str]:
    raw = row.get("request_params") or ""
    try:
        parsed = json.loads(raw) if raw else {}
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    parsed = _inflate(parsed) if isinstance(parsed, dict) else {}
    try:
        flat = json.dumps(parsed) if parsed else raw
    except (TypeError, ValueError):
        flat = raw
    return parsed, flat


def _walk(obj, key_pred):
    """Yield values whose key matches key_pred, at any depth."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if key_pred(str(k)):
                yield v
            yield from _walk(v, key_pred)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item, key_pred)


TARGET_FIELDS = (
    ("user", ("username", "userName")),
    ("role", ("rolename", "roleName")),
    ("function", ("functionname", "functionName")),
    ("snapshot", ("snapshotid", "snapshotId", "dbsnapshotidentifier")),
    ("database", ("dbinstanceidentifier", "dBInstanceIdentifier", "dbclusteridentifier")),
    ("bucket", ("bucket", "bucketname", "bucketName")),
    ("security-group", ("groupid", "groupId")),
    ("key", ("keyid", "keyId")),
    ("trail", ("trailname", "trailName", "name")),
    ("resource", ("resourcearn", "resourceArn")),
)


def _find_named_values(obj, names: set[str]):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in names:
                yield value
            yield from _find_named_values(value, names)
    elif isinstance(obj, list):
        for item in obj:
            yield from _find_named_values(item, names)


def normalize_target(row: dict) -> dict:
    """Extract a stable best-effort target identity for filtering and correlation."""
    parsed, _ = _params(row)
    for target_type, aliases in TARGET_FIELDS:
        names = {name.lower() for name in aliases}
        for value in _find_named_values(parsed, names):
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, dict):
                    continue
                normalized = str(candidate or "").strip()
                if normalized:
                    return {
                        "target_type": target_type,
                        "target_id": normalized,
                        "target_key": f"{target_type}:{normalized.lower()}",
                    }

    resource = str(row.get("resources") or "").split(";", 1)[0].strip()
    if resource:
        return {
            "target_type": "resource",
            "target_id": resource,
            "target_key": f"resource:{resource.lower()}",
        }
    return {"target_type": "unknown", "target_id": "", "target_key": ""}


def detect_content(row, org_accounts: set[str]) -> list[dict]:
    """
    Inspect the request parameters for the things that actually distinguish a
    backdoor from routine work. Returns a list of findings.
    """
    parsed, raw = _params(row)
    if not raw:
        return []
    name = row.get("event_name", "")
    out: list[dict] = []

    def add(sev, title, detail):
        out.append({"severity": sev, "title": title, "detail": detail})

    lowered = raw.lower()

    # --- NotAction with Allow: looks narrow, grants everything (AWSDoor technique)
    if '"notaction"' in lowered and '"allow"' in lowered:
        add(C, "Policy uses NotAction with Allow",
            "An Allow statement built on NotAction grants every action except the ones listed. "
            "A policy that appears to be about one S3 bucket can in fact confer administrator "
            "rights. Read the full policy document — do not judge it by the resource it names.")

    # --- Wildcard action
    for act in _walk(parsed, lambda k: k.lower() in ("action", "notaction")):
        vals = act if isinstance(act, list) else [act]
        if any(isinstance(v, str) and v.strip() in ("*", "*:*") for v in vals):
            add(H, "Policy grants all actions",
                "The policy document contains a wildcard action, which is full administrative access "
                "within its resource scope.")
            break

    # --- External AWS account referenced
    current = str(row.get("account_id", ""))
    seen = {a for a in ACCOUNT_RE.findall(raw) if a != current}
    external = seen - org_accounts if org_accounts else set()
    if external:
        listed = ", ".join(sorted(external)[:5])
        add(C, f"References AWS account(s) outside your organisation: {listed}",
            "An account ID appears in this request that is not in the organisation list you "
            "supplied. For a trust policy, snapshot share, bucket policy, or replication rule, "
            "this is a direct cross-account grant to a third party. Verify who owns it.")
    elif seen:
        listed = ", ".join(sorted(seen)[:5])
        add(M, f"References other AWS account(s): {listed}",
            "Cross-account reference. Re-run with --org-accounts so these can be checked "
            "automatically against your organisation.")

    # --- Public principals
    public = False
    for pr in _walk(parsed, lambda k: k.lower() == "principal"):
        vals = [pr] if isinstance(pr, str) else (
            list(pr.values()) if isinstance(pr, dict) else pr if isinstance(pr, list) else [])
        for v in vals:
            for item in (v if isinstance(v, list) else [v]):
                if isinstance(item, str) and item.strip() in ("*", "arn:aws:iam::*:root"):
                    public = True
    if public or "AllUsers" in raw or "AuthenticatedUsers" in raw:
        add(C, "Grants access to any principal",
            "The policy names a wildcard or all-users principal, which makes the resource "
            "accessible to anyone on the internet or to any authenticated AWS account.")

    # --- High-privilege managed policies
    for arn in _walk(parsed, lambda k: k.lower() in ("policyarn", "policyarns")):
        for a in (arn if isinstance(arn, list) else [arn]):
            if not isinstance(a, str):
                continue
            short = a.rsplit("/", 1)[-1]
            if short in ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess",
                         "AWSOrganizationsFullAccess", "AdministratorAccess-Amplify"):
                add(C, f"Attached the {short} managed policy",
                    "This grants effectively unlimited control within its scope. Confirm the "
                    "target identity needed it, and whether the leaver could assume it.")

    # --- Snapshot / image sharing
    if name in ("ModifySnapshotAttribute", "ModifyImageAttribute",
                "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"):
        if '"all"' in lowered or "'all'" in lowered:
            add(C, "Snapshot or image made public",
                "Shared with 'all', meaning any AWS account can copy the entire disk or database.")
        elif external:
            add(C, "Snapshot or image shared with an external account",
                "Full disk contents exported to an account outside your organisation, with no "
                "network traffic and no object-level logging. Revoke and scope the data involved.")

    # --- S3 lifecycle shadow-delete
    if name.startswith("PutBucketLifecycle"):
        for exp in _walk(parsed, lambda k: k.lower() == "expiration"):
            days = None
            if isinstance(exp, dict):
                days = exp.get("Days") or exp.get("days")
            if isinstance(days, int) and days <= 3:
                add(C, f"Lifecycle rule expires objects after {days} day(s)",
                    "Lifecycle expiry applies retroactively to existing objects and is processed "
                    "internally by AWS, so mass deletion produces no per-object DeleteObject events "
                    "attributable to anyone. This is the quietest way to empty a bucket. Remove the "
                    "rule now — the window to recover is roughly one day.")
                break

    # --- Public access block being turned off
    if "publicaccessblock" in name.lower():
        if '"false"' in lowered or ": false" in lowered or ":false" in lowered:
            add(C, "S3 public access block weakened",
                "One or more public-access-block settings were set to false, removing the guardrail "
                "that prevents a bucket from being made public.")

    # --- Lambda exposure and layers
    if name == "CreateFunctionUrlConfig" or "functionurl" in name.lower():
        auth_types = list(_walk(parsed, lambda k: k.lower() == "authtype"))
        if any(isinstance(value, str) and value.upper() == "NONE" for value in auth_types):
            add(C, "Lambda Function URL created with no authentication",
                "An unauthenticated HTTPS endpoint that executes the function with its full IAM "
                "role. If the function runs arbitrary input, this is a remote shell into the account.")
        else:
            add(H, "Lambda Function URL created",
                "The function is now reachable from the internet. Confirm this was intended.")
    if name == "UpdateFunctionConfiguration" and "layers" in lowered:
        add(H, "Lambda layer attached or changed",
            "Layer contents are not shown in the console — only the layer name — so a poisoned "
            "dependency here survives a code review of the function itself. Download the layer ZIP "
            "and inspect it.")
    if name == "AddPermission" and "qualifier" in lowered:
        add(H, "Lambda permission scoped to a specific version or alias",
            "Granting invoke rights on a pinned version lets someone call a backdoored version "
            "directly while $LATEST and the primary alias stay clean and pass inspection.")
    if "recursion" in name.lower() and "allow" in lowered:
        add(H, "Lambda recursive invocation enabled",
            "AWS breaks self-invoking loops by default. Allowing recursion lets one seed invocation "
            "sustain itself indefinitely with no scheduler or EventBridge rule to find.")

    # --- Open security group rules
    if name.startswith("AuthorizeSecurityGroup"):
        if any(c in raw for c in OPEN_CIDR):
            ports = set()
            for p in _walk(parsed, lambda k: k.lower() in ("fromport", "toport")):
                if isinstance(p, int):
                    ports.add(p)
            named = [f"{RISKY_PORTS[p]} ({p})" for p in sorted(ports) if p in RISKY_PORTS]
            if named:
                add(C, f"Opened {', '.join(named)} to the entire internet",
                    "A sensitive service port is now reachable from any address. This is a durable "
                    "entry point that will outlast the person's departure. Close it.")
            else:
                add(H, "Security group rule opened to 0.0.0.0/0",
                    "Reachable from any address on the internet. Confirm this was intended.")

    # --- Database deletion without a final snapshot
    if name.startswith("DeleteDB") and ("skipfinalsnapshot" in lowered and "true" in lowered):
        add(C, "Database deleted with no final snapshot",
            "SkipFinalSnapshot was true, so no restore point was created. Unless a separate backup "
            "or PITR window exists, this data is permanently gone.")

    # --- PassRole escalation chain
    if "iam:passrole" in lowered:
        add(H, "Policy grants iam:PassRole",
            "PassRole combined with permission to launch a compute service (Lambda, EC2, ECS, "
            "Glue) is a complete privilege-escalation chain: attach a more privileged role to a "
            "resource you control, then use it.")

    # --- Trust policy specifics
    if name == "UpdateAssumeRolePolicy":
        if '"sts:assumerolewithwebidentity"' in lowered:
            add(H, "Trust policy allows web-identity federation",
                "Check the OIDC provider and the condition block. A missing or wildcard 'sub' "
                "condition means any repository or workload on that provider can assume the role.")
        if '":root"' in raw and external:
            add(C, "Trust policy trusts an entire external account",
                "Trusting :root means every principal in that account can assume the role.")

    # --- MFA registered for someone else
    if name in ("EnableMFADevice", "CreateVirtualMFADevice"):
        add(M, "MFA device registered",
            "If the device was enrolled on another user's account, whoever holds it can satisfy "
            "MFA-conditional policies as that user. Confirm the user enrolled it themselves.")

    # --- Cross-region staging
    if name in ("CopySnapshot", "CopyImage"):
        add(H, "Resource copied, possibly to another region",
            "Copying into a region you do not actively monitor is a common staging step before "
            "exfiltration. Check the destination region against the ones you normally use.")

    return out


# ==========================================================================
# 4. Sequence detection — combinations that matter more than their parts
# ==========================================================================
SEQUENCES = [
    (("CreateUser", "CreateAccessKey"),
     "IAM user created and given long-lived keys",
     "Together these produce credentials that survive Entra deprovisioning entirely. In an "
     "SSO-managed org this is the textbook backdoor. Treat it as one until proven otherwise: "
     "identify the user, disable the key, and check what it has been used for."),
    (("CreateRole", "UpdateAssumeRolePolicy"),
     "Role created and its trust policy modified",
     "The two halves of trust-policy backdooring. Read the final trust policy and confirm every "
     "principal in it belongs to your organisation."),
    (("CreateSnapshot", "ModifySnapshotAttribute"),
     "Snapshot created and then shared",
     "The complete EBS exfiltration sequence. Confirm the shared snapshot is not one created here, "
     "and check the recipient account ID."),
    (("CreateFunction", "CreateFunctionUrlConfig"),
     "Lambda function created and exposed to the internet",
     "A function with a public URL runs with its execution role's permissions and needs no "
     "credentials to trigger. Review the code and the role, then check the URL's auth type."),
    (("PublishLayerVersion", "UpdateFunctionConfiguration"),
     "Lambda layer published and attached to a function",
     "Layer contents are invisible in the console. This is the standard way to hide a backdoor "
     "where a function code review will not find it. Download and inspect the layer."),
    (("DeleteAccessKey", "CreateAccessKey"),
     "Access key deleted and a new one created",
     "A user can hold only two keys. Deleting a stale one to make room for a new one is a known "
     "persistence pattern — and it looks like hygiene in isolation."),
    (("StopLogging", "PutEventSelectors"),
     "Audit logging altered in more than one way",
     "Multiple distinct changes to logging configuration is a strong signal. Reconstruct the "
     "affected window from Config history, flow logs, and billing data."),
]

LOGGING_EVENTS = {"StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail",
                  "StopConfigurationRecorder", "DeleteConfigurationRecorder",
                  "DeleteDetector", "UpdateDetector", "DeleteFlowLogs", "DeleteLogGroup"}


def _principal_key(row: dict) -> str:
    return str(row.get("principal_key") or row.get("principal_arn")
               or row.get("principal_id") or row.get("matched_on") or "").lower()


def _compatible_target(first: dict, second: dict) -> tuple[bool, str, str]:
    first_key = str(first.get("target_key") or "")
    second_key = str(second.get("target_key") or "")
    if first_key and second_key:
        return first_key == second_key, first_key, "strong"
    return True, first_key or second_key, "moderate"


def detect_sequences(rows, max_hours: int = 24) -> list[dict]:
    names = {r["event_name"] for r in rows}
    found = []
    for required, title, body in SEQUENCES:
        if not all(name in names for name in required):
            continue
        first_events = sorted(
            (row for row in rows if row["event_name"] == required[0]),
            key=lambda row: row["_ts"],
        )
        for first in first_events:
            chain = [first]
            confidence = "strong"
            target_key = str(first.get("target_key") or "")
            for event_name in required[1:]:
                candidates = [
                    row for row in rows
                    if row["event_name"] == event_name
                    and row.get("account_id") == first.get("account_id")
                    and _principal_key(row) == _principal_key(first)
                    and first["_ts"] <= row["_ts"] <= first["_ts"] + timedelta(hours=max_hours)
                ]
                compatible = []
                for candidate in candidates:
                    matches, candidate_target, candidate_confidence = _compatible_target(
                        first, candidate
                    )
                    if matches:
                        compatible.append(candidate)
                        target_key = target_key or candidate_target
                        if candidate_confidence != "strong":
                            confidence = candidate_confidence
                if not compatible:
                    chain = []
                    break
                chain.append(min(compatible, key=lambda row: row["_ts"]))
            if chain:
                found.append({
                    "title": title,
                    "body": body,
                    "events": list(required),
                    "confidence": confidence,
                    "principal": _principal_key(first),
                    "account_id": first.get("account_id", ""),
                    "target_key": target_key,
                    "first_seen": chain[0]["_ts"].isoformat(),
                    "last_seen": chain[-1]["_ts"].isoformat(),
                    "evidence_event_ids": [row.get("event_id", "") for row in chain],
                })
                break

    hit_logging = sorted(names & LOGGING_EVENTS)
    if hit_logging:
        found.append({
            "title": "Audit logging or monitoring was changed",
            "body": "Any period where logging was reduced is a blind spot this report cannot cover. "
                    "Note that CloudTrail Event History retains 90 days independently and cannot be "
                    "disabled, so use it to cross-check the gap, alongside AWS Config history, VPC "
                    "flow logs, and Cost Explorer for resources that appeared without a creation event.",
            "events": hit_logging})

    denied = [r for r in rows if str(r.get("error_code", "")).startswith(
        ("AccessDenied", "Unauthorized", "Forbidden", "InvalidClientTokenId"))]
    if len(denied) >= 5:
        top = ", ".join(n for n, _ in _top_names(denied, 4))
        found.append({
            "title": f"{len(denied)} denied attempts recorded",
            "body": f"Clusters of access-denied errors can indicate probing for permissions that "
                    f"still work, particularly after access was reduced. Most attempted: {top}.",
            "events": [n for n, _ in _top_names(denied, 6)]})
    return found


def _top_names(rows, n):
    from collections import Counter
    return Counter(r["event_name"] for r in rows).most_common(n)
