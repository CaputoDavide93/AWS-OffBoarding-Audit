#!/usr/bin/env python3
"""Reconcile high-risk historical events with current AWS resource state."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from audit_intel import normalize_target
from aws_offboarding_audit import credentials_for, discover_accounts, load_sso_token


NOT_FOUND_CODES = {
    "NoSuchEntity", "ResourceNotFoundException", "ResourceNotFoundFault",
    "DBInstanceNotFound", "DBClusterNotFoundFault", "InvalidSnapshot.NotFound",
    "InvalidGroup.NotFound", "NoSuchBucket", "TrailNotFoundException",
}
DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def state_result(status: str, detail: str, service: str) -> dict:
    return {"status": status, "detail": detail[:1000], "source": f"aws:{service}"}


def reconcile_event(row: dict, clients: dict[tuple[str, str], object]) -> dict:
    target_type = row.get("target_type", "unknown")
    target_id = row.get("target_id", "")
    event_name = row.get("event_name", "")
    region = row.get("region") or "us-east-1"

    def client(service: str, regional: bool = True):
        key = (service, region if regional else "us-east-1")
        if key not in clients:
            clients[key] = boto3.client(service, region_name=key[1], **clients["credentials"])
        return clients[key]

    try:
        if target_type == "user":
            iam = client("iam", regional=False)
            if event_name in {"CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"}:
                keys = iam.list_access_keys(UserName=target_id).get("AccessKeyMetadata", [])
                active = [item for item in keys if item.get("Status") == "Active"]
                return state_result(
                    "active" if active else "removed",
                    f"{len(active)} active access key(s) currently exist for this IAM user.",
                    "iam",
                )
            iam.get_user(UserName=target_id)
            return state_result("present", "IAM user currently exists.", "iam")

        if target_type == "role":
            role = client("iam", regional=False).get_role(RoleName=target_id)["Role"]
            statements = role.get("AssumeRolePolicyDocument", {}).get("Statement", [])
            return state_result(
                "active", f"IAM role exists with {len(statements)} trust-policy statement(s).", "iam"
            )

        if target_type == "function":
            lambda_client = client("lambda")
            if "FunctionUrl" in event_name:
                config = lambda_client.get_function_url_config(FunctionName=target_id)
                auth_type = config.get("AuthType", "unknown")
                return state_result("active", f"Function URL exists with AuthType {auth_type}.", "lambda")
            lambda_client.get_function(FunctionName=target_id)
            return state_result("present", "Lambda function currently exists.", "lambda")

        if target_type == "snapshot":
            ec2 = client("ec2")
            ec2.describe_snapshots(SnapshotIds=[target_id])
            if event_name == "ModifySnapshotAttribute":
                permissions = ec2.describe_snapshot_attribute(
                    SnapshotId=target_id, Attribute="createVolumePermission"
                ).get("CreateVolumePermissions", [])
                exposed = bool(permissions)
                return state_result(
                    "active" if exposed else "removed",
                    f"Snapshot exists with {len(permissions)} create-volume permission(s).",
                    "ec2",
                )
            return state_result("present", "Snapshot currently exists.", "ec2")

        if target_type == "bucket":
            s3 = client("s3")
            s3.head_bucket(Bucket=target_id)
            if event_name.startswith("PutBucketLifecycle"):
                rules = s3.get_bucket_lifecycle_configuration(Bucket=target_id).get("Rules", [])
                return state_result(
                    "active" if rules else "removed",
                    f"Bucket currently has {len(rules)} lifecycle rule(s).", "s3"
                )
            if event_name == "PutBucketReplication":
                rules = s3.get_bucket_replication(Bucket=target_id).get(
                    "ReplicationConfiguration", {}
                ).get("Rules", [])
                return state_result(
                    "active" if rules else "removed",
                    f"Bucket currently has {len(rules)} replication rule(s).", "s3"
                )
            return state_result("present", "S3 bucket currently exists.", "s3")

        if target_type == "security-group":
            groups = client("ec2").describe_security_groups(GroupIds=[target_id]).get(
                "SecurityGroups", []
            )
            open_rules = sum(
                1 for group in groups for permission in group.get("IpPermissions", [])
                for ip_range in permission.get("IpRanges", [])
                if ip_range.get("CidrIp") == "0.0.0.0/0"
            )
            return state_result(
                "active" if open_rules else "removed",
                f"Security group exists with {open_rules} internet-open ingress rule(s).", "ec2"
            )

        if target_type == "key":
            metadata = client("kms").describe_key(KeyId=target_id)["KeyMetadata"]
            enabled = bool(metadata.get("Enabled"))
            return state_result(
                "active" if enabled else "removed",
                f"KMS key state is {metadata.get('KeyState', 'unknown')}.", "kms"
            )

        if target_type == "database":
            rds = client("rds")
            if "Cluster" in event_name:
                rds.describe_db_clusters(DBClusterIdentifier=target_id)
            else:
                rds.describe_db_instances(DBInstanceIdentifier=target_id)
            return state_result("present", "Database resource currently exists.", "rds")

        if target_type == "trail":
            status = client("cloudtrail").get_trail_status(Name=target_id)
            logging = bool(status.get("IsLogging"))
            return state_result(
                "active" if logging else "removed",
                f"CloudTrail currently reports IsLogging={logging}.", "cloudtrail"
            )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", type(exc).__name__)
        if code in NOT_FOUND_CODES or "NotFound" in code or code.startswith("NoSuch"):
            return state_result("removed", f"AWS reports the target is absent ({code}).", "api")
        if code in DENIED_CODES or "AccessDenied" in code or "Unauthorized" in code:
            return state_result("unknown", f"State check was denied ({code}).", "api")
        return state_result("unknown", f"State check failed ({code}).", "api")
    except BotoCoreError as exc:
        return state_result("unknown", f"State check failed ({type(exc).__name__}).", "api")

    return state_result("unknown", "No current-state check is implemented for this target type.", "none")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check whether flagged AWS targets still exist.")
    parser.add_argument("input", help="Collector JSON event list.")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--sso-session")
    selector.add_argument("--start-url")
    parser.add_argument("--role-preference", nargs="*",
                        default=["SecurityAudit", "ReadOnlyAccess", "ViewOnlyAccess"])
    parser.add_argument("--out", default="aws_offboarding_state.json")
    args = parser.parse_args(argv)

    try:
        with open(args.input, encoding="utf-8") as fh:
            rows = json.load(fh)
        if not isinstance(rows, list):
            raise ValueError("input must contain an event list")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    token, sso_region = load_sso_token(args.sso_session, args.start_url)
    accounts = {
        account["accountId"]: account
        for account in discover_accounts(token, sso_region, args.role_preference)
    }
    checked_at = datetime.now(timezone.utc).isoformat()
    output = {"schema_version": 1, "checked_at": checked_at,
              "source": "aws-read-only-reconciliation", "events": {}, "targets": {},
              "coverage": {"checked": 0, "unknown": 0, "skipped": 0}}

    by_account: dict[str, list[dict]] = {}
    for row in rows:
        row.update(normalize_target(row))
        by_account.setdefault(str(row.get("account_id", "")), []).append(row)

    for account_id, account_rows in by_account.items():
        account = accounts.get(account_id)
        if not account:
            output["coverage"]["skipped"] += len(account_rows)
            continue
        try:
            credentials = credentials_for(
                token, sso_region, account_id, account["roleName"]
            )
        except (ClientError, BotoCoreError):
            output["coverage"]["unknown"] += len(account_rows)
            continue
        clients: dict = {"credentials": credentials}
        for row in account_rows:
            result = reconcile_event(row, clients)
            result["checked_at"] = checked_at
            event_id = str(row.get("event_id", ""))
            if event_id:
                output["events"][event_id] = result
            if row.get("target_key"):
                output["targets"][row["target_key"]] = result
            output["coverage"]["checked"] += 1
            if result["status"] == "unknown":
                output["coverage"]["unknown"] += 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, sort_keys=True)
    print(f"Wrote {args.out} with {output['coverage']['checked']} state checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())