#!/usr/bin/env python3
"""
aws_offboarding_audit.py

Sweep CloudTrail across every AWS account you can reach via IAM Identity Center
(Azure-federated SSO) and report everything a departing engineer did.

Uses your own SSO session: the SSO access token enumerates exactly the accounts
and permission sets you are entitled to, so no Organizations access or
management-account role chaining is required.

Quick start
-----------
    pip install boto3
    aws sso login --sso-session mycompany
    python3 aws_offboarding_audit.py \
        --sso-session mycompany \
        --user leaver@example.com \
        --days 30 \
        --all-regions

Notes
-----
* CloudTrail "event history" (lookup-events) covers **management events only**,
  for the **last 90 days**. Data events (S3 object reads, Lambda invokes) are
  NOT included — for those you need an org trail + Athena, or CloudTrail Lake.
* Defaults to write events only (ReadOnly=false). Pass --include-reads for the
  full picture (much slower, far noisier).
* lookup-events is throttled around 2 requests/sec per account per region, so
  the sweep is deliberately gentle. Adaptive retries are enabled.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import configparser
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    sys.exit("boto3 is required:  pip install boto3")


# --------------------------------------------------------------------------
# Events worth escalating in an offboarding review
# --------------------------------------------------------------------------
HIGH_SIGNAL_PREFIXES = (
    "CreateAccessKey", "UpdateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "CreateUser", "CreateRole", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "AttachGroupPolicy", "CreatePolicyVersion",
    "UpdateAssumeRolePolicy", "CreateServiceSpecificCredential",
    "DeactivateMFADevice", "DeleteVirtualMFADevice",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "PutBucketPublicAccessBlock",
    "PutKeyPolicy", "ScheduleKeyDeletion", "DisableKey",
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteFlowLogs", "DisassociateWebACL",
    "CreateAccessEntry", "AssociateAccessPolicy",
    "PutResourcePolicy", "CreateSAMLProvider", "UpdateSAMLProvider",
    "CreateOpenIDConnectProvider",
    "ModifyDBInstance", "RestoreDBInstanceFromDBSnapshot", "ShareSnapshot",
    "ModifySnapshotAttribute", "ModifyImageAttribute",
)
DESTRUCTIVE_HINTS = ("Delete", "Terminate", "Remove", "Revoke", "Detach", "Disable")
DEFAULT_REQUEST_PARAMS_LIMIT = 32768
COLLECTOR_SCHEMA_VERSION = 2
ACCESS_ERRORS = {
    "AccessDenied", "AccessDeniedException", "UnrecognizedClientException",
    "AuthFailure", "InvalidClientTokenId",
}

_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# SSO discovery
# --------------------------------------------------------------------------
def _cache_key(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _sso_session_settings(session_name: str | None,
                          config_path: str | None = None) -> tuple[str | None, str | None]:
    if not session_name:
        return None, None
    parser = configparser.RawConfigParser()
    parser.read(config_path or os.path.expanduser("~/.aws/config"))
    section = f"sso-session {session_name}"
    if not parser.has_section(section):
        return None, None
    return (parser.get(section, "sso_start_url", fallback=None),
            parser.get(section, "sso_region", fallback=None))


def load_sso_token(session_name: str | None, start_url: str | None,
                   cache_dir: str | None = None,
                   config_path: str | None = None) -> tuple[str, str]:
    """Pull the cached SSO access token written by `aws sso login`."""
    configured_url, configured_region = _sso_session_settings(session_name, config_path)
    requested_url = start_url or configured_url
    cache_dir = cache_dir or os.path.expanduser("~/.aws/sso/cache")
    session_key = _cache_key(session_name) if session_name else None
    url_key = _cache_key(requested_url) if requested_url else None
    candidates = []
    for path in glob.glob(os.path.join(cache_dir, "*.json")):
        try:
            with open(path) as fh:
                blob = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if "accessToken" not in blob:
            continue
        expires = blob.get("expiresAt", "")
        try:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            continue
        if exp_dt <= datetime.now(timezone.utc):
            continue
        stem = os.path.splitext(os.path.basename(path))[0]
        session_match = bool(session_name and (
            blob.get("sessionName") == session_name or stem == session_key
        ))
        url_match = bool(requested_url and (
            blob.get("startUrl") == requested_url or stem == url_key
        ))
        if session_name and not (session_match or url_match):
            continue
        if start_url and not url_match:
            continue
        specificity = 2 if session_match else 1 if url_match else 0
        candidates.append((specificity, exp_dt, path, blob))

    if not candidates:
        sys.exit(
            "No valid SSO token found. Run:\n"
            f"    aws sso login --sso-session {session_name or '<your-sso-session>'}"
        )
    if not session_name and not start_url and len(candidates) > 1:
        sys.exit("Multiple valid SSO tokens found. Pass --sso-session or --start-url explicitly.")
    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    blob = candidates[0][3]
    region = (blob.get("region") or configured_region
              or os.environ.get("AWS_REGION") or "eu-west-1")
    return blob["accessToken"], region


def discover_accounts(token: str, sso_region: str, role_pref: list[str]) -> list[dict]:
    """List every account/role pair the token can reach."""
    sso = boto3.client("sso", region_name=sso_region)
    accounts = []
    for page in sso.get_paginator("list_accounts").paginate(accessToken=token):
        accounts.extend(page["accountList"])

    resolved = []
    for acct in accounts:
        roles = []
        try:
            for page in sso.get_paginator("list_account_roles").paginate(
                accessToken=token, accountId=acct["accountId"]
            ):
                roles.extend(r["roleName"] for r in page["roleList"])
        except ClientError as exc:
            log(f"  ! {acct['accountId']} role list failed: {exc.response['Error']['Code']}")
            continue
        if not roles:
            continue
        chosen = next((p for p in role_pref if p in roles), None) or sorted(roles)[0]
        resolved.append(
            {
                "accountId": acct["accountId"],
                "accountName": acct.get("accountName", acct["accountId"]),
                "roleName": chosen,
            }
        )
    return resolved


def credentials_for(token: str, sso_region: str, account_id: str, role: str) -> dict:
    sso = boto3.client("sso", region_name=sso_region)
    creds = sso.get_role_credentials(
        roleName=role, accountId=account_id, accessToken=token
    )["roleCredentials"]
    return {
        "aws_access_key_id": creds["accessKeyId"],
        "aws_secret_access_key": creds["secretAccessKey"],
        "aws_session_token": creds["sessionToken"],
    }


# --------------------------------------------------------------------------
# Identity matching
# --------------------------------------------------------------------------
def match_event_user(record: dict, top_username: str, needles: list[str],
                     loose: bool) -> tuple[str, str] | None:
    """Return the matched identifier and confidence mode for a CloudTrail event."""
    ident = record.get("userIdentity", {}) or {}
    session_ctx = ident.get("sessionContext", {}) or {}
    values = [
        top_username or "",
        ident.get("arn", "") or "",
        ident.get("principalId", "") or "",
        ident.get("userName", "") or "",
        (session_ctx.get("sessionIssuer", {}) or {}).get("userName", "") or "",
        ident.get("onBehalfOf", {}).get("userId", "") if isinstance(ident.get("onBehalfOf"), dict) else "",
    ]

    candidates = set()
    for value in values:
        normalized = str(value).strip().lower()
        if not normalized:
            continue
        candidates.add(normalized)
        candidates.update(part for part in normalized.split("/") if part)
        candidates.update(part for part in normalized.split(":") if part)

    for needle in needles:
        if needle.strip().lower() in candidates:
            return needle, "exact"

    if loose:
        blob = json.dumps(record, separators=(",", ":")).lower()
        for needle in needles:
            if needle.strip() and needle.strip().lower() in blob:
                return needle, "loose"
    return None


def event_matches_user(record: dict, top_username: str, needles: list[str],
                       loose: bool) -> str | None:
    """Backward-compatible identity matcher returning only the matched identifier."""
    match = match_event_user(record, top_username, needles, loose)
    return match[0] if match else None


def classify(event_name: str) -> str:
    if any(event_name.startswith(p) for p in HIGH_SIGNAL_PREFIXES):
        return "HIGH"
    if any(h in event_name for h in DESTRUCTIVE_HINTS):
        return "DESTRUCTIVE"
    return "normal"


# --------------------------------------------------------------------------
# CloudTrail sweep
# --------------------------------------------------------------------------
BOTO_CFG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
)


def regions_for(creds: dict, all_regions: bool, explicit: list[str] | None) -> list[str]:
    if explicit:
        return sorted(set(explicit))
    if not all_regions:
        return ["us-east-1", "eu-west-1", "eu-west-2"]
    ec2 = boto3.client("ec2", region_name="us-east-1", config=BOTO_CFG, **creds)
    try:
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    except (ClientError, BotoCoreError):
        regions = ["us-east-1", "eu-west-1", "eu-west-2"]
    return sorted(set(regions) | {"us-east-1"})


def _unit_result(account: dict, region: str, status: str, rows: list[dict] | None = None,
                 **details) -> dict:
    matched_rows = rows or []
    unit = {
        "account_id": account["accountId"],
        "account_name": account["accountName"],
        "role_name": account.get("roleName", ""),
        "region": region,
        "status": status,
        "event_count": len(matched_rows),
        **details,
    }
    return {"rows": matched_rows, "unit": unit}


def _serialise_request_params(value, limit: int) -> tuple[str, bool, int]:
    text = json.dumps(value, separators=(",", ":"))
    original_length = len(text)
    return text[:limit], original_length > limit, original_length


def sweep_region(account: dict, creds: dict, region: str, start: datetime, end: datetime,
                 needles: list[str], include_reads: bool, loose: bool,
                 request_params_limit: int = DEFAULT_REQUEST_PARAMS_LIMIT) -> dict:
    client = boto3.client("cloudtrail", region_name=region, config=BOTO_CFG, **creds)
    kwargs: dict = {"StartTime": start, "EndTime": end, "MaxResults": 50}
    if not include_reads:
        kwargs["LookupAttributes"] = [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]

    hits: list[dict] = []
    pages_scanned = 0
    events_scanned = 0
    try:
        for page in client.get_paginator("lookup_events").paginate(**kwargs):
            pages_scanned += 1
            for evt in page.get("Events", []):
                events_scanned += 1
                try:
                    record = json.loads(evt.get("CloudTrailEvent", "{}"))
                except json.JSONDecodeError:
                    record = {}
                match = match_event_user(record, evt.get("Username", ""), needles, loose)
                if not match:
                    continue
                matched, match_mode = match
                name = evt.get("EventName", "")
                request_params, params_truncated, params_length = _serialise_request_params(
                    record.get("requestParameters"), request_params_limit
                )
                resources = [
                    {"type": r.get("ResourceType", ""), "name": r.get("ResourceName", "")}
                    for r in evt.get("Resources", [])
                    if r.get("ResourceName")
                ]
                hits.append(
                    {
                        "event_id": evt.get("EventId", ""),
                        "time_utc": evt["EventTime"].astimezone(timezone.utc).isoformat(),
                        "account_id": account["accountId"],
                        "account_name": account["accountName"],
                        "region": region,
                        "event_source": evt.get("EventSource", ""),
                        "event_name": name,
                        "severity": classify(name),
                        "matched_on": matched,
                        "match_mode": match_mode,
                        "principal_arn": (record.get("userIdentity", {}) or {}).get("arn", ""),
                        "principal_id": (record.get("userIdentity", {}) or {}).get("principalId", ""),
                        "source_ip": record.get("sourceIPAddress", ""),
                        "user_agent": (record.get("userAgent", "") or "")[:120],
                        "error_code": record.get("errorCode", ""),
                        "resources": "; ".join(r["name"] for r in resources)[:400],
                        "resources_json": json.dumps(resources, separators=(",", ":")),
                        "request_params": request_params,
                        "request_params_truncated": params_truncated,
                        "request_params_original_length": params_length,
                        "event_scope": str(record.get("eventCategory") or "Management").lower(),
                    }
                )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ACCESS_ERRORS:
            log(f"  ! {account['accountId']}/{region}: {code}")
        return _unit_result(
            account, region, "denied" if code in ACCESS_ERRORS else "failed",
            phase="lookup_events", error_code=code,
            error_message=str(exc.response.get("Error", {}).get("Message", ""))[:240],
            retryable=code.startswith(("Throttl", "RequestLimit")),
            pages_scanned=pages_scanned, events_scanned=events_scanned,
        )
    except BotoCoreError as exc:
        log(f"  ! {account['accountId']}/{region}: {type(exc).__name__}")
        return _unit_result(
            account, region, "failed", phase="lookup_events",
            error_code=type(exc).__name__, error_message=str(exc)[:240], retryable=True,
            pages_scanned=pages_scanned, events_scanned=events_scanned,
        )
    return _unit_result(
        account, region, "success", hits,
        phase="lookup_events", error_code="", error_message="", retryable=False,
        pages_scanned=pages_scanned, events_scanned=events_scanned,
    )


def sweep_account(token: str, sso_region: str, account: dict, start: datetime, end: datetime,
                  needles: list[str], args, checkpoint: CheckpointStore | None = None) -> dict:
    try:
        creds = credentials_for(token, sso_region, account["accountId"], account["roleName"])
    except (ClientError, BotoCoreError) as exc:
        code = (exc.response["Error"]["Code"] if isinstance(exc, ClientError)
                else type(exc).__name__)
        log(f"  ! {account['accountName']}: cannot assume {account['roleName']} "
            f"({code})")
        result = _unit_result(
            account, "*", "denied" if code in ACCESS_ERRORS else "failed",
            phase="credentials", error_code=code, error_message=str(exc)[:240],
            retryable=False, pages_scanned=0, events_scanned=0,
        )
        return {"rows": [], "units": [result["unit"]]}

    regions = regions_for(creds, args.all_regions, args.regions)
    found: list[dict] = []
    units: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=args.region_concurrency) as pool:
        futures = {}
        for region in regions:
            cached = checkpoint.completed(account["accountId"], region) if checkpoint else None
            if cached:
                found.extend(cached["rows"])
                units.append(cached["unit"])
                log(f"  resumed  {account['accountName']}/{region}")
                continue
            future = pool.submit(
                sweep_region, account, creds, region, start, end, needles,
                args.include_reads, args.loose, args.request_params_limit,
            )
            futures[future] = region
        for fut in cf.as_completed(futures):
            region = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = _unit_result(
                    account, region, "failed", phase="worker",
                    error_code=type(exc).__name__, error_message=str(exc)[:240],
                    retryable=False, pages_scanned=0, events_scanned=0,
                )
            found.extend(result["rows"])
            units.append(result["unit"])
            if checkpoint:
                checkpoint.record(result)

    flag = f"  {len(found):>5} events" if found else "      -       "
    log(f"{flag}  {account['accountName']} ({account['accountId']}) "
        f"via {account['roleName']}, {len(regions)} regions")
    return {"rows": found, "units": units}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
OUTPUT_FIELDS = [
    "event_id", "time_utc", "account_id", "account_name", "region",
    "event_source", "event_name", "severity", "matched_on", "match_mode",
    "principal_arn", "principal_id", "source_ip", "user_agent", "error_code",
    "resources", "resources_json", "request_params", "request_params_truncated",
    "request_params_original_length", "event_scope",
]


def _write_json(path: str, value) -> None:
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=2, sort_keys=True)
    os.replace(temp_path, path)


class CheckpointStore:
    def __init__(self, path: str, input_hash: str, resume: bool):
        self.path = path
        self.input_hash = input_hash
        self.lock = threading.Lock()
        self.data = {"schema_version": 1, "input_hash": input_hash, "units": {}}
        if resume and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                saved = json.load(fh)
            if saved.get("input_hash") != input_hash:
                raise ValueError("Checkpoint does not match this collection configuration.")
            self.data = saved
        else:
            _write_json(self.path, self.data)

    @staticmethod
    def key(account_id: str, region: str) -> str:
        return f"{account_id}/{region}"

    def completed(self, account_id: str, region: str) -> dict | None:
        with self.lock:
            result = self.data["units"].get(self.key(account_id, region))
            if result and result.get("unit", {}).get("status") == "success":
                return result
        return None

    def record(self, result: dict) -> None:
        unit = result["unit"]
        with self.lock:
            self.data["units"][self.key(unit["account_id"], unit["region"])] = result
            _write_json(self.path, self.data)


def build_preflight(args, accounts: list[dict], start: datetime, end: datetime,
                    run_contract: dict) -> dict:
    requested_regions = ("all enabled regions" if args.all_regions
                         else sorted(set(args.regions or [
                             "us-east-1", "eu-west-1", "eu-west-2"
                         ])))
    warnings = [
        "CloudTrail Event History covers management events only.",
        "The preflight does not call CloudTrail; permissions are proven only during collection.",
    ]
    if args.loose:
        warnings.append("Loose identity matching may include events that mention the subject.")
    return {
        "schema_version": 1,
        "run_id": f"aws-offboarding-{contract_hash(run_contract)[:16]}",
        "input_hash": contract_hash(run_contract),
        "status": "ready",
        "subject": args.user,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "accounts": accounts,
        "account_count": len(accounts),
        "regions": requested_regions,
        "estimated_units": (None if args.all_regions
                            else len(accounts) * len(requested_regions)),
        "include_reads": bool(args.include_reads),
        "identity_match_mode": "exact_and_loose" if args.loose else "exact",
        "warnings": warnings,
    }


def create_archive(paths: list[str], archive_path: str, recipient: str | None = None) -> str:
    tar_path = archive_path[:-4] if recipient and archive_path.endswith(".age") else archive_path
    if not tar_path.endswith(".tar.gz"):
        tar_path += ".tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        for artifact in paths:
            archive.add(artifact, arcname=os.path.basename(artifact))
    if not recipient:
        log("  ! Archive contains sensitive audit data and is not encrypted.")
        return tar_path

    age = shutil.which("age")
    if not age:
        os.remove(tar_path)
        raise RuntimeError("Encrypted archive requested, but the 'age' command is not installed.")
    encrypted_path = archive_path if archive_path.endswith(".age") else f"{tar_path}.age"
    try:
        subprocess.run(
            [age, "--recipient", recipient, "--output", encrypted_path, tar_path],
            check=True,
        )
    except Exception:
        if os.path.exists(tar_path):
            os.remove(tar_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        raise
    else:
        os.remove(tar_path)
    return encrypted_path


def build_run_contract(args, start: datetime, end: datetime, needles: list[str]) -> dict:
    return {
        "subject_identifiers": needles,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "sso_session": args.sso_session or "",
        "start_url": args.start_url or "",
        "accounts": sorted(args.accounts or []),
        "regions": sorted(args.regions or []),
        "all_regions": bool(args.all_regions),
        "include_reads": bool(args.include_reads),
        "loose_matching": bool(args.loose),
        "role_preference": list(args.role_preference),
        "request_params_limit": args.request_params_limit,
        "event_scope": "management",
    }


def contract_hash(contract: dict) -> str:
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_manifest(args, start: datetime, end: datetime, accounts: list[dict],
                   rows: list[dict], units: list[dict], run_contract: dict) -> dict:
    input_hash = contract_hash(run_contract)
    successful = sum(1 for unit in units if unit["status"] == "success")
    failed = len(units) - successful
    return {
        "schema_version": COLLECTOR_SCHEMA_VERSION,
        "run_id": f"aws-offboarding-{input_hash[:16]}",
        "input_hash": input_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "partial" if failed else "complete",
        "subject": args.user,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "source": "cloudtrail_lookup_events",
        "event_scope": "management",
        "include_reads": bool(args.include_reads),
        "identity_match_mode": "exact_and_loose" if args.loose else "exact",
        "request_params_limit": args.request_params_limit,
        "request_params_truncated": sum(
            1 for row in rows if row.get("request_params_truncated")
        ),
        "accounts_discovered": len(accounts),
        "requested_units": len(units),
        "successful_units": successful,
        "failed_units": failed,
        "events_matched": len(rows),
        "contract": run_contract,
        "units": sorted(
            units, key=lambda unit: (unit.get("account_id", ""), unit.get("region", ""))
        ),
        "limitations": [
            "CloudTrail Event History contains management events only.",
            "Data events such as S3 object access and Lambda invocation are not included.",
            "Event History is limited to the most recent 90 days.",
        ],
    }


def build_machine_summary(rows: list[dict], manifest: dict) -> dict:
    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "input_hash": manifest["input_hash"],
        "status": manifest["status"],
        "event_count": len(rows),
        "failed_event_count": sum(1 for row in rows if row.get("error_code")),
        "accounts_with_events": len({row.get("account_id") for row in rows}),
        "coverage": {
            "requested_units": manifest["requested_units"],
            "successful_units": manifest["successful_units"],
            "failed_units": manifest["failed_units"],
        },
        "by_account": dict(Counter(row.get("account_id", "") for row in rows)),
        "by_region": dict(Counter(row.get("region", "") for row in rows)),
        "by_event_name": dict(Counter(row.get("event_name", "") for row in rows)),
        "by_error_code": dict(Counter(
            row.get("error_code", "") for row in rows if row.get("error_code")
        )),
    }


def write_outputs(rows: list[dict], out_prefix: str) -> tuple[str, str]:
    rows.sort(key=lambda r: r["time_utc"])
    csv_path = f"{out_prefix}.csv"
    json_path = f"{out_prefix}.json"
    extra_fields = sorted({key for row in rows for key in row} - set(OUTPUT_FIELDS))
    fields = OUTPUT_FIELDS + extra_fields
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    _write_json(json_path, rows)
    return csv_path, json_path


def summarise(rows: list[dict], user: str, start: datetime, end: datetime) -> str:
    if not rows:
        return f"No matching activity for '{user}' between {start:%Y-%m-%d} and {end:%Y-%m-%d}."

    by_account = Counter(f"{r['account_name']} ({r['account_id']})" for r in rows)
    by_service = Counter(r["event_source"].replace(".amazonaws.com", "") for r in rows)
    by_action = Counter(r["event_name"] for r in rows)
    by_day = Counter(r["time_utc"][:10] for r in rows)
    by_ip = Counter(r["source_ip"] for r in rows if r["source_ip"])
    failures = [r for r in rows if r["error_code"]]
    high = [r for r in rows if r["severity"] in ("HIGH", "DESTRUCTIVE")]

    out = [
        "=" * 72,
        f"AWS OFFBOARDING AUDIT — {user}",
        f"Window: {start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC",
        f"Total matched events: {len(rows)} across {len(by_account)} account(s)",
        "=" * 72,
        "",
        "BY ACCOUNT",
    ]
    out += [f"  {n:>6}  {k}" for k, n in by_account.most_common()]

    out += ["", "BY SERVICE (top 20)"]
    out += [f"  {n:>6}  {k}" for k, n in by_service.most_common(20)]

    out += ["", "BY ACTION (top 25)"]
    out += [f"  {n:>6}  {k}" for k, n in by_action.most_common(25)]

    out += ["", "ACTIVITY BY DAY"]
    for day in sorted(by_day):
        bar = "#" * min(50, by_day[day])
        out.append(f"  {day}  {by_day[day]:>5}  {bar}")

    if by_ip:
        out += ["", "SOURCE IPs (top 10)"]
        out += [f"  {n:>6}  {k}" for k, n in by_ip.most_common(10)]

    out += ["", f"NEEDS REVIEW — privilege / destructive / logging changes ({len(high)})"]
    if high:
        for r in high[:60]:
            out.append(
                f"  [{r['severity']:<11}] {r['time_utc'][:19]}  {r['account_name']:<22.22} "
                f"{r['region']:<14} {r['event_name']}"
            )
        if len(high) > 60:
            out.append(f"  ... and {len(high) - 60} more (see CSV)")
    else:
        out.append("  none detected")

    if failures:
        out += ["", f"DENIED / FAILED ATTEMPTS ({len(failures)}) — possible probing after access changes"]
        for r in failures[:20]:
            out.append(
                f"  {r['time_utc'][:19]}  {r['account_name']:<22.22} "
                f"{r['event_name']} -> {r['error_code']}"
            )
        if len(failures) > 20:
            out.append(f"  ... and {len(failures) - 20} more")

    out += ["", "=" * 72]
    return "\n".join(out)


# --------------------------------------------------------------------------
def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required when --config is used.") from exc
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a YAML mapping.")
    collector = data.get("collector", data)
    if not isinstance(collector, dict):
        raise ValueError("The collector configuration must be a mapping.")
    return {str(key).replace("-", "_"): value for key, value in collector.items()}


def build_parser(defaults: dict | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a departing engineer's AWS activity across all SSO-reachable accounts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="YAML file containing collector defaults.")
    parser.add_argument("--user",
                        help="Identifier to match: SSO username, email, or IAM user name.")
    parser.add_argument("--also", action="append", default=[],
                        help="Extra identifiers to match (repeatable), such as an old username.")
    parser.add_argument("--sso-session", help="sso-session name from ~/.aws/config")
    parser.add_argument("--start-url", help="SSO start URL (alternative to --sso-session)")
    parser.add_argument("--days", type=int, default=30,
                        help="Look-back window in days (max 90). Default 30.")
    parser.add_argument("--start", help="Explicit UTC start timestamp (requires --end).")
    parser.add_argument("--end", help="Explicit UTC end timestamp (requires --start).")
    parser.add_argument("--regions", nargs="*",
                        help="Explicit regions. Default: us-east-1, eu-west-1, eu-west-2.")
    parser.add_argument("--all-regions", action="store_true",
                        help="Sweep every enabled region (slower).")
    parser.add_argument("--include-reads", action="store_true",
                        help="Include read-only events. Much slower and noisier.")
    parser.add_argument("--loose", action="store_true",
                        help="Also match the identifier anywhere in the event body. More false positives.")
    parser.add_argument("--role-preference", nargs="*",
                        default=["ReadOnlyAccess", "SecurityAudit", "ViewOnlyAccess",
                                 "AWSReadOnlyAccess", "AdministratorAccess"],
                        help="Preferred permission sets, in order.")
    parser.add_argument("--accounts", nargs="*", help="Restrict to these account IDs.")
    parser.add_argument("--account-concurrency", type=int, default=4)
    parser.add_argument("--region-concurrency", type=int, default=3)
    parser.add_argument("--request-params-limit", type=int,
                        default=DEFAULT_REQUEST_PARAMS_LIMIT,
                        help="Maximum stored requestParameters characters. Default 32768.")
    parser.add_argument("--preflight", action="store_true",
                        help="Write the collection plan without querying CloudTrail.")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse successful units from a matching checkpoint.")
    parser.add_argument("--checkpoint", help="Checkpoint path. Default: <out>.checkpoint.json")
    parser.add_argument("--archive", nargs="?", const="auto",
                        help="Package outputs as .tar.gz; optionally provide the path.")
    parser.add_argument("--encrypt-recipient",
                        help="Encrypt --archive for this age recipient.")
    parser.add_argument("--out", default="aws_offboarding_audit", help="Output file prefix.")
    if defaults:
        known = {action.dest for action in parser._actions}
        unknown = sorted(set(defaults) - known)
        if unknown:
            raise ValueError(f"Unknown collector configuration key(s): {', '.join(unknown)}")
        parser.set_defaults(**defaults)
    return parser


def parse_args(argv: list[str] | None = None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config")
    known, _ = pre_parser.parse_known_args(argv)
    parser = build_parser(_load_config(known.config))
    return parser, parser.parse_args(argv)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.user:
        parser.error("--user is required (or set collector.user in --config)")
    if bool(args.sso_session) == bool(args.start_url):
        parser.error("provide exactly one of --sso-session or --start-url")
    if args.days <= 0:
        parser.error("--days must be greater than zero")
    if args.account_concurrency <= 0 or args.region_concurrency <= 0:
        parser.error("concurrency values must be greater than zero")
    if args.request_params_limit < 800:
        parser.error("--request-params-limit must be at least 800")
    if args.all_regions and args.regions:
        parser.error("--all-regions cannot be combined with --regions")
    if args.regions is not None and not args.regions:
        parser.error("--regions requires at least one region")
    if bool(args.start) != bool(args.end):
        parser.error("--start and --end must be supplied together")
    if args.accounts and any(not re.fullmatch(r"\d{12}", account) for account in args.accounts):
        parser.error("every --accounts value must be a 12-digit AWS account ID")
    if args.encrypt_recipient and not args.archive:
        parser.error("--encrypt-recipient requires --archive")


def main(argv: list[str] | None = None) -> int:
    try:
        parser, args = parse_args(argv)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    validate_args(parser, args)

    if args.days > 90:
        log("! CloudTrail event history only retains 90 days; clamping.")
        args.days = 90

    try:
        if args.start and args.end:
            start, end = _parse_timestamp(args.start), _parse_timestamp(args.end)
            if start >= end:
                parser.error("--start must be earlier than --end")
            if end - start > timedelta(days=90):
                parser.error("the explicit collection window cannot exceed 90 days")
        else:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=args.days)
    except ValueError:
        parser.error("--start and --end must be valid ISO 8601 timestamps")
    needles = [args.user] + args.also

    log("Loading SSO token...")
    token, sso_region = load_sso_token(args.sso_session, args.start_url)

    log("Discovering accounts...")
    discovered_accounts = discover_accounts(token, sso_region, args.role_preference)
    accounts = discovered_accounts
    if args.accounts:
        wanted = set(args.accounts)
        accounts = [account for account in accounts if account["accountId"] in wanted]
    if not accounts:
        sys.exit("No reachable accounts found.")

    run_contract = build_run_contract(args, start, end, needles)
    input_hash = contract_hash(run_contract)
    if args.preflight:
        preflight = build_preflight(args, accounts, start, end, run_contract)
        preflight["accounts_discovered"] = len(discovered_accounts)
        preflight_path = f"{args.out}.preflight.json"
        _write_json(preflight_path, preflight)
        print(json.dumps(preflight, indent=2))
        log(f"Wrote {preflight_path}")
        return 0

    checkpoint_path = args.checkpoint or f"{args.out}.checkpoint.json"
    try:
        checkpoint = CheckpointStore(checkpoint_path, input_hash, args.resume)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    log(f"Sweeping {len(accounts)} account(s) for {needles} over "
        f"{(end - start).total_seconds() / 86400:.1f} days "
        f"({'all events' if args.include_reads else 'write events only'})...\n")

    rows: list[dict] = []
    units: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=args.account_concurrency) as pool:
        futures = {
            pool.submit(
                sweep_account, token, sso_region, account, start, end, needles, args, checkpoint
            ): account
            for account in accounts
        }
        for future in cf.as_completed(futures):
            account = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "rows": [],
                    "units": [_unit_result(
                        account, "*", "failed", phase="account_worker",
                        error_code=type(exc).__name__, error_message=str(exc)[:240],
                        retryable=False, pages_scanned=0, events_scanned=0,
                    )["unit"]],
                }
            rows.extend(result["rows"])
            units.extend(result["units"])

    report = summarise(rows, args.user, start, end)
    manifest = build_manifest(args, start, end, discovered_accounts, rows, units, run_contract)
    manifest["accounts_selected"] = len(accounts)
    manifest["checkpoint"] = checkpoint_path
    summary = build_machine_summary(rows, manifest)
    csv_path, json_path = write_outputs(rows, args.out)
    txt_path = f"{args.out}.txt"
    manifest_path = f"{args.out}.manifest.json"
    summary_path = f"{args.out}.summary.json"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    _write_json(manifest_path, manifest)
    _write_json(summary_path, summary)

    artifacts = [csv_path, json_path, txt_path, manifest_path, summary_path, checkpoint_path]
    if args.archive:
        requested_path = f"{args.out}.tar.gz" if args.archive == "auto" else args.archive
        try:
            archive_path = create_archive(artifacts, requested_path, args.encrypt_recipient)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            parser.error(str(exc))
        artifacts.append(archive_path)

    print("\n" + report)
    log("\nWrote " + ", ".join(artifacts))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
