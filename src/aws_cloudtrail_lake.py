#!/usr/bin/env python3
"""Collect or import CloudTrail Lake events for the offboarding dashboard."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from datetime import datetime, timezone

import boto3

from aws_offboarding_audit import (
    DEFAULT_REQUEST_PARAMS_LIMIT,
    _serialise_request_params,
    _write_json,
    classify,
    match_event_user,
    write_outputs,
)


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_query(event_data_store: str, start: datetime, end: datetime,
                identifiers: list[str], include_reads: bool) -> str:
    if not re.fullmatch(r"[A-Za-z0-9:/_-]+", event_data_store):
        raise ValueError("Invalid CloudTrail Lake event data store ID or ARN.")
    identity_terms = []
    for identifier in identifiers:
        escaped = sql_literal(f"%{identifier}%")
        identity_terms.extend([
            f"userIdentity.arn LIKE {escaped}",
            f"userIdentity.principalId LIKE {escaped}",
            f"userIdentity.userName LIKE {escaped}",
        ])
    clauses = [
        f"eventTime >= {sql_literal(start.isoformat())}",
        f"eventTime <= {sql_literal(end.isoformat())}",
        "(" + " OR ".join(identity_terms) + ")",
    ]
    if not include_reads:
        clauses.append("readOnly = false")
    fields = (
        "eventTime, eventID, eventSource, eventName, awsRegion, recipientAccountId, "
        "userIdentity, sourceIPAddress, userAgent, errorCode, resources, "
        "requestParameters, eventCategory, readOnly"
    )
    return f"SELECT {fields} FROM {event_data_store} WHERE " + " AND ".join(clauses)


def lake_cells_to_dict(cells: list[dict]) -> dict:
    return {
        str(cell.get("Field", "")): cell.get("Value", "")
        for cell in cells
        if cell.get("Field")
    }


def _json_value(value, fallback):
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def normalize_lake_row(source: dict, identifiers: list[str], loose: bool,
                       request_params_limit: int,
                       account_names: dict[str, str] | None = None) -> dict | None:
    identity = _json_value(source.get("userIdentity"), {})
    request_parameters = _json_value(source.get("requestParameters"), {})
    resources = _json_value(source.get("resources"), [])
    record = {"userIdentity": identity, "requestParameters": request_parameters}
    match = match_event_user(record, str(identity.get("userName", "")), identifiers, loose)
    if not match:
        return None
    matched_on, match_mode = match
    params, truncated, original_length = _serialise_request_params(
        request_parameters, request_params_limit
    )
    resource_items = resources if isinstance(resources, list) else []
    resource_names = [
        str(item.get("resourceName") or item.get("ResourceName") or "")
        for item in resource_items if isinstance(item, dict)
    ]
    account_id = str(source.get("recipientAccountId", ""))
    timestamp = datetime.fromisoformat(
        str(source.get("eventTime", "")).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    event_name = str(source.get("eventName", ""))
    return {
        "event_id": str(source.get("eventID", "")),
        "time_utc": timestamp.isoformat(),
        "account_id": account_id,
        "account_name": (account_names or {}).get(account_id, account_id),
        "region": str(source.get("awsRegion", "")),
        "event_source": str(source.get("eventSource", "")),
        "event_name": event_name,
        "severity": classify(event_name),
        "matched_on": matched_on,
        "match_mode": match_mode,
        "principal_arn": str(identity.get("arn", "")),
        "principal_id": str(identity.get("principalId", "")),
        "source_ip": str(source.get("sourceIPAddress", "")),
        "user_agent": str(source.get("userAgent", ""))[:120],
        "error_code": str(source.get("errorCode", "")),
        "resources": "; ".join(name for name in resource_names if name)[:400],
        "resources_json": json.dumps(resource_items, separators=(",", ":")),
        "request_params": params,
        "request_params_truncated": truncated,
        "request_params_original_length": original_length,
        "event_scope": str(source.get("eventCategory") or "Management").lower(),
    }


def load_export(path: str) -> list[dict]:
    if path.lower().endswith(".csv"):
        with open(path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    if isinstance(value, list):
        return [lake_cells_to_dict(row) if isinstance(row, list) else row for row in value]
    if isinstance(value, dict) and isinstance(value.get("QueryResultRows"), list):
        return [lake_cells_to_dict(row) for row in value["QueryResultRows"]]
    raise ValueError("Lake export must be a row list or contain QueryResultRows.")


def execute_query(query: str, region: str) -> tuple[str, list[dict]]:
    client = boto3.client("cloudtrail", region_name=region)
    query_id = client.start_query(QueryStatement=query)["QueryId"]
    while True:
        response = client.get_query_results(QueryId=query_id)
        status = response.get("QueryStatus")
        if status == "FINISHED":
            break
        if status in {"FAILED", "CANCELLED", "TIMED_OUT"}:
            raise RuntimeError(f"CloudTrail Lake query {query_id} ended with status {status}.")
        time.sleep(2)

    rows = [lake_cells_to_dict(row) for row in response.get("QueryResultRows", [])]
    token = response.get("NextToken")
    while token:
        response = client.get_query_results(QueryId=query_id, NextToken=token)
        rows.extend(lake_cells_to_dict(row) for row in response.get("QueryResultRows", []))
        token = response.get("NextToken")
    return query_id, rows


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect or import CloudTrail Lake audit events.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--event-data-store", help="CloudTrail Lake event data store ID or ARN.")
    source.add_argument("--input", help="Existing CloudTrail Lake/Athena JSON or CSV export.")
    parser.add_argument("--user", required=True)
    parser.add_argument("--also", action="append", default=[])
    parser.add_argument("--start", required=True, help="ISO 8601 start timestamp.")
    parser.add_argument("--end", required=True, help="ISO 8601 end timestamp.")
    parser.add_argument("--region", default="eu-west-1")
    parser.add_argument("--include-reads", action="store_true")
    parser.add_argument("--loose", action="store_true")
    parser.add_argument("--scope", choices=("management", "management-and-data"),
                        default="management-and-data")
    parser.add_argument("--request-params-limit", type=int,
                        default=DEFAULT_REQUEST_PARAMS_LIMIT)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the Lake SQL without executing it.")
    parser.add_argument("--out", default="aws_offboarding_audit")
    args = parser.parse_args(argv)

    try:
        start, end = parse_timestamp(args.start), parse_timestamp(args.end)
    except ValueError:
        parser.error("--start and --end must be valid ISO 8601 timestamps")
    if start >= end:
        parser.error("--start must be earlier than --end")
    identifiers = [args.user] + args.also
    query = (build_query(args.event_data_store, start, end, identifiers, args.include_reads)
             if args.event_data_store else "")
    if args.dry_run:
        if not query:
            parser.error("--dry-run requires --event-data-store")
        print(query)
        return 0

    try:
        if args.input:
            query_id, source_rows = "import", load_export(args.input)
        else:
            query_id, source_rows = execute_query(query, args.region)
        rows = [
            normalized for source_row in source_rows
            if (normalized := normalize_lake_row(
                source_row, identifiers, args.loose, args.request_params_limit
            )) is not None
        ]
    except Exception as exc:
        print(f"CloudTrail Lake collection failed: {exc}", file=sys.stderr)
        return 1

    csv_path, json_path = write_outputs(rows, args.out)
    scopes = sorted({row["event_scope"] for row in rows})
    manifest = {
        "schema_version": 2,
        "run_id": f"cloudtrail-lake-{query_id}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "complete" if args.event_data_store else "imported",
        "subject": args.user,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "source": "cloudtrail_lake" if args.event_data_store else "cloudtrail_lake_export",
        "event_scope": args.scope,
        "observed_event_categories": scopes,
        "include_reads": bool(args.include_reads),
        "events_matched": len(rows),
        "requested_units": 1,
        "successful_units": 1,
        "failed_units": 0,
        "request_params_truncated": sum(
            1 for row in rows if row.get("request_params_truncated")
        ),
        "limitations": [
            "Coverage depends on the event data store selectors and retention configuration.",
            "Imported exports cannot independently prove query completeness.",
        ],
    }
    manifest_path = f"{args.out}.manifest.json"
    _write_json(manifest_path, manifest)
    print(f"{len(rows)} events written to {json_path}, {csv_path}, and {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())