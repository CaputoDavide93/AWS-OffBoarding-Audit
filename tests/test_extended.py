import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from botocore.exceptions import ClientError

from audit_analyst import validate_analysis
from audit_baseline import build_baseline
from audit_intel import detect_sequences, normalize_target
from aws_audit_report import (
    apply_baseline,
    apply_current_state,
    enrich,
    json_for_html,
    md_escape,
    render_html,
)
from aws_cloudtrail_lake import build_query, normalize_lake_row
from aws_current_state import reconcile_event
from aws_offboarding_dashboard import parse_args as parse_dashboard_args
from aws_offboarding_audit import (
    CheckpointStore,
    _serialise_request_params,
    build_manifest,
    build_run_contract,
    create_archive,
    parse_args,
    sweep_region,
)


def event(name: str, when: str, target: str, event_id: str = "event-1") -> dict:
    return {
        "event_id": event_id,
        "time_utc": when,
        "account_id": "111122223333",
        "account_name": "prod-platform",
        "region": "eu-west-1",
        "event_source": "iam.amazonaws.com",
        "event_name": name,
        "matched_on": "leaver@example.com",
        "principal_arn": (
            "arn:aws:sts::111122223333:assumed-role/Admin/leaver@example.com"
        ),
        "source_ip": "192.0.2.10",
        "error_code": "",
        "resources": "",
        "request_params": json.dumps({"userName": target}),
    }


class CollectorContractTests(unittest.TestCase):
    def test_request_parameters_record_truncation(self):
        serialized, truncated, original_length = _serialise_request_params(
            {"policy": "x" * 1000}, 100
        )
        self.assertEqual(len(serialized), 100)
        self.assertTrue(truncated)
        self.assertGreater(original_length, len(serialized))

    def test_access_denied_is_not_zero_event_success(self):
        class Paginator:
            def paginate(self, **kwargs):
                assert kwargs["MaxResults"] == 50
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "LookupEvents",
                )

        class Client:
            def get_paginator(self, name):
                assert name == "lookup_events"
                return Paginator()

        account = {"accountId": "111122223333", "accountName": "prod", "roleName": "Audit"}
        with patch("aws_offboarding_audit.boto3.client", return_value=Client()):
            result = sweep_region(
                account, {}, "eu-west-1",
                datetime(2026, 8, 1, tzinfo=timezone.utc),
                datetime(2026, 8, 2, tzinfo=timezone.utc),
                ["leaver@example.com"], False, False,
            )
        self.assertEqual(result["unit"]["status"], "denied")
        self.assertEqual(result["rows"], [])

    def test_manifest_marks_partial_coverage(self):
        args = SimpleNamespace(
            user="leaver@example.com", sso_session="work", start_url=None,
            accounts=[], regions=["eu-west-1"], all_regions=False,
            include_reads=False, loose=False, role_preference=["SecurityAudit"],
            request_params_limit=32768,
        )
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 2, tzinfo=timezone.utc)
        contract = build_run_contract(args, start, end, [args.user])
        units = [
            {"account_id": "1", "region": "eu-west-1", "status": "success"},
            {"account_id": "2", "region": "eu-west-1", "status": "denied"},
        ]
        manifest = build_manifest(args, start, end, [], [], units, contract)
        self.assertEqual(manifest["status"], "partial")
        self.assertEqual(manifest["failed_units"], 1)

    def test_checkpoint_rejects_different_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = str(Path(temp_dir, "checkpoint.json"))
            CheckpointStore(path, "first", False)
            with self.assertRaises(ValueError):
                CheckpointStore(path, "second", True)

    def test_yaml_configuration_sets_cli_defaults(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir, "config.yaml")
            config.write_text(
                "collector:\n  user: leaver@example.com\n  sso_session: work\n  days: 12\n",
                encoding="utf-8",
            )
            _, args = parse_args(["--config", str(config)])
        self.assertEqual(args.user, "leaver@example.com")
        self.assertEqual(args.days, 12)

    def test_unencrypted_archive_contains_named_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir, "summary.json")
            artifact.write_text("{}", encoding="utf-8")
            output = create_archive([str(artifact)], str(Path(temp_dir, "audit")))
            self.assertTrue(Path(output).exists())

    def test_encryption_request_does_not_leave_plaintext_when_age_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir, "summary.json")
            artifact.write_text("{}", encoding="utf-8")
            archive = Path(temp_dir, "audit.tar.gz")
            with patch("aws_offboarding_audit.shutil.which", return_value=None):
                with self.assertRaises(RuntimeError):
                    create_archive([str(artifact)], str(archive), "age1example")
            self.assertFalse(archive.exists())


class IntelligenceTests(unittest.TestCase):
    def test_target_normalization_and_sequence_correlation(self):
        first = event("CreateUser", "2026-08-01T10:00:00+00:00", "backdoor", "e1")
        second = event("CreateAccessKey", "2026-08-01T11:00:00+00:00", "backdoor", "e2")
        rows = enrich([first, second], {}, timezone.utc, None, None, 8, 19, set())
        matches = detect_sequences(rows, max_hours=24)
        self.assertEqual(matches[0]["confidence"], "strong")
        self.assertEqual(matches[0]["target_key"], "user:backdoor")

    def test_different_targets_do_not_correlate(self):
        first = event("CreateUser", "2026-08-01T10:00:00+00:00", "one", "e1")
        second = event("CreateAccessKey", "2026-08-01T11:00:00+00:00", "two", "e2")
        rows = enrich([first, second], {}, timezone.utc, None, None, 8, 19, set())
        self.assertFalse(any(item["title"].startswith("IAM user")
                             for item in detect_sequences(rows)))

    def test_database_target_is_not_a_snapshot(self):
        target = normalize_target({"request_params": '{"dBInstanceIdentifier":"prod-db"}'})
        self.assertEqual(target["target_type"], "database")


class DashboardTests(unittest.TestCase):
    def test_report_yaml_defaults_are_overridden_by_cli(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir, "config.yaml")
            config.write_text(
                "collector:\n  user: leaver@example.com\n"
                "report:\n  timezone: UTC\n  work_start: 7\n  work_end: 17\n"
                "  org_accounts:\n    - '111122223333'\n  sequence_hours: 12\n",
                encoding="utf-8",
            )
            args = parse_dashboard_args([
                "--config", str(config), "--timezone", "Europe/Rome"
            ])

        self.assertEqual(args.timezone, "Europe/Rome")
        self.assertEqual(args.work_start, 7)
        self.assertEqual(args.work_end, 17)
        self.assertEqual(args.org_accounts, ["111122223333"])
        self.assertEqual(args.sequence_hours, 12)

    def test_state_baseline_and_dashboard_payload(self):
        rows = enrich(
            [event("CreateUser", "2026-08-01T10:00:00+00:00", "backdoor")],
            {}, timezone.utc, None, None, 8, 19, set(),
        )
        apply_current_state(rows, {
            "targets": {"user:backdoor": {"status": "active", "detail": "exists"}}
        })
        baseline = apply_baseline(rows, {
            "label": "Peers", "sample_size": 10,
            "events": {"CreateUser": {"mean": 0, "stddev": 0}},
        })
        ctx = {
            "user": "leaver@example.com", "window": "1 Aug", "n_accounts": 1,
            "n_regions": 1, "n_events": 1, "notice": None, "last_day": None,
            "generated": "now", "report_id": "report-1", "input_sha256": "abc",
            "coverage": {"status": "complete", "event_scope": "management",
                         "requested_units": 1, "successful_units": 1, "failed_units": 0},
            "baseline": baseline, "tz": timezone.utc, "tzname": "UTC",
            "_notice_dt": None, "_last_day_dt": None,
        }
        rendered = render_html(rows, [], None, ctx)
        self.assertIn("id='filter-severity'", rendered)
        self.assertIn("Still active", rendered)
        self.assertIn("Above peer baseline", rendered)
        match = re.search(r"id='report-data'>(.*?)</script>", rendered)
        self.assertIsNotNone(match)
        payload = json.loads(match.group(1))
        self.assertEqual(payload["events"][0]["current_state"], "active")

    def test_html_and_markdown_serializers_neutralize_markup(self):
        self.assertNotIn("</script>", json_for_html({"x": "</script>"}))
        escaped = md_escape("# heading | <script>x</script>")
        self.assertIn("\\# heading \\|", escaped)
        self.assertNotIn("<script>", escaped)


class AnalystTests(unittest.TestCase):
    def test_analysis_schema_preserves_pattern_hypotheses(self):
        value = {
            "headline": "Review", "assessment": "Limited evidence", "confidence": "medium",
            "confidence_note": "Management events only", "priority_actions": [],
            "event_notes": [], "blind_spots": [], "questions_for_the_team": [],
            "pattern_notes": [{
                "pattern": "IAM user created and given long-lived keys",
                "routine_explanation": "A service migration was approved.",
                "concerning_explanation": "The keys create access outside SSO.",
                "deciding_evidence": "Confirm the owner, ticket, and current key state.",
            }],
        }

        result = validate_analysis(value)

        self.assertEqual(len(result["pattern_notes"]), 1)
        self.assertIn("outside SSO", result["pattern_notes"][0]["concerning_explanation"])

    def test_analysis_schema_rejects_invalid_urgency(self):
        value = {
            "headline": "Review", "assessment": "Limited evidence", "confidence": "medium",
            "confidence_note": "Management events only", "event_notes": [],
            "blind_spots": [], "questions_for_the_team": [],
            "priority_actions": [
                {"rank": 1, "urgency": "later", "action": "Check", "rationale": "Why"}
            ],
        }
        with self.assertRaises(ValueError):
            validate_analysis(value)


class SourceAndStateTests(unittest.TestCase):
    def test_lake_query_and_data_event_normalization(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 2, tzinfo=timezone.utc)
        query = build_query("12345678-1234-1234-1234-123456789012", start, end,
                            ["o'hara@example.com"], False)
        self.assertIn("o''hara@example.com", query)
        with self.assertRaises(ValueError):
            build_query("store WHERE 1=1", start, end, ["user"], False)
        row = {
            "eventTime": "2026-08-01T10:00:00Z", "eventID": "e1",
            "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
            "awsRegion": "eu-west-1", "recipientAccountId": "111122223333",
            "userIdentity": json.dumps({
                "arn": "arn:aws:sts::111122223333:assumed-role/Admin/leaver@example.com"
            }),
            "requestParameters": '{"bucketName":"prod"}', "resources": "[]",
            "eventCategory": "Data",
        }
        normalized = normalize_lake_row(row, ["leaver@example.com"], False, 32768)
        self.assertEqual(normalized["event_scope"], "data")

    def test_current_state_uses_read_only_service_result(self):
        class IAM:
            def list_access_keys(self, UserName):
                assert UserName == "svc-user"
                return {"AccessKeyMetadata": [{"Status": "Active"}]}

        result = reconcile_event(
            {"event_name": "CreateAccessKey", "target_type": "user",
             "target_id": "svc-user", "region": "eu-west-1"},
            {"credentials": {}, ("iam", "us-east-1"): IAM()},
        )
        self.assertEqual(result["status"], "active")

    def test_peer_baseline_builder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = []
            for index, count in enumerate((0, 1, 2)):
                path = Path(temp_dir, f"peer-{index}.json")
                path.write_text(json.dumps([{"event_name": "CreateRole"}] * count),
                                encoding="utf-8")
                paths.append(str(path))
            baseline = build_baseline(paths, "Platform peers")
        self.assertEqual(baseline["sample_size"], 3)
        self.assertEqual(baseline["events"]["CreateRole"]["mean"], 1)


if __name__ == "__main__":
    unittest.main()