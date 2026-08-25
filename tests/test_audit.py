import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from audit_intel import C, H, L, M, detect_content
from aws_audit_report import (
    assess_action,
    enrich,
    group_events,
    offboarding_readiness,
    parse_review_date,
    render_html,
    review_priority,
)
from aws_offboarding_audit import (
    _cache_key,
    event_matches_user,
    load_sso_token,
    match_event_user,
    regions_for,
)


ORG_ACCOUNTS = {"111122223333", "444455556666", "777788889999", "222233334444"}


def raw_event(name: str, when: str, params: str = "{}") -> dict:
    return {
        "time_utc": when,
        "account_id": "111122223333",
        "account_name": "prod-platform",
        "region": "eu-west-1",
        "event_source": "test.amazonaws.com",
        "event_name": name,
        "matched_on": "leaver@example.com",
        "principal_arn": "",
        "source_ip": "82.14.9.201",
        "user_agent": "test",
        "error_code": "",
        "resources": "",
        "request_params": params,
    }


class ContentDetectorTests(unittest.TestCase):
    def test_cross_account_reference_without_org_list_is_medium(self):
        row = raw_event(
            "UpdateAssumeRolePolicy",
            "2026-08-14T09:00:00+00:00",
            '{"Principal":{"AWS":"arn:aws:iam::908877665544:root"}}',
        )

        findings = detect_content(row, set())

        self.assertIn(
            (M, "References other AWS account(s): 908877665544"),
            {(finding["severity"], finding["title"]) for finding in findings},
        )

    def test_verified_external_account_reference_is_critical(self):
        row = raw_event(
            "UpdateAssumeRolePolicy",
            "2026-08-14T09:00:00+00:00",
            '{"Principal":{"AWS":"arn:aws:iam::908877665544:root"}}',
        )

        findings = detect_content(row, ORG_ACCOUNTS)

        self.assertIn(
            (C, "References AWS account(s) outside your organisation: 908877665544"),
            {(finding["severity"], finding["title"]) for finding in findings},
        )

    def test_lambda_auth_type_is_read_structurally(self):
        authenticated = raw_event(
            "CreateFunctionUrlConfig",
            "2026-08-14T09:00:00+00:00",
            '{"FunctionName":"none-helper","AuthType":"AWS_IAM"}',
        )
        unauthenticated = raw_event(
            "CreateFunctionUrlConfig",
            "2026-08-14T09:00:00+00:00",
            '{"FunctionName":"helper","AuthType":"NONE"}',
        )

        authenticated_titles = {f["title"] for f in detect_content(authenticated, ORG_ACCOUNTS)}
        unauthenticated_titles = {
            f["title"] for f in detect_content(unauthenticated, ORG_ACCOUNTS)
        }

        self.assertNotIn(
            "Lambda Function URL created with no authentication", authenticated_titles
        )
        self.assertIn("Lambda Function URL created", authenticated_titles)
        self.assertIn(
            "Lambda Function URL created with no authentication", unauthenticated_titles
        )

    def test_escaped_not_action_policy_is_detected(self):
        row = raw_event(
            "PutRolePolicy",
            "2026-08-14T09:00:00+00:00",
            '{"policyDocument":"{\\"Effect\\":\\"Allow\\",'
            '\\"NotAction\\":\\"s3:ListBucket\\"}"}',
        )

        titles = {finding["title"] for finding in detect_content(row, ORG_ACCOUNTS)}

        self.assertIn("Policy uses NotAction with Allow", titles)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tz = ZoneInfo("Europe/London")
        self.last_day = parse_review_date("2026-08-15", self.tz, end_of_day=True)

    def test_last_working_day_is_inclusive_in_display_timezone(self):
        same_day = raw_event("ListBuckets", "2026-08-15T22:30:00+00:00")
        next_day = raw_event("ListBuckets", "2026-08-15T23:00:00+00:00")

        rows = enrich(
            [same_day, next_day], {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS
        )
        by_time = {row["time_utc"]: row for row in rows}

        self.assertNotIn("After last working day", by_time[same_day["time_utc"]]["flags"])
        self.assertIn("After last working day", by_time[next_day["time_utc"]]["flags"])

    def test_parameter_evidence_sorts_before_base_severity(self):
        rows = [
            {"event_name": "CatalogueCritical", "base_severity": C, "content_findings": []},
            {
                "event_name": "ParameterEvidence",
                "base_severity": L,
                "content_findings": [{"severity": H, "title": "Evidence", "detail": ""}],
            },
        ]

        groups = group_events(rows)

        self.assertEqual([name for name, _ in groups], ["ParameterEvidence", "CatalogueCritical"])

    def test_plain_language_assessment_uses_available_evidence(self):
        routine = enrich(
            [raw_event("ListBuckets", "2026-08-14T09:00:00+00:00")],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        watch = enrich(
            [raw_event("CreateRole", "2026-08-14T09:00:00+00:00")],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        investigate = enrich(
            [raw_event(
                "UpdateAssumeRolePolicy",
                "2026-08-14T09:00:00+00:00",
                '{"Principal":{"AWS":"arn:aws:iam::908877665544:root"}}',
            )],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )

        self.assertEqual(assess_action(routine)["label"], "Likely routine")
        self.assertEqual(assess_action(watch)["label"], "Keep an eye on")
        self.assertEqual(assess_action(investigate)["label"], "Investigate now")

    def test_offboarding_readiness_separates_evidence_from_manual_controls(self):
        rows = enrich(
            [raw_event("ListBuckets", "2026-08-16T09:00:00+00:00")],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        ctx = {
            "last_day": "2026-08-15",
            "coverage": {"status": "partial"},
            "state_metadata": {"available": False},
        }

        checklist = {item["title"]: item for item in offboarding_readiness(rows, ctx)}

        self.assertEqual(checklist["Set the departure boundary"]["status"], "ready")
        self.assertEqual(checklist["Confirm audit coverage"]["status"], "attention")
        self.assertIn("1 event(s)", checklist["Review activity after departure"]["detail"])
        self.assertEqual(
            checklist["Disable identity access and revoke sessions"]["status"], "manual"
        )

    def test_review_priority_scores_evidence_not_the_person(self):
        routine = enrich(
            [raw_event("ListBuckets", "2026-08-14T09:00:00+00:00")],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        routine[0]["match_mode"] = "exact"
        routine_score = review_priority(
            routine, [], {"last_day": "2026-08-15", "coverage": {"status": "complete"}}
        )

        concerning = enrich(
            [raw_event(
                "UpdateAssumeRolePolicy",
                "2026-08-16T09:00:00+00:00",
                '{"Principal":{"AWS":"arn:aws:iam::908877665544:root"}}',
            )],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        concerning_score = review_priority(
            concerning,
            [{"confidence": "strong", "title": "External trust chain"}],
            {"last_day": "2026-08-15", "coverage": {"status": "complete"}},
        )

        self.assertEqual(routine_score["score"], 1)
        self.assertEqual(routine_score["label"], "Routine review")
        self.assertGreaterEqual(concerning_score["score"], 7)
        self.assertIn("same-principal", " ".join(concerning_score["reasons"]))

    def test_html_report_places_optional_guide_on_its_own_page(self):
        rows = enrich(
            [raw_event("ListBuckets", "2026-08-14T09:00:00+00:00")],
            {}, self.tz, None, self.last_day, 8, 19, ORG_ACCOUNTS,
        )
        ctx = {
            "user": "leaver@example.com", "window": "14 Aug 2026", "n_accounts": 1,
            "n_regions": 1, "n_events": 1, "notice": None, "last_day": "2026-08-15",
            "generated": "14 Aug 2026 10:00 BST", "tz": self.tz,
            "tzname": "Europe/London", "_notice_dt": None,
            "_last_day_dt": self.last_day,
        }

        report = render_html(rows, [], None, ctx)
        summary_start = report.index("data-report-page='summary'")
        actions_start = report.index("data-report-page='actions'")
        guide_start = report.index("data-report-page='guide'")
        guide_heading = report.index("Reading this report without a technical background")
        readiness_start = report.index("id='readiness'")
        coverage_start = report.index("id='coverage'")

        self.assertLess(summary_start, actions_start)
        self.assertLess(actions_start, guide_start)
        self.assertLess(readiness_start, actions_start)
        self.assertGreater(coverage_start, actions_start)
        self.assertLess(coverage_start, guide_start)
        self.assertGreater(guide_heading, guide_start)
        self.assertIn("href='#page-guide' data-page-link='guide'", report)
        self.assertIn("id='page-guide' data-report-page='guide' hidden", report)

    def test_post_departure_reads_render_without_other_timeline_ticks(self):
        rows = enrich(
            [raw_event("ListBuckets", "2026-08-16T09:00:00+00:00")],
            {},
            self.tz,
            None,
            self.last_day,
            8,
            19,
            ORG_ACCOUNTS,
        )
        ctx = {
            "user": "leaver@example.com",
            "window": "16 Aug 2026 - 16 Aug 2026",
            "n_accounts": 1,
            "n_regions": 1,
            "n_events": 1,
            "notice": None,
            "last_day": "2026-08-15",
            "generated": "16 Aug 2026 10:00 BST",
            "tz": self.tz,
            "tzname": "Europe/London",
            "_notice_dt": None,
            "_last_day_dt": self.last_day,
        }

        report = render_html(rows, [], None, ctx)

        self.assertIn("read-only calls after the last working day", report)


class CollectorTests(unittest.TestCase):
    def test_sso_session_selects_its_hashed_cache_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir, "cache")
            cache_dir.mkdir()
            config_path = Path(temp_dir, "config")
            config_path.write_text(
                "[sso-session work]\n"
                "sso_start_url = https://work.awsapps.com/start\n"
                "sso_region = eu-west-2\n",
                encoding="utf-8",
            )
            valid_until = "2099-01-01T00:00:00Z"
            Path(cache_dir, f"{_cache_key('work')}.json").write_text(
                json.dumps({"accessToken": "work-token", "expiresAt": valid_until}),
                encoding="utf-8",
            )
            Path(cache_dir, "unrelated.json").write_text(
                json.dumps({
                    "accessToken": "wrong-token",
                    "expiresAt": "2099-02-01T00:00:00Z",
                    "startUrl": "https://other.awsapps.com/start",
                }),
                encoding="utf-8",
            )

            token, region = load_sso_token(
                "work", None, cache_dir=str(cache_dir), config_path=str(config_path)
            )

        self.assertEqual(token, "work-token")
        self.assertEqual(region, "eu-west-2")

    def test_identity_matching_is_exact_unless_loose_is_requested(self):
        record = {
            "userIdentity": {
                "arn": "arn:aws:sts::111122223333:assumed-role/Admin/joann@example.com",
            },
            "requestParameters": {"description": "ticket for ann@example.com"},
        }

        self.assertIsNone(event_matches_user(record, "joann@example.com", ["ann@example.com"], False))
        self.assertEqual(
            match_event_user(record, "joann@example.com", ["ann@example.com"], True),
            ("ann@example.com", "loose"),
        )
        self.assertEqual(
            match_event_user(record, "joann@example.com", ["joann@example.com"], False),
            ("joann@example.com", "exact"),
        )

    def test_explicit_regions_are_not_widened(self):
        self.assertEqual(
            regions_for({}, False, ["eu-central-1", "eu-central-1"]),
            ["eu-central-1"],
        )

    def test_default_regions_remain_available(self):
        self.assertEqual(
            regions_for({}, False, None),
            ["us-east-1", "eu-west-1", "eu-west-2"],
        )


class CliIntegrationTests(unittest.TestCase):
    def test_fixture_report_and_degradation_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = subprocess.run(
                [sys.executable, str(SRC / "test_fixture.py")],
                cwd=temp_dir,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(fixture.returncode, 0, fixture.stderr)

            report = subprocess.run(
                [
                    sys.executable,
                    str(SRC / "aws_audit_report.py"),
                    "sample.json",
                    "--user",
                    "leaver@example.com",
                    "--notice-date",
                    "2026-07-24",
                    "--last-day",
                    "2026-08-15",
                    "--org-accounts",
                    *sorted(ORG_ACCOUNTS),
                    "--no-enrich",
                    "--out",
                    "test_report",
                ],
                cwd=temp_dir,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertIn("TrailDiscover enrichment disabled", report.stderr)

            markdown = Path(temp_dir, "test_report.md").read_text(encoding="utf-8")
            expected_findings = {
                "References AWS account(s) outside your organisation: 908877665544",
                "Snapshot or image shared with an external account",
                "Policy uses NotAction with Allow",
                "Opened SSH (22) to the entire internet",
                "Lifecycle rule expires objects after 1 day(s)",
                "Lambda layer attached or changed",
                "Lambda Function URL created with no authentication",
                "Database deleted with no final snapshot",
                "Attached the AdministratorAccess managed policy",
            }
            for title in expected_findings:
                self.assertIn(f"> **{title}**", markdown)

            env = os.environ.copy()
            env.pop("ANTHROPIC_API_KEY", None)
            analysis = subprocess.run(
                [
                    sys.executable,
                    str(SRC / "aws_audit_report.py"),
                    "sample.json",
                    "--user",
                    "leaver@example.com",
                    "--no-enrich",
                    "--analyze",
                    "--out",
                    "no_key_report",
                ],
                cwd=temp_dir,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(analysis.returncode, 0, analysis.stderr)
            self.assertIn("No API key", analysis.stderr)
            self.assertTrue(Path(temp_dir, "no_key_report.html").exists())
            self.assertTrue(Path(temp_dir, "no_key_report.md").exists())


if __name__ == "__main__":
    unittest.main()