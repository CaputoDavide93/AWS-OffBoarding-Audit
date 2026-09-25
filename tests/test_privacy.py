"""Privacy defaults for the analyst pass and integrity of the TrailDiscover download."""

import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import audit_analyst  # noqa: E402
import audit_intel  # noqa: E402
import aws_audit_report  # noqa: E402
from aws_offboarding_dashboard import load_report_config  # noqa: E402


class AnalystDefaults(unittest.TestCase):
    def capture(self, argv):
        seen = {}

        def fake_analyse(rows, sequences, ctx, **kwargs):
            seen.update(kwargs)
            return None

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "in.json"
            sample.write_text(json.dumps([{
                "time_utc": "2026-08-01T10:00:00Z", "account_id": "111122223333",
                "account_name": "prod", "region": "eu-west-1",
                "event_source": "iam.amazonaws.com", "event_name": "CreateUser",
                "matched_on": "leaver", "principal_arn": "", "source_ip": "203.0.113.9",
                "user_agent": "test", "error_code": "", "resources": "", "request_params": "{}",
            }]))
            with patch.object(audit_analyst, "analyse", fake_analyse), \
                    patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                aws_audit_report.main([str(sample), "--user", "leaver", "--no-enrich",
                                       "--analyze", "--out", str(Path(tmp) / "r")] + argv)
        return seen

    def test_redact_on_and_search_off_by_default(self):
        seen = self.capture([])
        self.assertTrue(seen["redact"])
        self.assertFalse(seen["use_search"])
        self.assertNotIn("api_key", seen)

    def test_opt_out_and_opt_in(self):
        seen = self.capture(["--no-redact", "--search"])
        self.assertFalse(seen["redact"])
        self.assertTrue(seen["use_search"])

    def test_api_key_flag_removed(self):
        with self.assertRaises(SystemExit), patch("sys.stderr", io.StringIO()):
            aws_audit_report.main(["x.json", "--api-key", "sk-ant-x"])

    def test_call_claude_redacts_ips_and_accounts_by_default(self):
        sent = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"content": [{"type": "text", "text": "{}"}]}'

        def fake_urlopen(req, timeout=None):
            sent["body"] = req.data.decode()
            return Resp()

        digest = {"ip": "203.0.113.9", "acct": "arn:aws:iam::123456789012:role/x"}
        with patch.object(audit_analyst.urllib.request, "urlopen", fake_urlopen):
            try:
                audit_analyst.call_claude(digest, "k")
            except Exception:
                pass
        self.assertNotIn("203.0.113.9", sent["body"])
        self.assertNotIn("123456789012", sent["body"])
        self.assertNotIn("web_search", sent["body"])

    def test_legacy_no_search_config_key(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("report:\n  no_search: false\n")
        self.assertEqual(load_report_config(fh.name), {"search": True})


class TrailDiscoverIntegrity(unittest.TestCase):
    def test_url_is_pinned_to_commit(self):
        self.assertIn(audit_intel.TRAILDISCOVER_COMMIT, audit_intel.TRAILDISCOVER_URL)
        self.assertNotIn("/main/", audit_intel.TRAILDISCOVER_URL)

    def test_tampered_download_is_rejected(self):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'[{"eventName": "CreateUser"}]'

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(audit_intel, "CACHE_PATH", str(Path(tmp) / "td.json")), \
                patch.object(audit_intel.urllib.request, "urlopen", lambda *a, **k: Resp()):
            self.assertEqual(audit_intel.load_traildiscover(refresh=True, quiet=True), {})
            self.assertFalse((Path(tmp) / "td.json").exists())

    def test_matching_hash_is_accepted(self):
        raw = b'[{"eventName": "CreateUser"}]'
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(audit_intel, "TRAILDISCOVER_SHA256", hashlib.sha256(raw).hexdigest()), \
                patch.object(audit_intel, "CACHE_PATH", str(Path(tmp) / "td.json")), \
                patch.object(audit_intel.urllib.request, "urlopen",
                             lambda *a, **k: type("R", (), {"__enter__": lambda s: s,
                                                             "__exit__": lambda s, *a: False,
                                                             "read": lambda s: raw})()):
            self.assertIn("CreateUser", audit_intel.load_traildiscover(refresh=True, quiet=True))


if __name__ == "__main__":
    unittest.main()
