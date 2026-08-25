#!/usr/bin/env python3
"""Run the AWS offboarding collector and build the defensive review dashboard."""

from __future__ import annotations

import argparse
import os
import webbrowser

from aws_audit_report import main as report_main
from aws_offboarding_audit import main as collector_main


REPORT_CONFIG_KEYS = {
    "notice_date", "last_day", "org_accounts", "timezone", "work_start", "work_end",
    "state", "baseline", "sequence_hours", "no_enrich", "analyze", "no_search",
    "redact", "model", "out", "open_report",
}


def load_report_config(path: str | None) -> dict:
    if not path:
        return {}
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required when --config is used.") from exc
    with open(path, encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a YAML mapping.")
    report = data.get("report", {})
    if not isinstance(report, dict):
        raise ValueError("The report configuration must be a mapping.")
    defaults = {str(key).replace("-", "_"): value for key, value in report.items()}
    unknown = sorted(set(defaults) - REPORT_CONFIG_KEYS)
    if unknown:
        raise ValueError(f"Unknown report configuration key(s): {', '.join(unknown)}")
    return defaults


def add_value(arguments: list[str], flag: str, value) -> None:
    if value is not None:
        arguments.extend([flag, str(value)])


def add_values(arguments: list[str], flag: str, values) -> None:
    if values:
        arguments.append(flag)
        arguments.extend(str(value) for value in values)


def build_parser(defaults: dict | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect AWS activity and build one portable offboarding dashboard."
    )
    parser.add_argument("--input", help="Existing collector/Lake JSON; skips collection.")
    parser.add_argument("--config", help="Collector and report YAML defaults.")
    parser.add_argument("--user", help="Departing engineer identifier.")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--sso-session")
    selector.add_argument("--start-url")
    parser.add_argument("--also", action="append", default=[])
    parser.add_argument("--days", type=int)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--regions", nargs="*")
    parser.add_argument("--all-regions", action="store_true")
    parser.add_argument("--include-reads", action="store_true")
    parser.add_argument("--loose", action="store_true")
    parser.add_argument("--accounts", nargs="*")
    parser.add_argument("--request-params-limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--raw-out", default="aws_offboarding_audit")

    parser.add_argument("--notice-date")
    parser.add_argument("--last-day")
    parser.add_argument("--org-accounts", nargs="*", default=[])
    parser.add_argument("--timezone", default="Europe/London")
    parser.add_argument("--work-start", type=int, default=8)
    parser.add_argument("--work-end", type=int, default=19)
    parser.add_argument("--state")
    parser.add_argument("--baseline")
    parser.add_argument("--sequence-hours", type=int, default=24)
    parser.add_argument("--no-enrich", action="store_true")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--no-search", action="store_true")
    parser.add_argument("--redact", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--out", default="aws_offboarding_report")
    parser.add_argument("--open", action="store_true", dest="open_report")
    if defaults:
        parser.set_defaults(**defaults)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config")
    known, _ = pre_parser.parse_known_args(argv)
    try:
        defaults = load_report_config(known.config)
    except (OSError, RuntimeError, ValueError) as exc:
        pre_parser.error(str(exc))
    return build_parser(defaults).parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    input_path = args.input
    if not input_path:
        collector_args = []
        add_value(collector_args, "--config", args.config)
        add_value(collector_args, "--user", args.user)
        add_value(collector_args, "--sso-session", args.sso_session)
        add_value(collector_args, "--start-url", args.start_url)
        for identifier in args.also:
            add_value(collector_args, "--also", identifier)
        add_value(collector_args, "--days", args.days)
        add_value(collector_args, "--start", args.start)
        add_value(collector_args, "--end", args.end)
        add_values(collector_args, "--regions", args.regions)
        add_values(collector_args, "--accounts", args.accounts)
        add_value(collector_args, "--request-params-limit", args.request_params_limit)
        if args.all_regions:
            collector_args.append("--all-regions")
        if args.include_reads:
            collector_args.append("--include-reads")
        if args.loose:
            collector_args.append("--loose")
        if args.resume:
            collector_args.append("--resume")
        if args.preflight:
            collector_args.append("--preflight")
        collector_args.extend(["--out", args.raw_out])
        result = collector_main(collector_args)
        if result or args.preflight:
            return result
        input_path = f"{args.raw_out}.json"

    report_args = [input_path]
    add_value(report_args, "--user", args.user)
    add_value(report_args, "--notice-date", args.notice_date)
    add_value(report_args, "--last-day", args.last_day)
    add_values(report_args, "--org-accounts", args.org_accounts)
    add_value(report_args, "--timezone", args.timezone)
    add_value(report_args, "--work-start", args.work_start)
    add_value(report_args, "--work-end", args.work_end)
    add_value(report_args, "--state", args.state)
    add_value(report_args, "--baseline", args.baseline)
    add_value(report_args, "--sequence-hours", args.sequence_hours)
    add_value(report_args, "--model", args.model)
    if args.no_enrich:
        report_args.append("--no-enrich")
    if args.analyze:
        report_args.append("--analyze")
    if args.no_search:
        report_args.append("--no-search")
    if args.redact:
        report_args.append("--redact")
    report_args.extend(["--out", args.out])
    result = report_main(report_args)
    if result:
        return result
    if args.open_report:
        webbrowser.open(f"file://{os.path.abspath(args.out + '.html')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())