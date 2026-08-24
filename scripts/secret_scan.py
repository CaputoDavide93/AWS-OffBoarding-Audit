#!/usr/bin/env python3
"""Fail when repository files contain likely credentials or private keys."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".venv", "__pycache__"}
SENSITIVE_NAMES = {
    ".env", "credentials", "id_rsa", "id_ed25519",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS secret assignment": re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}"
    ),
}


def iter_files():
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [name for name in dirs if name not in IGNORED_PARTS]
        for name in files:
            path = Path(root, name)
            if path == Path(__file__):
                continue
            yield path


def main() -> int:
    findings = []
    for path in iter_files():
        relative = path.relative_to(ROOT)
        if path.name in SENSITIVE_NAMES or path.suffix.lower() in SENSITIVE_SUFFIXES:
            findings.append((str(relative), 0, "sensitive filename"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for label, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append((str(relative), line_number, label))

    if findings:
        print("Potential secrets detected; values are intentionally not displayed:", file=sys.stderr)
        for filename, line_number, label in findings:
            location = f"{filename}:{line_number}" if line_number else filename
            print(f"  {location} [{label}]", file=sys.stderr)
        return 1
    print("Secret scan passed: no high-confidence credentials or private keys found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())