# Contributing

Issues and pull requests are welcome.

## Reporting an environment we have not tested

The tool is tested on synthetic data only: Python 3.11 on Linux in CI and Python 3.14 on macOS locally. Runs against a real AWS organisation are not covered by the test suite. If you run it against yours, an issue saying what worked and what did not is useful, including when everything worked.

### What to attach

- Operating system and Python version (`python3 --version`)
- The exact command you ran, with account IDs, user names and addresses replaced by placeholders
- The last lines the script printed, with the same redaction
- Whether you used Event History or CloudTrail Lake, and the look-back window
- The permission set the collector used (for example `SecurityAudit`)
- The result of `make check` if you changed code

Never attach collector output, report files, credentials or unredacted logs to a public issue. They can contain account IDs, ARNs, usernames and source IP addresses. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## Changing code or docs

1. Fork the repository and branch from `main`.
2. Run `make venv` once, then `make check` before you push. It runs the secret scan, `ruff`, the unit tests and the diagram freshness check.
3. Keep every AWS call read-only. A new call needs a row in the list in the README and a test.
4. Use conventional commit messages (`fix:`, `feat:`, `docs:`).
5. Use synthetic data only: the AWS documentation account `123456789012`, `leaver@example.com`, and addresses from `192.0.2.0/24` or `203.0.113.0/24`.

Diagrams are drawn by `tools/gen_diagram.py`; run `make diagram` after editing one. Screenshots are retaken with `make screenshots`.
