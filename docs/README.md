# 📚 Documentation

Docs follow the Diátaxis split: tutorial, how-to, reference, explanation.

| Doc | Type | For |
| --- | --- | --- |
| [setup.md](setup.md) | Walkthrough | Numbered install and first run, with screenshots |
| [faq.md](faq.md) | FAQ | Short answers: safety, data, permissions, limits |
| [troubleshooting.md](troubleshooting.md) | Troubleshooting | Symptoms and fixes |
| [how-it-works.md](how-it-works.md) | Explanation | The two-stage pipeline in one page |
| [tutorial-getting-started.md](tutorial-getting-started.md) | Tutorial | First run, synthetic then real |
| [howto-guide.md](howto-guide.md) | How-to | Specific tasks: SSO setup, baselines, Lake, AI analysis, archiving |
| [offboarding-playbook.md](offboarding-playbook.md) | Playbook | Access removal, evidence review, ownership, and closure criteria |
| [reference-cli.md](reference-cli.md) | Reference | Every flag, across all six scripts |
| [reference-data-contract.md](reference-data-contract.md) | Reference | The event JSON schema, collector → report |
| [explanation-architecture.md](explanation-architecture.md) | Explanation | Pipeline design, severity model, detector internals, extension points |

## 🖼️ Assets

| File | What it is |
| --- | --- |
| [assets/example-report.html](assets/example-report.html) | Fully synthetic example report (download and open locally) |
| [assets/architecture-light.svg](assets/architecture-light.svg) / [assets/architecture-dark.svg](assets/architecture-dark.svg) | Architecture diagram, drawn by `tools/gen_diagram.py` |
| [assets/pipeline-light.svg](assets/pipeline-light.svg) / [assets/pipeline-dark.svg](assets/pipeline-dark.svg) | Two-stage pipeline diagram, drawn by `tools/gen_diagram.py` |
| [assets/screenshots/](assets/screenshots/) | Report screenshots from the synthetic sample, taken by `make screenshots` |
| [assets/brand/icon.svg](assets/brand/icon.svg) | Project icon; `make brand` renders the PNG and the social preview |
| [assets/social-preview.png](assets/social-preview.png) | 1280x640 social preview, uploaded by hand in the repository settings |
