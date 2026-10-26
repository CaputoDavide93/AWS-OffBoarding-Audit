# One entry point for the checks CI runs. `make check` before every push.
PYTHON := .venv/bin/python

.PHONY: venv lint test scan diagram check screenshots social-preview

venv: ## Virtual environment with the runtime dependencies and ruff
	python3 -m venv .venv
	$(PYTHON) -m pip install -q -r requirements.txt ruff

lint: ## ruff
	$(PYTHON) -m ruff check .

test: ## The unittest suite (no AWS access needed)
	$(PYTHON) -m unittest discover -s tests

scan: ## Repository secret scan
	$(PYTHON) tools/secret_scan.py

diagram: ## Redraw docs/assets/*.svg
	python3 tools/gen_diagram.py

check: scan lint test ## Everything CI checks
	python3 tools/gen_diagram.py --check
	sh tools/brand/check-icon.sh

screenshots: ## Retake docs/assets/screenshots/ from the synthetic sample (not CI)
	test -x .venv-screenshots/bin/python || ( \
		python3 -m venv .venv-screenshots && \
		.venv-screenshots/bin/python -m pip install -q -r tools/screenshots/requirements.txt )
	.venv-screenshots/bin/python -m playwright install chromium
	.venv-screenshots/bin/python tools/screenshots/take_screenshots.py

social-preview: ## Redraw docs/assets/social-preview.png (needs Google Chrome and pillow)
	python3 tools/brand/brand_kit.py social --repo AWS-Offboarding-Audit --name "AWS Offboarding Audit" --tagline "Check what a departing engineer did across every AWS account, in one local report" --chip "Read-only AWS calls" --chip "CloudTrail + Lake" --chip "Local HTML dashboard" --chip "Python 3.10+" --icon docs/assets/brand/icon.svg
