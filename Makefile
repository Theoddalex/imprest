# Dev workflow. `make security` is the local mirror of the CI security jobs.

PY := .venv/bin/python

.PHONY: test security bandit trivy audit-image

test:
	$(PY) -m pytest -q

## Static analysis of our own code (SAST) — key handling, auth, injection.
bandit:
	$(PY) -m bandit -c pyproject.toml -r src

## Dependencies (SCA), committed secrets, and IaC misconfig — one scanner.
## Severity floor HIGH: fail on what matters, don't cry wolf on LOWs.
## Trivy can't read pip deps from pyproject.toml, so freeze the resolved venv
## into a lockfile it understands, scan, then clean up (it is gitignored).
trivy:
	$(PY) -m pip freeze --exclude-editable > requirements.txt
	trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
	  --exit-code 1 --skip-version-check .; \
	  status=$$?; rm -f requirements.txt; exit $$status

## The shippable artifact itself (base image + installed packages).
audit-image:
	docker build -q -t agentpay:audit .
	trivy image --severity HIGH,CRITICAL --exit-code 1 agentpay:audit

security: bandit trivy
	@echo "security checks passed"
