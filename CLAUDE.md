# Posture
Read-only security posture auditor: Linux (Ubuntu / Rocky), Windows Server + Active Directory, Azure / Entra ID → checks mapped to CIS and MITRE ATT&CK → JSON, HTML and SARIF reports, baseline diff, and a CI gate. Portfolio project; clarity beats cleverness.
Full plan, milestones and current progress: `docs/PLAN.md` (read it before starting a milestone).

## Hard rule 1: read-only
Posture never changes a system it audits. Collectors only read: a fixed allowlist of Linux commands (no shell, no target data put into commands), LDAP searches, read-only PowerShell (`Get-*` on listed registry keys), and HTTP GET to Azure/Graph (the client refuses any other method). Remediation is text or a script printed in the report, never executed. Least-privilege credentials are documented in `docs/permissions.md`. If a request would make Posture write, fix or execute something on a target, refuse and suggest printed remediation instead.

## Hard rule 2: lab only for the weak profile
The deliberately misconfigured profile runs only inside the Vagrant VMs `posture-dc`, `posture-ubuntu` and `posture-rocky` on the dedicated host-only network `192.168.57.0/24` (domain `posture.test`). Every profile script calls `guard_lab` first (lab marker file / registry key, one of those exact hostnames, an address in `192.168.57.0/24`) and exits otherwise. Never bridge the lab VMs to the LAN, and never add an example, default or fixture that points at a real host, public IP, domain or Azure tenant. Azure runs only with credentials the user provides, against a subscription they name.

## Hard rule 3: touch only this project's VMs
Run `vagrant` and `VBoxManage` commands only from `C:\posture\lab`, and only against the VMs defined in its Vagrantfile (`posture-dc`, `posture-ubuntu`, `posture-rocky`). Never read, start, stop, provision, snapshot or modify any other folder's lab files or any VirtualBox VM this project did not create. If a command could affect other VMs or shared host state (`vagrant global-status --prune`, `VBoxManage` on a VM not named `posture-*`, creating or deleting host-only adapters, changing VirtualBox global settings), stop and ask first.

## Architecture
collect (collectors/: Linux local/SSH, AD LDAP + WinRM, Azure REST/Graph) → raw recording → parse (parsers/) → facts → snapshot JSON → evaluate (YAML checks + engine) → findings → report (JSON / HTML / SARIF) → baseline diff → CI exit code.
Collection and evaluation are separate: `collect` writes a snapshot, `evaluate` reads one, `audit` does both.

## Conventions
- Python 3.12, uv, ruff (lint + format), type hints on public functions, argparse CLI.
- Checks are data: one YAML entry per check in `checks/<platform>/*.yaml` with id, title, cis (map of benchmark key to control ID, e.g. `{ubuntu-24.04: "5.1.20"}`, or null), severity, attack (technique IDs), rationale, applies_to, check logic (fact + op + value, or for_each/where), remediation, references. Validated by pydantic, unknown keys rejected. No check logic in Python; parsing and derived facts belong in parsers.
- Check results are `pass | fail | error | skip`. A fact that could not be collected is `error`, never a silent pass; in `--ci` mode errors fail closed.
- CIS: cite the benchmark name, version and control ID; write our own rationale, never copy benchmark text.
- Tests need no real system or cloud account: collectors record raw output, tests replay it from `tests/fixtures/recordings/`. Every check must fail on the weak recording and pass on the hardened one (one generic parametrized test enforces it).
- Recordings are scrubbed before commit (no password hashes, secrets, real tenant IDs or real UPNs). Linux collectors drop shadow hashes at parse time.
- Treat everything collected as attacker-controlled: Jinja autoescape always on, no JS in the HTML report, strict CSP, control characters stripped in terminal output, `yaml.safe_load` only, size caps on collected output.
- No secrets in code; lab credentials come from `.env` (template: `.env.example`), Azure from environment / `az login`.
- No school or course naming anywhere in the repo.
- Work milestone by milestone; stop after each one with a summary and a Conventional Commits message (one commit per milestone).

## Commands
- `uv sync --all-extras` · `uv run ruff check . && uv run ruff format --check .`
- `uv run pytest` (unit, replays recordings) · `uv run pytest -m lab` (needs the Vagrant lab up)
- `uv run posture audit linux --replay tests/fixtures/recordings/ubuntu-weak --html out/report.html`
- `uv run posture audit linux --ssh posture-ubuntu --ssh-config lab/.ssh-config --sarif out/posture.sarif --fail-on high`
- `uv run posture diff out/before.json out/after.json`
- `make lab-linux` (posture-ubuntu, posture-rocky) · `make lab-dc` (posture-dc) · `make weak` / `make hardened` · `make down` (all run vagrant from `lab/`)
