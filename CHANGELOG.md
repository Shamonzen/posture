# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-30

First public release.

### Added
- **Linux collector**: local and SSH transports, a fixed command allowlist (no shell), exact-argument
  `deploy/sudoers.posture`, record / replay, shadow hashes dropped at parse time.
- **Active Directory collector**: fixed LDAP searches over LDAPS (certificate and IP SAN verified
  before the bind) on a read-only connection; DC registry settings over sealed WinRM (`--winrm`)
  with one fixed `Get-Item` script per key.
- **Azure collector**: 10 fixed ARM and Microsoft Graph GET requests; the HTTP client refuses
  every other method, never follows redirects and keeps the token on the API it came from.
- **56 checks** as YAML data (26 Linux, 16 AD, 14 Azure) mapped to CIS benchmark controls and
  MITRE ATT&CK techniques, validated by a strict schema; every check fails on its weak recording
  and passes on its hardened one.
- **Engine** with `pass / fail / error / skip`; an uncollected fact is `error`, never a pass.
- **Reports**: JSON, static HTML (no JavaScript, strict CSP, autoescaped), SARIF 2.1.0.
- **Baseline and CI gate**: fingerprinted findings, `--baseline`, `--fail-on`, `posture diff`,
  exit codes 0 / 1 / 2.
- **Multi-target audits** from an inventory file into one report.
- **Vagrant lab** (`posture-ubuntu`, `posture-rocky`, `posture-dc`) with weak and hardened
  profiles behind a lab guard, and scrubbed recordings from it.
- **CI**: lint, tests, Bandit, pip-audit, gitleaks, SBOM, Dependabot, SARIF upload, and the
  posture gate over the lab recordings.
- Documentation: README, least-privilege permissions (`docs/permissions.md`), threat model,
  plan and milestone notes (`docs/PLAN.md`).

[1.0.0]: https://github.com/Shamonzen/posture/releases/tag/v1.0.0
