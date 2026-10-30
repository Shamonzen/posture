# Posture — plan

## Context
Portfolio project #2, for security engineer interviews (cloud / infrastructure / DevSecOps). Project #1 is [LogSentry](https://github.com/Shamonzen/logsentry) (detect); Posture is the "prevent" side: a **read-only** auditor that checks Linux hosts, Windows Server + Active Directory, and Azure / Entra ID against CIS benchmarks, and reports what is misconfigured, why it matters (the ATT&CK techniques it enables), and how to fix it. A Vagrant lab with a weak and a hardened profile shows the before/after. Repo: `C:\posture`, branch `main`, remote `github.com/Shamonzen/posture` (private while in progress, public at v1.0), MIT.

**Your answers:** Python 3.12 + uv · Windows via LDAP (AD objects) + read-only PowerShell over WinRM (DC host settings) · Linux locally or over SSH, same command list · build order Linux → AD → Azure · repo and CLI `posture` · HTML report is one static file · lab host has 16 GB RAM · Posture replaces the "Linux hardening auditor" idea and becomes project #2 (the recon orchestrator moves to #3).

## Stack
- **Python 3.12, uv + `uv.lock`, ruff, pytest, pydantic v2, PyYAML (`safe_load` only), Jinja2**: the same tooling as LogSentry.
- **argparse** CLI (stdlib, as in LogSentry).
- **Extras keep the core light:** `posture[ad]` = `ldap3` + `pypsrp`; `posture[azure]` = `azure-identity` + `httpx`. Linux needs nothing extra: `subprocess` (no shell) locally, the system `ssh` client remotely (reuses your ssh config, host-key checking, agent).
- **Azure through plain REST**, not the 30-package Azure SDK: ARM (`management.azure.com`) and Microsoft Graph (`graph.microsoft.com/v1.0`) with httpx, tokens from `azure-identity`. Recorded JSON fixtures then map 1:1 to API responses.
- **Check logic: a small operator set in YAML** (no JMESPath / Rego dependency). Dev deps: pytest, ruff, jsonschema (SARIF validation), bandit, pip-audit.

## Architecture
```
 Linux (local / ssh) ─┐                                                       ┌─> JSON
 AD (LDAP + WinRM)  ──┼─> collect ─> raw recording ─> parse ─> facts ─> snapshot ─> evaluate ─> findings ─┼─> HTML (static)
 Azure (ARM + Graph) ─┘  (read-only    (replayable)   (parsers/)          (JSON)    (checks/*.yaml        ├─> SARIF ─> GitHub code scanning
                          transports)                                                + engine)            └─> diff vs baseline ─> CI exit code
```
- **Collect and evaluate are separate.** `posture collect` writes a snapshot (facts + metadata: target, platform, collected_at, the identity used, collection errors). `posture evaluate` turns a snapshot into findings. `posture audit` does both. An old snapshot can be re-evaluated with new checks, and the snapshot is the audit evidence.
- **Record / replay.** Each transport (command runner, LDAP search, WinRM script, HTTP GET) can save its raw responses with `--record <dir>`, and `--replay <dir>` feeds them back. Tests replay recordings taken from the lab, so no test needs a real system or a cloud account.
- **Parsers do the thinking, checks only compare.** Parsers turn raw output into named facts (e.g. `ssh.permitrootlogin`, `ad.users[].does_not_require_preauth` decoded from `userAccountControl`, `azure.storage_accounts[].allow_blob_public_access`). Checks are YAML comparisons over those facts. Anything that needs real logic becomes a derived fact in a parser, with its own test.
- **Read-only is enforced in code, not just promised:** the Linux command list is a constant checked by a test (and matched by `deploy/sudoers.posture`); the HTTP client raises on anything but GET; the LDAP layer only exposes `search`; the WinRM scripts are fixed files of `Get-*` calls.

## Check format
```yaml
- id: LNX-SSH-001
  title: SSH root login is disabled
  platform: linux
  applies_to: {distro: [ubuntu, rocky]}
  cis: {ubuntu-24.04: "5.1.20", rhel-9: "5.1.20"}   # benchmark key -> control ID (keys and full names in models.BENCHMARKS)
  severity: high
  attack: [T1110.001, T1078.003]
  rationale: >-
    Our own words: what an attacker gains and why.
  check:
    fact: ssh.permitrootlogin
    op: in
    value: ["no", "prohibit-password"]
  remediation:
    text: Set `PermitRootLogin no` in /etc/ssh/sshd_config.d/ and reload sshd.
    script: |
      echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/50-posture.conf && sudo systemctl reload ssh
  references: ["https://attack.mitre.org/techniques/T1110/001/"]
```
- **Operators:** `eq, ne, in, not_in, lt, le, gt, ge, regex, exists, empty, not_empty`, and for lists of strings `contains, any_match, none_match, subset` (a string where a list is expected is an `error`, never a substring test; a failed `none_match` / `subset` shows only the offending items), combined with `all` / `any`. For lists of objects: `for_each: ad.users` + `key: sam` + `where: {...}` → every matching object is an offender, listed by its `key` as evidence (capped at 50); the check passes when there are none. A missing fact or a wrong type (e.g. `lt` on a string) is an `error`; `all`/`any` evaluate every branch, so an uncollected fact is never hidden by short-circuiting.
- **Results:** `pass | fail | error | skip`. Missing fact → `error` (never a silent pass). `applies_to` not matched → `skip`.
- **`cis` may be null** where CIS has no control (Kerberoasting, AS-REP roasting, delegation are not CIS controls); `references` then points at Microsoft / ANSSI guidance. Severity is our own call, documented in the rationale.
- **Validation at load:** unknown keys rejected, unique ids, ATT&CK ids match `T\d{4}(\.\d{3})?`, each op gets the value type it needs, regexes compile, `cis` stated explicitly (null needs `references`). Fact names are proven by the weak/hardened contract test: a fact no parser produces makes the check `error`, which fails the test.
- **YAML gotcha:** unquoted `no` / `yes` are booleans in YAML 1.1 (`safe_load`), so string values like `"no"` must be quoted. A bad check stops Posture at startup.

## Data model
- **Snapshot:** `schema_version, tool_version, platform, target, collected_at (UTC), identity, facts {…}, errors [{source, message}]`.
- **Finding:** `check_id, title, platform, target, status, severity, cis, attack[], evidence (offending objects or the observed value), remediation, fingerprint`.
- **Fingerprint** = sha256 of `check_id + target + resource` (resource = the offending object, e.g. a user's `sAMAccountName`). Stable across runs, so baseline diff and SARIF `partialFingerprints` work.

## Outputs, baseline, CI mode
- **Terminal:** a summary table (control characters stripped).
- **JSON:** the findings list + snapshot metadata. It is also the baseline format.
- **HTML:** one static file, no JavaScript: inline CSS, `<meta>` CSP `default-src 'none'; style-src 'sha256-…'` (hash computed at render), Jinja autoescape, findings grouped by severity in `<details>`, each with rationale, ATT&CK links, evidence and remediation. A test feeds hostile data (an AD `description` with `<script>`, a username with ANSI codes) and checks it comes out escaped.
- **SARIF 2.1.0:** one rule per check (`security-severity` set so GitHub shows critical/high/medium/low), one result per failed finding. Findings are about hosts, not files, so each result's location is the check's YAML file in the repo and the target goes in the message and `partialFingerprints`. Validated against the SARIF schema in tests.
- **Diff:** `posture diff old.json new.json` → new, fixed and unchanged findings. `--baseline accepted.json` hides accepted findings.
- **CI mode:** `--fail-on <severity>` exits 1 when any `fail` or `error` at or above that severity is left after the baseline; 0 otherwise; 2 on usage or total collection failure.

## Least privilege (`docs/permissions.md`)
| Environment | Identity | Why it's enough |
|---|---|---|
| Linux | dedicated `posture` user over SSH key; `deploy/sudoers.posture` allows exactly the commands that need root (`sshd -T`, `getent shadow`, `auditctl -l`, `ufw status verbose`, `firewall-cmd --list-all`…), exact arguments | sudo matches arguments exactly, so no shell escape; shadow hashes are dropped at parse time |
| Pending updates | `apt-get -s upgrade` / `dnf -C check-update --security` | uses the existing package cache (refreshing it would be a write); the cache age is reported |
| AD | an ordinary domain user, over LDAPS (certificate verified) | any authenticated user can read the objects these checks need |
| DC host settings | WinRM with a non-admin account in *Remote Management Users*, reading registry values only | verify in milestone 9; upgrade path: a JEA endpoint exposing only those reads |
| Azure | **Reader** on the subscription; Graph application permissions `Policy.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All` (MFA registration) | all read-only; no write role anywhere |
If a fact can't be read with these rights, its checks report `error` with the reason, rather than asking for more rights.

## Checks (first set; ~45 total)
| Platform | Area | Examples | ATT&CK the misconfiguration enables |
|---|---|---|---|
| Linux | SSH | root login, password auth, empty passwords, MaxAuthTries, weak ciphers/MACs/KEX, X11 forwarding | T1110.001, T1078.003, T1021.004 |
| Linux | Users / sudo | extra UID 0, empty or no password, `NOPASSWD: ALL`, sudo without `use_pty`/logging | T1548.003, T1078.003 |
| Linux | Files | perms on `/etc/shadow`, `/etc/passwd`, `/etc/sudoers*`, sshd_config; unexpected SUID binaries; world-writable files in system dirs | T1548.001, T1222.002, T1098 |
| Linux | Firewall | ufw / firewalld inactive, default inbound allow | T1562.004 |
| Linux | Updates | pending security updates, no unattended-upgrades / dnf-automatic | T1068, T1190 |
| Linux | Logging | auditd not running, no audit rules for identity/sudoers, journald not persistent | T1562.012, T1070.002 |
| AD | Password / lockout | min length < 14, no lockout threshold, reversible encryption | T1110.001, T1110.003 |
| AD | Kerberos | Kerberoastable users (SPN on a user account), AS-REP roastable (`DONT_REQ_PREAUTH`), krbtgt password age | T1558.003, T1558.004, T1558.001 |
| AD | Delegation | unconstrained delegation on non-DC computers or users | T1558, T1550.003 |
| AD | Accounts | stale enabled accounts, `PASSWD_NOTREQD`, password never expires on admins, large privileged groups, `adminCount` orphans | T1078.002 |
| AD | LAPS | enabled non-DC computers without legacy or Windows LAPS attributes | T1078.003, T1550.002 |
| DC host | Signing / NTLM | SMB signing not required, LDAP signing not required, `LmCompatibilityLevel` < 5 | T1557.001, T1557, T1110.002 |
| Azure | Identity | admins without MFA via Conditional Access (or Security Defaults), legacy auth not blocked, permanent Global Admins > N | T1078.004, T1110.003 |
| Azure | Guests | guest invite open to everyone, guests with directory read like members | T1087.004 |
| Azure | Storage | `allowBlobPublicAccess`, public containers, HTTP allowed, min TLS < 1.2 | T1530 |
| Azure | Network | NSG inbound from `*`/Internet to 22, 3389, 1433, 3306, 5985/5986 | T1133, T1021.001, T1021.004 |
| Azure | Logging | no Activity Log export, Defender for Cloud plans off | T1562.008 |
Exact CIS control IDs are looked up per check when it is written (Ubuntu 24.04, Rocky Linux 9, Windows Server 2019, Microsoft Azure Foundations, Microsoft 365 for Entra items). Linux IDs come from CIS Ubuntu 24.04 v1.0.0 and RHEL 9 v2.0.0 as implemented by ansible-lockdown (UBUNTU24-CIS, RHEL9-CIS); Rocky 9 uses the RHEL 9 numbering.

## Folder structure
```
posture/
  CLAUDE.md  README.md  LICENSE  CHANGELOG.md  pyproject.toml  uv.lock  Makefile  .env.example  .gitignore
  checks/{linux,ad,azure}/*.yaml
  src/posture/
    cli.py            # collect | evaluate | audit | diff | checks
    models.py         # Snapshot, Check, Finding, Severity, Status
    checks.py         # load + validate check YAML
    engine.py         # operators, for_each/where, evaluate(check, snapshot) -> Finding
    baseline.py       # fingerprint, diff, baseline filter
    collectors/       # transport.py (record/replay), linux.py, ad.py (ldap + winrm), azure.py (GET-only client)
    parsers/          # linux.py (one small function per command), ad/, azure/
    reports/          # json_.py, html.py, sarif.py, templates/report.html
    winrm/            # fixed read-only PowerShell scripts
  deploy/sudoers.posture
  docs/PLAN.md  docs/permissions.md  docs/reports/{before,after}.html
  lab/
    Vagrantfile       # posture-dc (WS2019), posture-ubuntu (24.04), posture-rocky (9); host-only 192.168.57.0/24
    guard_lab.sh  guard_lab.ps1
    profiles/linux/{weak,hardened}.sh  profiles/windows/{promote-dc,weak,hardened}.ps1
  tests/
    fixtures/recordings/{ubuntu,rocky,dc,azure}-{weak,hardened}/   # scrubbed
    fixtures/hostile/                                              # XSS / ANSI payloads
    test_engine.py  test_checks_load.py  test_checks_weak_hardened.py  test_parsers_*.py
    test_reports.py  test_sarif.py  test_baseline.py  test_readonly.py  test_cli.py
    lab/test_lab.py   # @pytest.mark.lab
  .github/workflows/ci.yml  .github/dependabot.yml
```

## Lab (Vagrant + VirtualBox, no Hyper-V)
- **VMs:** `posture-dc` Windows Server 2019 evaluation box, 2 vCPU / 3.5 GB, `192.168.57.10`, promoted to domain `posture.test` (`.test` is reserved, so it can never collide with a real domain); `posture-ubuntu` 24.04, 1 GB, `.11`; `posture-rocky` 9, 1 GB, `.12`. The same name is the Vagrant machine name, the VirtualBox display name (`vb.name`) and the hostname, so they can't be confused with other VirtualBox VMs. Box versions pinned in the Vagrantfile.
- **Isolation from other VirtualBox labs:** the lab uses its own host-only network `192.168.57.0/24` (`192.168.56.0/24` belongs to other labs on this host). `vagrant` / `VBoxManage` run only from `lab/` and only against the three `posture-*` VMs; anything that could touch other VMs or shared host state (`global-status --prune`, host-only adapter changes) needs the user's go-ahead (CLAUDE.md, hard rule 3).
- **SSH:** committed `lab/ssh-config` with host aliases `posture-ubuntu` / `posture-rocky` straight to their host-only IPs, user `posture`, a lab-only ed25519 key in git-ignored `lab/keys/` (generated by `lab.sh up`), host keys accepted on first connect into `lab/keys/known_hosts`. Synced folders are disabled: the weak VMs get no write path into the host.
- **16 GB host:** all three fit (~5.5 GB) with other VMs off. `lab.sh` names the VMs it starts; every command takes VM names (`lab.sh up posture-dc`), so the DC can run alone with the Linux VMs halted.
- **Network:** host-only adapter for Posture's traffic; VirtualBox NAT only for package installs. No bridged adapter, no port forwards beyond Vagrant's own localhost ones.
- **Driver:** no `make` on the Windows host, so `bash lab/lab.sh up | weak | hardened | record <profile> [vm…] | test | status | halt | destroy` (Git Bash). It runs vagrant from `lab/` and always names the posture-* VMs.
- **Profiles:** `lab.sh up` provisions the base once (audit account, `deploy/sudoers.posture`, marker) and saves a `base` snapshot. `lab.sh weak|hardened` restores `base`, then runs that one profile, so the two never have to undo each other. The hardened profile's last step removes Vagrant's own `vagrant ALL=(ALL) NOPASSWD: ALL` (a real LNX-SUDO-001 finding); `vagrant provision` can't sudo afterwards, which is fine because every switch restores `base` first. The Vagrantfile prepends `guard_lab.sh` to every shell provisioner, which checks a marker (`/etc/posture-lab`, `HKLM:\SOFTWARE\PostureLab`) set by the base provisioner, one of the exact hostnames `posture-dc` / `posture-ubuntu` / `posture-rocky`, and an address in `192.168.57.0/24`; otherwise it exits.
- **Weak profile:** each check has a matching misconfiguration (root SSH login, `NOPASSWD: ALL`, firewall off, auditd removed…; on the DC: a user with an SPN, a `DONT_REQ_PREAUTH` user, a computer with unconstrained delegation, stale accounts, weak password policy, SMB/LDAP signing off, `LmCompatibilityLevel 1`, computer objects without LAPS). Lab passwords come from `.env`.
- **Hardened profile:** the same settings fixed, Windows LAPS schema + policy (needs the April 2023 cumulative update on WS2019; fallback: legacy LAPS. The check accepts either).
- `lab.sh record weak|hardened` checks the VM's marker says that profile, then runs `posture collect --ssh … --record` into `tests/fixtures/recordings/<os>-<profile>/` (shadow is scrubbed at collection). `lab.sh test` (`pytest -m lab`) audits the live VMs, checks every result matches the profile, and hashes every readable file in `/etc` before and after to prove the audit changed nothing.

## CI (`.github/workflows/ci.yml`, from milestone 1)
- Jobs: **lint** (ruff check + format), **test** (pytest), **SAST** (Bandit, SARIF uploaded to code scanning), **dependencies** (`pip-audit` on `uv export`), **secrets** (gitleaks on the full history), **SBOM** (CycloneDX via syft, kept as a build artifact). From milestone 6: **posture** job: evaluate the weak recordings and upload the SARIF (findings visible in the Security tab), and `--fail-on high` on the hardened recordings (must pass).
- Hardening of the pipeline itself: actions pinned by commit SHA, `permissions: contents: read` by default (`security-events: write` only on SARIF upload jobs), Dependabot for GitHub Actions and uv.

## Milestones (each one sitting = one commit)
Status: ✅ done · ⏭️ next. Update this list when a milestone is committed.

1. ✅ **Scaffold + DevSecOps CI:** git init, pyproject/uv, ruff, package skeleton, `posture --help` smoke test, full CI (lint, test, Bandit, pip-audit, gitleaks, SBOM), Dependabot, LICENSE, `.gitignore` (`out/`, `.env`, raw recordings), `.env.example`.
2. ✅ **Models + check loader + engine:** pydantic models, YAML validation (unknown keys, duplicate ids, bad ATT&CK ids, bad regex), every operator, `for_each/where`, `pass/fail/error/skip`. Tests per operator and per validation error.
3. ✅ **Linux collector + parsers:** local and SSH transports, record/replay, command allowlist + `test_readonly.py`, `deploy/sudoers.posture` checked against the allowlist, parsers with tests, shadow hashes dropped. Hand-written Ubuntu fixtures for now.
4. ✅ **Linux checks (26)** in `checks/linux/` (ssh, accounts, files, firewall, updates, logging) + the weak-fails / hardened-passes contract test over hand-written `ubuntu-` and `rocky-` `weak` / `hardened` recordings. Added the list operators and the `cis` benchmark map.
5. ✅ **Linux lab:** `lab/Vagrantfile` (posture-ubuntu, posture-rocky; bento boxes pinned to 202510.26.0), `guard_lab.sh` prepended to every provisioner, base / weak / hardened profiles on a `base` snapshot, `lab/lab.sh`, committed `lab/ssh-config`. The hand-written fixtures are replaced by recordings from the real VMs; `lab.sh test` passes on both profiles (every result matches, `/etc` unchanged by the audit). What the real hosts showed:
    - `sshd -T` works on Ubuntu 24.04; `dnf -C` works as the non-root `posture` user (through a per-user copy of the cache); the year-old boxes really have pending security updates (165 Ubuntu, 188 Rocky packages), so the weak profile fails LNX-UPD-001 honestly.
    - **Bug found and fixed:** `dnf updateinfo list --security` also lists advisories for the older kernels dnf keeps installed (`installonly_limit`), so a fully patched Rocky host never read clean. The collector now uses `dnf check-update --security`.
    - OpenSSH 10 clients print a post-quantum warning on stderr against old servers; the ssh runner passes `LogLevel=ERROR` so client noise never lands in the target's output.
    - Setuid allowlist: added Rocky's `sssd` helpers and `mount.nfs`. The VirtualBox Guest Additions ship `VBoxDRMClient` setuid root on both boxes: a real finding, removed by the hardened profile instead of allowlisted.
    - Vagrant's own sudo rule is `vagrant ALL=…` on Ubuntu and `%vagrant ALL=…` on Rocky; the hardened profile removes both, last.
    - Known limits: a kernel updated but not yet rebooted into still passes LNX-UPD-001 (no "reboot required" check yet); the non-root `find` skips unreadable directories (`/root`, `/etc/sudoers.d`…), recorded in the fixtures' `_meta.json`.
6. ✅ **Reports + baseline + CI mode:** `_meta.json` now written with LF on Windows. `posture evaluate` / `audit` with `--json` (report = snapshot metadata without facts + findings; also the baseline format), `--html` (static, no JS, CSP with the CSS hash, control characters stripped then autoescaped; hostile username/hostname/stderr test), `--sarif` (2.1.0, validated against the OASIS schema in tests; each result points at its check's YAML line), `--baseline`, `--fail-on`; `posture diff`. Exit codes 0 / 1 gate / 2 usage, bad checks or nothing collected. CI `posture` job: hardened recordings pass `--fail-on high`, weak ones must fail it, weak SARIF uploaded once the repo is public. `docs/reports/before.html` / `after.html` from the Ubuntu recordings. Decisions:
    - Fingerprint = sha256(check id, target, sorted `for_each` offenders). Observed values (e.g. a pending-update count) are not part of it, so a baseline survives the number moving; a new offending account is a new finding.
    - SARIF carries `fail` results only; `error` findings still fail the CI gate (fail closed) but code scanning has no "unknown" state to show them in.
7. ✅ **DC lab:** `posture-dc` (`gusztavvargadr/windows-server-2019-standard` 1809.0.2407, already patched past April 2023 so Windows LAPS is built in), promoted to `posture.test`; `guard_lab.ps1` prepended (with `profiles/windows/common.ps1`) to every Windows provisioner and tested with stubbed cmdlets; audit account `POSTURE\posture`: ordinary domain user, *Remote Management Users*, not delegable. Weak / hardened profiles on a `base` snapshot, each ending with a check that its policy and registry values really applied; both verified on the live DC, and `posture` opens a WinRM session there as a non-admin and reads the Lsa key. `lab.sh` commands take VM names; `record` stays Linux-only until milestone 9. What the real DC showed:
    - **The box forwarded RDP (53389) on every host interface**, putting the weak DC on the LAN. The Vagrantfile overrides it to 127.0.0.1, and a test requires every forwarded port to be localhost-only.
    - A just-promoted DC refuses WinRM logons until it reboots, so Vagrant's `reboot: true` and `vagrant reload` hang on the 401 and ACPI shutdown is ignored. `lab.sh up` promotes, hard powers off (safe once promotion has finished), boots, then runs `base`.
    - After promotion `vagrant` is only in BUILTIN\Administrators: enough for users and SYSVOL, not for GPO objects or the schema. Those two writes run as the domain Administrator (`.env`), instead of adding `vagrant` to Domain / Schema Admins.
    - Password policy and DC security options are edited in the Default Domain (Controllers) Policy's `GptTmpl.inf` plus a GPO version bump, since a direct registry or `Set-ADDefaultDomainPasswordPolicy` change is reverted by the next refresh.
    - For milestone 9: krbtgt age and stale accounts can't be aged in a fresh lab (`old.contractor` is enabled and has never logged on: count never-logged-on accounts older than N days as stale, or test those checks against hand-edited fixture values). `vagrant` stays in BUILTIN\Administrators with a non-expiring password in both profiles (Vagrant needs it): exclude it in the checks by name with a comment, or report it honestly. The LAPS expiry on the placeholder computers `ws01` / `ws02` is stamped by the hardened profile, since no LAPS client runs behind them.
8. ✅ **AD collector (LDAP):** `posture collect ad --ldap DC --user DOMAIN\user --ca-file …` (password from `POSTURE_LDAP_PASSWORD` or a prompt), `posture[ad]` = `ldap3`. A fixed list of searches (rootDSE, "Who am I?", domain policy, users, computers, groups), paged, capped at 50 000 entries, on a `read_only` connection that never follows referrals; recordings are the JSON of each search. Parsers decode `userAccountControl`, `msDS-SupportedEncryptionTypes`, `pwdProperties`, FILETIME / generalized times (ages against the DC's own `currentTime`), LAPS by its expiry attributes only (never the password), and expand privileged groups (by SID: domain RIDs 512/518/519/526/527, BUILTIN 544/548–551) through nesting. `lab.sh record <profile> posture-dc` records `dc-weak` / `dc-hardened` (LDAP part); a lab test checks a live LDAPS audit matches one of them. Spike against the hardened DC (`LDAPServerIntegrity = 2`):
    - **Released ldap3 (2.9.1) can't sign or seal a bind** (`session_security` exists only in unreleased master), and its NTLM fails on Python 3.12 / OpenSSL 3 anyway (`unsupported hash type MD4`). Simple bind on 389: `strongerAuthRequired`, as it should be. Kerberos would need gssapi/winkerberos and ldap3 still negotiates no security layer. `msldap` signs and seals, but brings an async stack of 4+ packages.
    - **Chosen: LDAPS + simple bind**, certificate verified (system store or `--ca-file`), the TLS handshake checked before any credential is sent. ldap3 turns Python's hostname check off and its own matcher ignores IP SANs, so for an IP target the collector checks the certificate's IP SAN itself.
    - **The DC had no certificate.** `base.ps1` now creates a self-signed one (DNS + IP SANs). Two traps, each logged only as event 1220 `8009030e` while 636 resets every handshake: the key must be in the legacy *Microsoft RSA SChannel Cryptographic Provider* (`-KeySpec KeyExchange`), not CNG; and a self-signed certificate must also sit in the machine's Root store. Then AD DS picks it up by itself: no `renewServerCertificate` (refused as "inappropriate authentication" with the broken cert) and no NTDS restart (which cuts Vagrant's WinRM session, since on a DC `vagrant` authenticates against AD DS). `lab.sh up` exports it over Vagrant's WinRM to `lab/keys/posture-dc.pem` for pinning. The `base` snapshot was re-saved with it.
    - For milestone 9: `adminCount` is set by SDProp (hourly), so right after a profile only `old.admin` (set by hand) has it. `krbtgt` shows `msDS-SupportedEncryptionTypes = 0` (= unset, parsed as `None`). Membership through `primaryGroupID` and `member` beyond 1 500 values (range retrieval) are not read: a `shortcut:` in `parsers/ad.py`.
9. ⏭️ **DC host collector (WinRM)** + **AD checks (~15)**: pypsrp, fixed `Get-ItemProperty` scripts, verify the non-admin account can read every key (else `error` + documented); record and scrub `dc-weak` / `dc-hardened`.
10. **Azure collector:** azure-identity, GET-only httpx client (test that POST/PUT/PATCH/DELETE raise), ARM + Graph with `@odata.nextLink` / `nextLink` paging, throttling retry, scrubbed hand-built `azure-weak` / `azure-hardened` recordings; Security Defaults handled as an alternative to Conditional Access.
11. **Azure checks (~12)** + `docs/permissions.md` complete (Reader, the four Graph permissions, how to create the app registration). Optional live run against your subscription, never in CI.
12. **Multi-target audits:** `posture audit --inventory lab/inventory.yaml` (all lab hosts in one run, one report), combined before/after HTML and SARIF.
13. **README + v1.0:** problem, Mermaid diagram, before/after screenshots, check table, how to run it, permissions, threat model, limitations, comparison with Lynis / PingCastle / Prowler / ScoutSuite, interview notes; `CHANGELOG.md`, tag `v1.0.0`, repo public.

After each milestone I stop, summarize, and suggest a commit message (Conventional Commits).

## Threat model (goes into the README)
The auditor holds strong read credentials and swallows output from systems that may already be compromised.

| Threat | Mitigation |
|---|---|
| Stored XSS in the report via hostile AD attributes, usernames, Azure resource names | Jinja autoescape, no JS, CSP with `default-src 'none'`, escaping test with hostile fixtures |
| Terminal injection (ANSI / control characters) | Control characters stripped before printing |
| Command injection on the audited host | Fixed command list, argument lists only (no shell), no collected data ever put into a command |
| Hostile or huge output (DoS, ReDoS) | Size caps per command / response, timeouts, simple regexes in parsers |
| Posture used to change systems | Read-only enforced in code (allowlist test, GET-only client, search-only LDAP, fixed `Get-*` scripts) and by the credentials themselves |
| Credential theft from the tool's host | No stored secrets: SSH keys/agent, `.env` for lab only, `az login` / environment for Azure; nothing written to snapshots or reports |
| MITM on collection | SSH host-key checking stays on; LDAP signing/sealing or LDAPS; WinRM message encryption; HTTPS to Azure |
| The report is an attacker's roadmap (list of Kerberoastable accounts, open ports) | Reports and snapshots are sensitive: `out/` is git-ignored, only scrubbed lab recordings are committed, SARIF uploaded only from lab fixtures |
| Remediation scripts run blindly | Scripts are suggestions, shown with a warning to review and test first; never executed by Posture |
| Malicious check files | `yaml.safe_load`, strict pydantic schema, no code in checks |
| Supply chain | `uv.lock` hashes, pip-audit, SBOM, Dependabot, SHA-pinned actions, gitleaks |

## 5 decisions an interviewer will question
1. **Why build this instead of using Lynis, PingCastle, Prowler or ScoutSuite?** Those are the tools to run in production, and the README says so. **Lynis** is a mature shell-based Linux/Unix host auditor with hundreds of tests and a hardening index, but no AD or cloud. **PingCastle** goes far deeper into AD than Posture (trusts, ACLs, GPO risk scoring), but is AD-only and Windows/.NET. **Prowler** covers AWS / Azure / GCP / M365 / Kubernetes against CIS and many other frameworks, but no hosts or on-prem AD. **ScoutSuite** is a multi-cloud configuration review with an offline HTML report, cloud only. *What Posture adds:* one data model and one report across host, directory and cloud (the three layers an infrastructure security engineer owns), every finding tied to the ATT&CK techniques it enables, and a CI-native workflow (SARIF, baseline diff, severity gate). *Against:* far fewer checks than any of them. *Answer:* it shows I understand what those tools check and why, and how to wire posture into a pipeline; for coverage I'd run Prowler + PingCastle + Lynis and import their results.
2. **Checks as YAML data, not Python (or Rego / OPA).** *For:* reviewable by non-developers, diffable, easy to map to CIS/ATT&CK, safe to load (no code execution), one generic test proves every check. *Against:* a tiny operator language hits a ceiling. *Answer:* the hard logic lives in parsers as tested derived facts; checks stay comparisons. Rego would be the upgrade if the operator set keeps growing, at the cost of a second language.
3. **Collect / evaluate split with record and replay.** *For:* offline, deterministic tests with real lab data; snapshots are audit evidence; old snapshots can be re-evaluated with new checks; collection can run where the credentials are, evaluation anywhere. *Against:* snapshots hold sensitive data and must be handled like the report; recordings drift from reality as OS versions change, so they're re-recorded from the lab.
4. **Read-only and least privilege, enforced, with honest gaps.** Reader + read-only Graph, an ordinary domain user for LDAP, non-admin WinRM, an exact-argument sudoers list. *Against:* some settings can't be read without admin rights. *Answer:* those checks return `error` with the reason (never a silent pass), and `--ci` fails closed on them. Upgrade: a JEA endpoint for the DC.
5. **The auditor is itself an attack surface, and its output is sensitive.** It reads data an attacker may control (AD descriptions, usernames, resource names) and produces a map of weaknesses. Mitigations: escaping + CSP + no JS, no shell and no interpolation in collectors, size caps, strict YAML schema, no stored credentials, reports git-ignored, only scrubbed lab data public. SARIF puts host findings on the check's YAML file because code scanning needs a file location — a known compromise.

## Limitations (to be honest about in the README)
- Point-in-time audit, not continuous monitoring; drift between runs is shown only by `diff`.
- Configured vs effective state: Posture reads effective settings where it can (`sshd -T`, registry on the DC), but GPOs not yet applied, or other DCs, are not seen; one DC is audited.
- Pending updates are as fresh as the host's package cache (Posture never refreshes it).
- Conditional Access is evaluated structurally (policy targets admins, requires MFA, is enabled), not by simulating sign-ins; exclusions are listed as evidence.
- ~45 checks, a fraction of a full CIS benchmark.

## Stretch goals (not scheduled)
JEA endpoint for the DC · Terraform for an Azure weak/hardened test environment · import Prowler / PingCastle / Lynis results into the same report · ATT&CK Navigator layer export of failed findings · AWS / GCP · Ollama "explain this finding" · compliance score per CIS section · signed reports · Kubernetes (CIS K8s) checks.

## Verification
- Every milestone: `uv run ruff check . && uv run pytest` passes; CI goes green after the push.
- Milestone 4 onward: every check fails on its weak recording and passes on its hardened one.
- Milestone 6: the SARIF upload shows findings in the repo's Security tab; `--fail-on high` passes on the hardened recordings and fails on the weak ones.
- Milestones 5, 7, 9: `lab.sh weak && lab.sh record weak` then `lab.sh hardened && lab.sh record hardened` produce recordings that match the committed ones in their findings; `pytest -m lab` passes against the live VMs.
- Read-only: `test_readonly.py` (command allowlist, sudoers match, GET-only client); in the lab, the hardened VMs' config files have unchanged hashes after an audit.
