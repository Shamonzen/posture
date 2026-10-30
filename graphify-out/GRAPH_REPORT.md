# Graph Report - posture  (2026-10-30)

## Corpus Check
- 53 files · ~60,531 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 557 nodes · 1364 edges · 34 communities (24 shown, 10 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 187 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `0532c42a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- collectors/ad.py
- parsers/linux.py
- engine.py
- cli.py
- Posture
- test_engine.py
- pytest
- Posture — plan
- posture
- test_lab_files.py
- ReplayRunner
- lab.sh
- guard_lab.sh script
- base.sh
- hardened.sh
- weak.sh
- Get-LabSecret
- test_readonly.py
- parsers/ad.py
- test_collect_azure.py
- parsers/azure.py
- test_collect_ad.py
- Snapshot
- collectors/azure.py
- test_lab.py
- AzureRunner
- transport.py
- Command
- LdapRunner
- read_only_client
- Permissions
- SshRunner
- test_connection_is_ldaps_read_only_and_never_follows_referrals

## God Nodes (most connected - your core abstractions)
1. `Result` - 103 edges
2. `Status` - 27 edges
3. `main()` - 22 edges
4. `run()` - 20 edges
5. `load_checks()` - 19 edges
6. `Snapshot` - 18 edges
7. `Posture — plan` - 18 edges
8. `_collect()` - 15 edges
9. `ReplayRunner` - 15 edges
10. `Report` - 15 edges

## Surprising Connections (you probably didn't know these)
- `Limitations (to be honest about in the README)` --references--> `diff()`  [INFERRED]
  docs/PLAN.md → src/posture/baseline.py
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `_collect()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_checks_weak_hardened.py → src/posture/collectors/transport.py
- `_replay()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_collect_ad.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (34 total, 10 thin omitted)

### Community 0 - "collectors/ad.py"
Cohesion: 0.13
Nodes (9): _days(), _derive(), HostRunner, registry_script(), RegistryRead, Runner, Search, _value() (+1 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.08
Nodes (45): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+37 more)

### Community 2 - "engine.py"
Cohesion: 0.15
Nodes (16): _applies(), _compare(), evaluate(), FactError, _holds(), _items(), _require(), resolve() (+8 more)

### Community 3 - "cli.py"
Cohesion: 0.08
Nodes (29): apply_baseline(), diff(), _failing(), gate(), load_report(), _add_outputs(), _add_source(), build_parser() (+21 more)

### Community 4 - "Posture"
Cohesion: 0.22
Nodes (8): Architecture, Commands, Conventions, graphify, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture

### Community 5 - "test_engine.py"
Cohesion: 0.14
Nodes (29): evaluate_all(), Status, make_check(), make_snapshot(), _ids(), _report(), test_baseline_hides_only_accepted_failures(), test_diff_new_fixed_unchanged() (+21 more)

### Community 6 - "pytest"
Cohesion: 0.11
Nodes (28): CheckError, load_checks(), main(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected() (+20 more)

### Community 7 - "Posture — plan"
Cohesion: 0.09
Nodes (20): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Context, Data model, Folder structure (+12 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.15
Nodes (7): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_guard_lab_ps1(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "ReplayRunner"
Cohesion: 0.23
Nodes (8): ReplayRunner, FakeRunner, test_cli_collect_replay(), test_failures_become_errors_and_distro_filters_commands(), test_hash_never_reaches_recording_or_facts(), test_parse_error_becomes_error(), test_record_then_replay_round_trip(), test_replay_ubuntu_weak()

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

### Community 16 - "Get-LabSecret"
Cohesion: 0.30
Nodes (5): Get-LabAdmin(), Get-LabSecret(), Set-LabGpo(), Set-LabPolicy(), Wait-LabAD()

### Community 18 - "test_readonly.py"
Cohesion: 0.12
Nodes (10): _sudoers_commands(), test_ad_collector_only_reads(), test_azure_client_refuses_anything_but_get(), test_azure_requests_are_fixed_gets_on_arm_or_graph(), test_command_is_read_only(), test_registry_script_only_reads_named_values(), test_ssh_runner_quotes_and_puts_host_after_double_dash(), test_ssh_runner_rejects_option_like_hosts() (+2 more)

### Community 19 - "parsers/ad.py"
Cohesion: 0.18
Nodes (20): _account(), computers(), domain(), enc_types(), _entries(), _filetime(), _flags(), _generalized_time() (+12 more)

### Community 20 - "test_collect_azure.py"
Cohesion: 0.15
Nodes (14): FakeCredential, _request(), _runner(), test_graph_and_arm_paging_are_followed(), handler(), test_http_errors_become_collection_errors(), test_nsg_exposed_admin_ports(), test_oversized_response_is_an_error() (+6 more)

### Community 21 - "parsers/azure.py"
Cohesion: 0.20
Nodes (15): admin_mfa_registration(), authorization_policy(), conditional_access(), _covers(), defender_plans(), derive(), diagnostic_settings(), global_admins() (+7 more)

### Community 22 - "test_collect_ad.py"
Cohesion: 0.15
Nodes (13): _by_name(), FakeRunner, _replay(), test_absent_registry_values_take_the_os_default(), test_certificate_must_name_the_ip(), test_enc_types(), test_failures_and_bad_output_become_errors(), test_filetime_never_and_epoch() (+5 more)

### Community 23 - "Snapshot"
Cohesion: 0.22
Nodes (9): collect(), collect(), collect(), _derive(), _merge(), NotRecorded, write_recording(), CollectError (+1 more)

### Community 25 - "test_lab.py"
Cohesion: 0.21
Nodes (5): _from_repo_root(), _shape(), _ssh(), test_live_audit_is_read_only_and_matches_profile(), test_live_ldaps_and_winrm_audit_matches_a_recording()

### Community 26 - "AzureRunner"
Cohesion: 0.18
Nodes (5): AzureRunner, _error(), Request, _retry_after(), Runner

### Community 27 - "transport.py"
Cohesion: 0.27
Nodes (4): _collect(), _statuses(), test_fails_on_weak_and_passes_on_hardened(), test_recording_collects_cleanly()

### Community 28 - "Command"
Cohesion: 0.27
Nodes (4): Command, LocalRunner, _run(), _with_sudo()

### Community 30 - "read_only_client"
Cohesion: 0.32
Nodes (3): _get_only(), read_only_client(), ReadOnlyViolation

### Community 31 - "Permissions"
Cohesion: 0.33
Nodes (5): Active Directory (LDAP), Azure, Domain controller host settings (WinRM, `--winrm`), Linux, Permissions

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 153 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `collectors/ad.py`, `ReplayRunner`, `parsers/ad.py`, `test_collect_azure.py`, `parsers/azure.py`, `test_collect_ad.py`, `Snapshot`, `collectors/azure.py`, `AzureRunner`, `transport.py`, `Command`, `LdapRunner`?**
  _High betweenness centrality (0.202) - this node is a cross-community bridge._
- **Are the 81 inferred relationships involving `Result` (e.g. with `collect()` and `HostRunner`) actually correct?**
  _`Result` has 81 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `collectors/ad.py` be split into smaller, more focused modules?**
  _Cohesion score 0.13333333333333333 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `pytest` to `ReplayRunner`, `cli.py`, `Snapshot`, `Posture — plan`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `Status` (e.g. with `evaluate()` and `summary()`) actually correct?**
  _`Status` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07656341320864991 - nodes in this community are weakly interconnected._