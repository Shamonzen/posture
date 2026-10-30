# Graph Report - posture  (2026-10-30)

## Corpus Check
- 54 files · ~68,664 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 572 nodes · 1416 edges · 31 communities (24 shown, 7 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 191 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `dc87ec1b`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- collect
- parsers/linux.py
- engine.py
- cli.py
- WinrmRunner
- test_engine.py
- pytest
- Posture — plan
- posture
- test_lab_files.py
- json
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
- collectors/ad.py
- test_lab.py
- AzureRunner
- Command
- _names_ip
- read_only_client
- Permissions
- test_connection_is_ldaps_read_only_and_never_follows_referrals

## God Nodes (most connected - your core abstractions)
1. `Result` - 103 edges
2. `main()` - 27 edges
3. `Status` - 27 edges
4. `run()` - 20 edges
5. `load_checks()` - 19 edges
6. `Snapshot` - 19 edges
7. `Posture — plan` - 18 edges
8. `_collect()` - 16 edges
9. `ReplayRunner` - 16 edges
10. `Report` - 16 edges

## Surprising Connections (you probably didn't know these)
- `Limitations (to be honest about in the README)` --references--> `diff()`  [INFERRED]
  docs/PLAN.md → src/posture/baseline.py
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `Milestones (each one sitting = one commit)` --references--> `subscription()`  [INFERRED]
  docs/PLAN.md → src/posture/parsers/azure.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `test_record_then_replay_round_trip()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_collect_azure.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (31 total, 7 thin omitted)

### Community 0 - "collect"
Cohesion: 0.14
Nodes (6): collect(), HostRunner, LdapRunner, Runner, Search, _value()

### Community 1 - "parsers/linux.py"
Cohesion: 0.08
Nodes (45): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+37 more)

### Community 2 - "engine.py"
Cohesion: 0.08
Nodes (26): Architecture, Commands, Conventions, graphify, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture (+18 more)

### Community 3 - "cli.py"
Cohesion: 0.07
Nodes (34): apply_baseline(), diff(), _failing(), gate(), load_report(), _add_outputs(), _add_source(), build_parser() (+26 more)

### Community 4 - "WinrmRunner"
Cohesion: 0.29
Nodes (3): registry_script(), RegistryRead, WinrmRunner

### Community 5 - "test_engine.py"
Cohesion: 0.14
Nodes (29): Status, make_check(), make_snapshot(), _ids(), _report(), test_baseline_hides_only_accepted_failures(), test_diff_new_fixed_unchanged(), test_fingerprint_ignores_observed_values_but_not_offenders() (+21 more)

### Community 6 - "pytest"
Cohesion: 0.24
Nodes (13): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+5 more)

### Community 7 - "Posture — plan"
Cohesion: 0.09
Nodes (20): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Context, Data model, Folder structure (+12 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.15
Nodes (7): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_guard_lab_ps1(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "json"
Cohesion: 0.14
Nodes (22): main(), _audit(), test_bad_inventory_exits_2(), test_baseline_accepting_everything_passes_the_gate(), test_collect_evaluate_and_outputs(), test_diff_weak_to_hardened(), test_fail_on_high_gates_weak_and_passes_hardened(), test_help_exits_cleanly() (+14 more)

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

### Community 16 - "Get-LabSecret"
Cohesion: 0.30
Nodes (5): Get-LabAdmin(), Get-LabSecret(), Set-LabGpo(), Set-LabPolicy(), Wait-LabAD()

### Community 18 - "test_readonly.py"
Cohesion: 0.13
Nodes (9): _sudoers_commands(), test_ad_collector_only_reads(), test_azure_client_refuses_anything_but_get(), test_azure_requests_are_fixed_gets_on_arm_or_graph(), test_command_is_read_only(), test_registry_script_only_reads_named_values(), test_ssh_runner_rejects_option_like_hosts(), test_sudoers_has_no_wildcards_or_all() (+1 more)

### Community 19 - "parsers/ad.py"
Cohesion: 0.18
Nodes (20): _account(), computers(), domain(), enc_types(), _entries(), _filetime(), _flags(), _generalized_time() (+12 more)

### Community 20 - "test_collect_azure.py"
Cohesion: 0.13
Nodes (16): FakeCredential, _request(), _runner(), test_cli_collect_azure_replay(), test_cli_rejects_subscription_for_other_platforms(), test_graph_and_arm_paging_are_followed(), handler(), test_http_errors_become_collection_errors() (+8 more)

### Community 21 - "parsers/azure.py"
Cohesion: 0.20
Nodes (15): admin_mfa_registration(), authorization_policy(), conditional_access(), _covers(), defender_plans(), derive(), diagnostic_settings(), global_admins() (+7 more)

### Community 22 - "test_collect_ad.py"
Cohesion: 0.08
Nodes (17): ReplayRunner, _collect(), test_recording_collects_cleanly(), _by_name(), FakeRunner, _replay(), test_absent_registry_values_take_the_os_default(), test_certificate_must_name_the_ip() (+9 more)

### Community 23 - "collectors/ad.py"
Cohesion: 0.18
Nodes (8): collect(), collect(), _derive(), _merge(), NotRecorded, write_recording(), CollectError, Snapshot

### Community 25 - "test_lab.py"
Cohesion: 0.21
Nodes (6): _from_repo_root(), _shape(), _ssh(), test_live_audit_is_read_only_and_matches_profile(), test_live_inventory_audits_all_three_vms(), test_live_ldaps_and_winrm_audit_matches_a_recording()

### Community 26 - "AzureRunner"
Cohesion: 0.18
Nodes (5): AzureRunner, _error(), Request, _retry_after(), Runner

### Community 28 - "Command"
Cohesion: 0.21
Nodes (8): Runner, Command, LocalRunner, _run(), SshRunner, _with_sudo(), test_ssh_runner_adds_sudo_non_interactive(), test_ssh_runner_quotes_and_puts_host_after_double_dash()

### Community 29 - "_names_ip"
Cohesion: 0.33
Nodes (3): _days(), _derive(), _names_ip()

### Community 30 - "read_only_client"
Cohesion: 0.32
Nodes (3): _get_only(), read_only_client(), ReadOnlyViolation

### Community 31 - "Permissions"
Cohesion: 0.33
Nodes (5): Active Directory (LDAP), Azure, Domain controller host settings (WinRM, `--winrm`), Linux, Permissions

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 155 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `collect`, `WinrmRunner`, `json`, `parsers/ad.py`, `test_collect_azure.py`, `parsers/azure.py`, `test_collect_ad.py`, `collectors/ad.py`, `AzureRunner`, `Command`?**
  _High betweenness centrality (0.210) - this node is a cross-community bridge._
- **Are the 81 inferred relationships involving `Result` (e.g. with `collect()` and `HostRunner`) actually correct?**
  _`Result` has 81 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `collect` be split into smaller, more focused modules?**
  _Cohesion score 0.14166666666666666 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `json` to `cli.py`, `pytest`, `Posture — plan`, `test_collect_azure.py`, `test_collect_ad.py`, `collectors/ad.py`, `test_lab.py`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `main()` (e.g. with `Context` and `CheckError`) actually correct?**
  _`main()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07656341320864991 - nodes in this community are weakly interconnected._