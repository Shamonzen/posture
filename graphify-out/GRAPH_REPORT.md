# Graph Report - posture  (2026-10-30)

## Corpus Check
- 49 files · ~51,613 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 450 nodes · 1110 edges · 20 communities (14 shown, 6 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 154 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `0eea931d`
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
- main
- lab.sh
- guard_lab.sh script
- base.sh
- hardened.sh
- weak.sh
- Get-LabSecret
- test_readonly.py
- parsers/ad.py

## God Nodes (most connected - your core abstractions)
1. `Result` - 72 edges
2. `Status` - 27 edges
3. `main()` - 20 edges
4. `run()` - 20 edges
5. `load_checks()` - 19 edges
6. `Posture — plan` - 18 edges
7. `Snapshot` - 16 edges
8. `Report` - 15 edges
9. `CheckError` - 14 edges
10. `_evaluate()` - 14 edges

## Surprising Connections (you probably didn't know these)
- `Limitations (to be honest about in the README)` --references--> `diff()`  [INFERRED]
  docs/PLAN.md → src/posture/baseline.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `test_record_then_replay_round_trip()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_collect_ad.py → src/posture/collectors/transport.py
- `test_replay_ubuntu_weak()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_collect_linux.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (20 total, 6 thin omitted)

### Community 0 - "collectors/ad.py"
Cohesion: 0.05
Nodes (30): collect(), _days(), _derive(), LdapRunner, _names_ip(), Runner, Search, _value() (+22 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.07
Nodes (47): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+39 more)

### Community 2 - "engine.py"
Cohesion: 0.13
Nodes (16): _applies(), _compare(), evaluate(), FactError, _holds(), _items(), _require(), resolve() (+8 more)

### Community 3 - "cli.py"
Cohesion: 0.06
Nodes (33): apply_baseline(), diff(), _failing(), gate(), load_report(), _add_outputs(), _add_source(), build_parser() (+25 more)

### Community 4 - "Posture"
Cohesion: 0.22
Nodes (8): Architecture, Commands, Conventions, graphify, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture

### Community 5 - "test_engine.py"
Cohesion: 0.14
Nodes (29): evaluate_all(), Status, make_check(), make_snapshot(), _ids(), _report(), test_baseline_hides_only_accepted_failures(), test_diff_new_fixed_unchanged() (+21 more)

### Community 6 - "pytest"
Cohesion: 0.24
Nodes (13): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+5 more)

### Community 7 - "Posture — plan"
Cohesion: 0.10
Nodes (19): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Data model, Folder structure, Lab (Vagrant + VirtualBox, no Hyper-V) (+11 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.15
Nodes (7): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_guard_lab_ps1(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "main"
Cohesion: 0.14
Nodes (21): Context, main(), _audit(), test_baseline_accepting_everything_passes_the_gate(), test_collect_evaluate_and_outputs(), test_diff_weak_to_hardened(), test_fail_on_high_gates_weak_and_passes_hardened(), test_help_exits_cleanly() (+13 more)

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

### Community 16 - "Get-LabSecret"
Cohesion: 0.30
Nodes (5): Get-LabAdmin(), Get-LabSecret(), Set-LabGpo(), Set-LabPolicy(), Wait-LabAD()

### Community 18 - "test_readonly.py"
Cohesion: 0.09
Nodes (12): _statuses(), test_fails_on_weak_and_passes_on_hardened(), test_recording_collects_cleanly(), _sudoers_commands(), test_ad_collector_only_reads(), test_command_is_read_only(), test_connection_is_ldaps_read_only_and_never_follows_referrals(), test_ssh_runner_adds_sudo_non_interactive() (+4 more)

### Community 19 - "parsers/ad.py"
Cohesion: 0.21
Nodes (16): _account(), computers(), domain(), enc_types(), _entries(), _filetime(), _flags(), _generalized_time() (+8 more)

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 119 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `collectors/ad.py`, `main`, `parsers/ad.py`?**
  _High betweenness centrality (0.154) - this node is a cross-community bridge._
- **Are the 56 inferred relationships involving `Result` (e.g. with `collect()` and `LdapRunner`) actually correct?**
  _`Result` has 56 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `collectors/ad.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05191146881287726 - nodes in this community are weakly interconnected._
- **Why does `Posture — plan` connect `Posture — plan` to `main`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `Status` (e.g. with `evaluate()` and `summary()`) actually correct?**
  _`Status` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0701484895033282 - nodes in this community are weakly interconnected._