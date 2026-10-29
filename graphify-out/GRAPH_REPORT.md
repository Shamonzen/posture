# Graph Report - posture  (2026-10-29)

## Corpus Check
- 33 files · ~25,729 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 8 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 288 nodes · 646 edges · 16 communities (11 shown, 5 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 97 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `5d3f0d78`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- transport.py
- parsers/linux.py
- engine.py
- collectors/linux.py
- cli.py
- test_engine.py
- pytest
- Posture — plan
- posture
- test_lab_files.py
- Posture
- lab.sh
- guard_lab.sh
- base.sh
- hardened.sh
- weak.sh

## God Nodes (most connected - your core abstractions)
1. `Result` - 55 edges
2. `run()` - 20 edges
3. `Status` - 19 edges
4. `Posture — plan` - 18 edges
5. `load_checks()` - 17 edges
6. `_lines()` - 14 edges
7. `collect()` - 13 edges
8. `Command` - 13 edges
9. `CheckError` - 12 edges
10. `_holds()` - 12 edges

## Surprising Connections (you probably didn't know these)
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `Architecture` --references--> `collect()`  [INFERRED]
  CLAUDE.md → src/posture/collectors/linux.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `FakeRunner` --uses--> `Result`  [INFERRED]
  tests/test_collect_linux.py → src/posture/collectors/transport.py
- `test_failures_become_errors_and_distro_filters_commands()` --uses--> `Result`  [INFERRED]
  tests/test_collect_linux.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (16 total, 5 thin omitted)

### Community 0 - "transport.py"
Cohesion: 0.09
Nodes (17): Command, _run(), SshRunner, _with_sudo(), _from_repo_root(), _ssh(), test_live_audit_is_read_only_and_matches_profile(), _statuses() (+9 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.08
Nodes (45): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+37 more)

### Community 2 - "engine.py"
Cohesion: 0.13
Nodes (20): _applies(), _compare(), evaluate(), evaluate_all(), FactError, _holds(), _items(), _require() (+12 more)

### Community 3 - "collectors/linux.py"
Cohesion: 0.13
Nodes (6): collect(), _derive(), _merge(), Runner, NotRecorded, write_recording()

### Community 4 - "cli.py"
Cohesion: 0.12
Nodes (14): Context, build_parser(), main(), LocalRunner, ReplayRunner, test_help_exits_cleanly(), test_version(), FakeRunner (+6 more)

### Community 5 - "test_engine.py"
Cohesion: 0.17
Nodes (22): Severity, Status, make_check(), make_snapshot(), run(), test_all_and_any(), test_any_with_uncollected_branch_is_error(), test_applies_to_skips() (+14 more)

### Community 6 - "pytest"
Cohesion: 0.24
Nodes (13): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+5 more)

### Community 7 - "Posture — plan"
Cohesion: 0.10
Nodes (19): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Data model, Folder structure, Lab (Vagrant + VirtualBox, no Hyper-V) (+11 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.20
Nodes (6): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "Posture"
Cohesion: 0.25
Nodes (7): Architecture, Commands, Conventions, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 76 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `transport.py`, `collectors/linux.py`, `cli.py`?**
  _High betweenness centrality (0.189) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `Result` (e.g. with `collect()` and `Runner`) actually correct?**
  _`Result` has 44 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `transport.py` be split into smaller, more focused modules?**
  _Cohesion score 0.09388335704125178 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `cli.py` to `transport.py`, `collectors/linux.py`?**
  _High betweenness centrality (0.149) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `Status` (e.g. with `evaluate()` and `test_live_audit_is_read_only_and_matches_profile()`) actually correct?**
  _`Status` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07656341320864991 - nodes in this community are weakly interconnected._