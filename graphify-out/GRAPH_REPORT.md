# Graph Report - posture  (2026-10-29)

## Corpus Check
- 46 files · ~45,253 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 376 nodes · 928 edges · 18 communities (12 shown, 6 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 141 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d6484646`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- transport.py
- parsers/linux.py
- engine.py
- cli.py
- collectors/linux.py
- test_engine.py
- pytest
- Posture — plan
- posture
- test_lab_files.py
- test_reports.py
- lab.sh
- guard_lab.sh script
- base.sh
- hardened.sh
- weak.sh
- Get-LabSecret

## God Nodes (most connected - your core abstractions)
1. `Result` - 55 edges
2. `Status` - 27 edges
3. `run()` - 20 edges
4. `load_checks()` - 19 edges
5. `main()` - 18 edges
6. `Posture — plan` - 18 edges
7. `Report` - 15 edges
8. `CheckError` - 14 edges
9. `_evaluate()` - 14 edges
10. `Snapshot` - 14 edges

## Surprising Connections (you probably didn't know these)
- `Limitations (to be honest about in the README)` --references--> `diff()`  [INFERRED]
  docs/PLAN.md → src/posture/baseline.py
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `Architecture` --references--> `collect()`  [INFERRED]
  CLAUDE.md → src/posture/collectors/linux.py
- `FakeRunner` --uses--> `Result`  [INFERRED]
  tests/test_collect_linux.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (18 total, 6 thin omitted)

### Community 0 - "transport.py"
Cohesion: 0.07
Nodes (24): Command, NotRecorded, ReplayRunner, _run(), SshRunner, _with_sudo(), _from_repo_root(), _ssh() (+16 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.08
Nodes (45): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+37 more)

### Community 2 - "engine.py"
Cohesion: 0.14
Nodes (17): _applies(), _compare(), evaluate(), FactError, _holds(), _items(), _require(), resolve() (+9 more)

### Community 3 - "cli.py"
Cohesion: 0.10
Nodes (31): apply_baseline(), diff(), _failing(), gate(), load_report(), _add_outputs(), _add_source(), build_parser() (+23 more)

### Community 4 - "collectors/linux.py"
Cohesion: 0.10
Nodes (13): Architecture, Commands, Conventions, graphify, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture (+5 more)

### Community 5 - "test_engine.py"
Cohesion: 0.14
Nodes (29): evaluate_all(), Status, make_check(), make_snapshot(), _ids(), _report(), test_baseline_hides_only_accepted_failures(), test_diff_new_fixed_unchanged() (+21 more)

### Community 6 - "pytest"
Cohesion: 0.22
Nodes (13): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+5 more)

### Community 7 - "Posture — plan"
Cohesion: 0.09
Nodes (20): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Context, Data model, Folder structure (+12 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.15
Nodes (7): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_guard_lab_ps1(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "test_reports.py"
Cohesion: 0.11
Nodes (13): _finalize(), render_html(), render_sarif(), _rule(), test_cli_collect_replay(), test_record_then_replay_round_trip(), _report(), test_html_csp_allows_only_its_own_css() (+5 more)

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

### Community 16 - "Get-LabSecret"
Cohesion: 0.30
Nodes (5): Get-LabAdmin(), Get-LabSecret(), Set-LabGpo(), Set-LabPolicy(), Wait-LabAD()

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 99 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `transport.py`, `collectors/linux.py`?**
  _High betweenness centrality (0.119) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `Result` (e.g. with `collect()` and `Runner`) actually correct?**
  _`Result` has 44 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `transport.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0660377358490566 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `cli.py` to `test_reports.py`, `pytest`, `Posture — plan`?**
  _High betweenness centrality (0.076) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `Status` (e.g. with `evaluate()` and `summary()`) actually correct?**
  _`Status` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07656341320864991 - nodes in this community are weakly interconnected._