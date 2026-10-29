# Graph Report - posture  (2026-10-29)

## Corpus Check
- 40 files · ~43,276 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 9 file(s) not represented in the graph (top: (none) 5, .example 1, .posture 1)

## Summary
- 359 nodes · 902 edges · 16 communities (11 shown, 5 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 131 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `b27ae721`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- transport.py
- parsers/linux.py
- engine.py
- cli.py
- cli.py
- test_engine.py
- pytest
- Posture — plan
- posture
- test_lab_files.py
- test_reports.py
- lab.sh
- guard_lab.sh
- base.sh
- hardened.sh
- weak.sh

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
- `test_replay_ubuntu_weak()` --uses--> `ReplayRunner`  [INFERRED]
  tests/test_collect_linux.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (16 total, 5 thin omitted)

### Community 0 - "transport.py"
Cohesion: 0.05
Nodes (29): Architecture, Commands, Conventions, graphify, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture (+21 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.08
Nodes (45): Result, apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group() (+37 more)

### Community 2 - "engine.py"
Cohesion: 0.14
Nodes (19): _applies(), _compare(), evaluate(), evaluate_all(), FactError, _holds(), _items(), _require() (+11 more)

### Community 3 - "cli.py"
Cohesion: 0.12
Nodes (21): apply_baseline(), diff(), _failing(), gate(), load_report(), _add_outputs(), _add_source(), build_parser() (+13 more)

### Community 4 - "cli.py"
Cohesion: 0.15
Nodes (18): main(), _audit(), test_baseline_accepting_everything_passes_the_gate(), test_collect_evaluate_and_outputs(), test_diff_weak_to_hardened(), test_fail_on_high_gates_weak_and_passes_hardened(), test_help_exits_cleanly(), test_nothing_collected_exits_2() (+10 more)

### Community 5 - "test_engine.py"
Cohesion: 0.14
Nodes (28): Status, make_check(), make_snapshot(), _ids(), _report(), test_baseline_hides_only_accepted_failures(), test_diff_new_fixed_unchanged(), test_fingerprint_ignores_observed_values_but_not_offenders() (+20 more)

### Community 6 - "pytest"
Cohesion: 0.15
Nodes (16): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+8 more)

### Community 7 - "Posture — plan"
Cohesion: 0.09
Nodes (20): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Context, Data model, Folder structure (+12 more)

### Community 9 - "test_lab_files.py"
Cohesion: 0.18
Nodes (6): _guard(), test_every_shell_provisioner_runs_the_guard_first(), test_guard_lab(), test_lab_driver_names_only_posture_vms(), test_only_host_only_network_on_the_lab_subnet(), test_vm_names_hostnames_and_ssh_config_agree()

### Community 10 - "test_reports.py"
Cohesion: 0.16
Nodes (9): _finalize(), render_html(), _report(), test_html_csp_allows_only_its_own_css(), test_html_escapes_hostile_data(), test_json_report_drops_facts_and_round_trips(), test_sarif_is_valid(), test_sarif_points_at_the_check_yaml() (+1 more)

### Community 11 - "lab.sh"
Cohesion: 0.83
Nodes (3): keys(), lab.sh script, usage()

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 93 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `parsers/linux.py` to `transport.py`, `cli.py`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `Result` (e.g. with `collect()` and `Runner`) actually correct?**
  _`Result` has 44 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `transport.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05499735589635114 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `cli.py` to `engine.py`, `cli.py`, `pytest`, `Posture — plan`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `Status` (e.g. with `evaluate()` and `summary()`) actually correct?**
  _`Status` has 22 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07656341320864991 - nodes in this community are weakly interconnected._