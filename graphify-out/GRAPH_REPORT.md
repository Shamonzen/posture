# Graph Report - posture  (2026-10-29)

## Corpus Check
- 24 files · ~15,045 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 3, .example 1, .posture 1)

## Summary
- 255 nodes · 590 edges · 9 communities (8 shown, 1 thin omitted)
- Extraction: 84% EXTRACTED · 16% INFERRED · 0% AMBIGUOUS · INFERRED: 95 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `028673e6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- transport.py
- parsers/linux.py
- engine.py
- collectors/linux.py
- Result
- test_engine.py
- pytest
- Posture — plan
- posture

## God Nodes (most connected - your core abstractions)
1. `Result` - 55 edges
2. `run()` - 20 edges
3. `Status` - 18 edges
4. `Posture — plan` - 18 edges
5. `load_checks()` - 16 edges
6. `_lines()` - 14 edges
7. `collect()` - 13 edges
8. `Command` - 13 edges
9. `CheckError` - 12 edges
10. `_holds()` - 12 edges

## Surprising Connections (you probably didn't know these)
- `Context` --references--> `main()`  [INFERRED]
  docs/PLAN.md → src/posture/cli.py
- `Architecture` --references--> `evaluate()`  [INFERRED]
  CLAUDE.md → src/posture/engine.py
- `Architecture` --references--> `collect()`  [INFERRED]
  CLAUDE.md → src/posture/collectors/linux.py
- `test_apt_unattended()` --uses--> `Result`  [INFERRED]
  tests/test_parsers_linux.py → src/posture/collectors/transport.py
- `test_dnf_security()` --uses--> `Result`  [INFERRED]
  tests/test_parsers_linux.py → src/posture/collectors/transport.py

## Import Cycles
- None detected.

## Communities (9 total, 1 thin omitted)

### Community 0 - "transport.py"
Cohesion: 0.07
Nodes (24): Context, build_parser(), main(), LocalRunner, ReplayRunner, _run(), SshRunner, _with_sudo() (+16 more)

### Community 1 - "parsers/linux.py"
Cohesion: 0.12
Nodes (25): apt_unattended(), apt_upgrade(), auditctl(), cache_mtime(), dnf_security(), firewalld(), group(), hostname() (+17 more)

### Community 2 - "engine.py"
Cohesion: 0.13
Nodes (20): _applies(), _compare(), evaluate(), evaluate_all(), FactError, _holds(), _items(), _require() (+12 more)

### Community 3 - "collectors/linux.py"
Cohesion: 0.10
Nodes (13): Architecture, Commands, Conventions, Hard rule 1: read-only, Hard rule 2: lab only for the weak profile, Hard rule 3: touch only this project's VMs, Posture, collect() (+5 more)

### Community 4 - "Result"
Cohesion: 0.13
Nodes (24): Result, FakeRunner, test_failures_become_errors_and_distro_filters_commands(), test_hash_never_reaches_recording_or_facts(), test_parse_error_becomes_error(), test_apt_unattended(), test_auditctl(), test_auditctl_sudo_refused_is_error() (+16 more)

### Community 5 - "test_engine.py"
Cohesion: 0.17
Nodes (22): Severity, Status, make_check(), make_snapshot(), run(), test_all_and_any(), test_any_with_uncollected_branch_is_error(), test_applies_to_skips() (+14 more)

### Community 6 - "pytest"
Cohesion: 0.22
Nodes (13): CheckError, load_checks(), test_cis_must_be_stated(), test_cis_null_needs_references(), test_duplicate_id_across_files(), test_for_each_needs_key_and_where(), test_invalid_check_rejected(), test_missing_directory() (+5 more)

### Community 7 - "Posture — plan"
Cohesion: 0.10
Nodes (19): 5 decisions an interviewer will question, Architecture, Check format, Checks (first set; ~45 total), CI (`.github/workflows/ci.yml`, from milestone 1), Data model, Folder structure, Lab (Vagrant + VirtualBox, no Hyper-V) (+11 more)

## Knowledge Gaps
- **1 isolated node(s):** `posture`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 63 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Result` connect `Result` to `transport.py`, `parsers/linux.py`, `collectors/linux.py`?**
  _High betweenness centrality (0.230) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `Result` (e.g. with `collect()` and `Runner`) actually correct?**
  _`Result` has 44 INFERRED edges - model-reasoned connections that need verification._
- **What connects `posture` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `transport.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06638714185883997 - nodes in this community are weakly interconnected._
- **Why does `main()` connect `transport.py` to `collectors/linux.py`?**
  _High betweenness centrality (0.176) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `Status` (e.g. with `evaluate()` and `_statuses()`) actually correct?**
  _`Status` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Should `parsers/linux.py` be split into smaller, more focused modules?**
  _Cohesion score 0.11904761904761904 - nodes in this community are weakly interconnected._