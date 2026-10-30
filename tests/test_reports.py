import base64
import hashlib
import json
import re
from pathlib import Path

import jsonschema
import pytest
from conftest import make_check, make_snapshot

from posture.checks import load_checks
from posture.collectors import linux
from posture.collectors.transport import ReplayRunner
from posture.engine import evaluate_all
from posture.models import CollectError, Status
from posture.reports import build_report, summary
from posture.reports.html import render_html
from posture.reports.sarif import render_sarif

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
CHECKS = load_checks(ROOT / "checks")
SCRIPT = "<script>alert(1)</script>"
ANSI = "\x1b[2J\x1b]0;pwned\x07"


def _report(name):
    snapshot = linux.collect(ReplayRunner(FIXTURES / "recordings" / name))
    return build_report([snapshot], evaluate_all(CHECKS, snapshot))


@pytest.fixture
def hostile():
    """Collected data an attacker controls: a username, a hostname and a command's stderr."""
    check = make_check(
        {"for_each": "users", "key": "name", "where": {"fact": "uid", "op": "eq", "value": 0}}
    )
    snapshot = make_snapshot({"users": [{"name": SCRIPT + ANSI, "uid": 0}]}).model_copy(
        update={
            "target": f"host{ANSI}<img src=x>",
            "errors": [CollectError(source="sshd", message=f"exit 1: {SCRIPT}{ANSI}")],
        }
    )
    return build_report([snapshot], evaluate_all([check], snapshot))


def test_html_escapes_hostile_data(hostile):
    html = render_html(hostile)
    assert hostile.findings[0].status == Status.FAIL
    assert "<script" not in html and "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "\x1b" not in html and "\x07" not in html


def test_html_csp_allows_only_its_own_css():
    html = render_html(_report("ubuntu-weak"))
    css = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    assert f"default-src &#39;none&#39;; style-src &#39;sha256-{digest}&#39;" in html
    assert "<script" not in html and " style=" not in html


def test_terminal_summary_strips_control_characters(hostile):
    text = summary(hostile)
    assert "\x1b" not in text and "\x07" not in text
    assert "1 fail" in text


def test_json_report_drops_facts_and_round_trips():
    report = _report("ubuntu-weak")
    assert report.snapshots[0].facts == {}
    assert type(report).model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize("name", ["ubuntu-weak", "rocky-hardened"])
def test_sarif_is_valid(name):
    schema = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    report = _report(name)
    sarif = json.loads(render_sarif(report, CHECKS))
    jsonschema.validate(sarif, schema)
    [run] = sarif["runs"]
    failed = [f for f in report.findings if f.status == Status.FAIL]
    assert len(run["results"]) == len(failed)
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rules == {c.id for c in CHECKS if c.platform == report.snapshots[0].platform}


def test_sarif_points_at_the_check_yaml():
    sarif = json.loads(render_sarif(_report("ubuntu-weak"), CHECKS))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "LNX-SSH-001")
    location = result["locations"][0]["physicalLocation"]
    path, line = location["artifactLocation"]["uri"], location["region"]["startLine"]
    assert (ROOT / path).read_text(encoding="utf-8").splitlines()[line - 1] == "- id: LNX-SSH-001"
    assert result["message"]["text"].startswith("posture-ubuntu: ")
    assert result["partialFingerprints"]["postureFingerprint/v1"]


def test_combined_report_names_every_target_and_keeps_sarif_valid():
    snapshots = [
        linux.collect(ReplayRunner(FIXTURES / "recordings" / n))
        for n in ("ubuntu-weak", "rocky-weak")
    ]
    report = build_report(snapshots, [f for s in snapshots for f in evaluate_all(CHECKS, s)])
    html, text = render_html(report), summary(report)
    assert all(t in html and t in text for t in ("posture-ubuntu", "posture-rocky"))
    schema = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    sarif = json.loads(render_sarif(report, CHECKS))
    jsonschema.validate(sarif, schema)
    targets = {r["properties"]["target"] for r in sarif["runs"][0]["results"]}
    assert targets == {"posture-ubuntu", "posture-rocky"}
