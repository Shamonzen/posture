"""One static HTML file: no JavaScript, inline CSS allowed only by its hash."""

import base64
import hashlib
import json
from importlib.resources import files
from typing import Any

from jinja2 import Environment, PackageLoader
from markupsafe import Markup

from posture.models import BENCHMARKS, Report
from posture.reports import BY_SEVERITY, FAILING, clean


def _finalize(value: Any) -> Any:
    # Every {{ }} goes through here, then autoescape: collected text loses control characters.
    return clean(value) if isinstance(value, str) and not isinstance(value, Markup) else value


def _attack_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


_ENV = Environment(
    loader=PackageLoader("posture.reports"),
    autoescape=True,
    finalize=_finalize,
    trim_blocks=True,
    lstrip_blocks=True,
)
_ENV.filters["pretty"] = lambda value: (
    value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False)
)
_ENV.filters["attack_url"] = _attack_url


def render_html(report: Report) -> str:
    css = (files("posture.reports") / "templates" / "report.css").read_text(encoding="utf-8")
    digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    failing = [f for f in report.findings if f.status in FAILING]
    return _ENV.get_template("report.html").render(
        report=report,
        targets=", ".join(s.target for s in report.snapshots),
        errors=[(s.target, e) for s in report.snapshots for e in s.errors],
        # Markup on our own packaged CSS, never on collected data.
        css=Markup(css),  # noqa: S704  # nosec B704
        csp=f"default-src 'none'; style-src 'sha256-{digest}'",
        groups=[(s, [f for f in failing if f.severity == s]) for s in BY_SEVERITY],
        passed=[f for f in report.findings if f.status not in FAILING],
        benchmarks=BENCHMARKS,
    )
