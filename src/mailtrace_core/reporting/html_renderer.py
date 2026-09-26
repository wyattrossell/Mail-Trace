"""Self-contained HTML report (inline CSS, inline SVG route diagram, embedded logo)."""

from __future__ import annotations

import base64
import mimetypes
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from mailtrace_core.reporting.models import Report
from mailtrace_core.reporting.route_diagram import route_svg
from mailtrace_core.util.defang import defang_email, defang_ip, defang_url

_env = Environment(
    loader=PackageLoader("mailtrace_core.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=False,
    lstrip_blocks=False,
)
_env.filters["defang_email"] = defang_email
_env.filters["defang_ip"] = defang_ip
_env.filters["defang_url"] = defang_url


def _logo_data_uri(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 2_000_000:
        return ""
    mime = mimetypes.guess_type(p.name)[0] or "image/png"
    return f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode("ascii")


def render_html(report: Report) -> str:
    pe = report.result.email
    recipient = pe.to[0].address if pe.to else None
    template = _env.get_template("report.html.j2")
    return template.render(
        r=report,
        m=report.meta,
        v=report.verdict,
        pe=pe,
        au=pe.auth,
        en=report.result.enrichment,
        route_svg=route_svg(pe.hops, recipient),
        logo_data=_logo_data_uri(report.meta.logo_path),
    )
