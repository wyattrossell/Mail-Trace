"""Machine-readable report."""

from __future__ import annotations

import json
from typing import Any

from mailtrace_core.models import to_jsonable
from mailtrace_core.reporting.models import Report

SCHEMA_VERSION = 1


def report_dict(report: Report) -> dict[str, Any]:
    data = to_jsonable(report)
    data["schema_version"] = SCHEMA_VERSION
    data["format"] = "mailtrace-report"
    return data


def render_json(report: Report) -> str:
    return json.dumps(report_dict(report), indent=2, ensure_ascii=False)
