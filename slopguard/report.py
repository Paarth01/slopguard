"""Generates HTML and JSON reports from a ScanResult."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from slopguard.models import ScanResult

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(result=result, counts=result.summary_counts())


def write_reports(result: ScanResult, output_dir: str = "out") -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_path = out / "report.html"
    html_path.write_text(render_html(result), encoding="utf-8")

    json_path = out / "report.json"
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    return html_path, json_path
