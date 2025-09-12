import shutil
from dataclasses import asdict
from pathlib import Path

import yaml

from hyperscale.kite.config import Config
from hyperscale.kite.core import Assessment


def generate_html_report() -> str:
    """
    Generate an HTML report by copying the static dashboard and injecting results.

    Returns:
        str: Path to the generated HTML report
    """
    # Load the assessment results
    assessment = Assessment.load()

    # Create the output directory
    config = Config.get()
    report_dir = config.data_dir / "html"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Copy static dashboard files into the report directory
    _copy_dashboard_assets(report_dir)

    # Prepare YAML string and inject into copied files
    assessment_yaml = yaml.safe_dump(asdict(assessment), sort_keys=False)
    injected_string = _to_js_string_literal(assessment_yaml)
    _inject_results_placeholder(report_dir, injected_string)

    # Choose primary HTML file to return
    index_path = report_dir / "index.html"
    if index_path.exists():
        return str(index_path)

    # If no html file exists, raise an error
    raise FileNotFoundError(
        "Dashboard index.html not found in report directory after copying dashboard."
    )


def _copy_dashboard_assets(report_dir: Path) -> None:
    """Copy the static dashboard into the report directory."""
    src_dir = Path(__file__).parent / "dashboard"
    if not src_dir.exists():
        raise FileNotFoundError(f"Dashboard directory not found: {src_dir}")

    # Copy tree, allowing existing directory
    shutil.copytree(src_dir, report_dir, dirs_exist_ok=True)


def _inject_results_placeholder(report_dir: Path, injected_string: str) -> None:
    """Replace placeholder string in index.html within report_dir."""
    placeholder = "PYTHON-SECURE-COMPASS-RESULTS-ONE"
    index_file = report_dir / "index.html"
    if not index_file.exists():
        raise FileNotFoundError(
            "index.html not found in report directory for injection"
        )

    content = index_file.read_text()
    if placeholder not in content:
        raise ValueError("Placeholder not found in index.html for injection")

    content = content.replace(placeholder, injected_string)
    index_file.write_text(content)


def _to_js_string_literal(value: str) -> str:
    """Escape Python string for safe inclusion as a JS double-quoted string.

    - Escapes backslashes and double quotes
    - Normalizes newlines and replaces with \n
    Returns the full JS literal including surrounding quotes.
    """
    # Escape backslashes first
    value = value.replace("\\", "\\\\")
    # Escape double quotes
    value = value.replace('"', '\\"')
    # Normalize newlines to \n
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("\n", "\\n")
    return f"{value}"
