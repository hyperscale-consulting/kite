from datetime import datetime
from pathlib import Path
from typing import Any

from hyperscale.kite.config import Config
from hyperscale.kite.core import Assessment


def generate_html_report() -> str:
    """
    Generate an HTML report from kite-results.yaml.

    Returns:
        str: Path to the generated HTML report
    """
    # Load the assessment results
    assessment = Assessment.load()

    # Create the output directory
    config = Config.get()
    report_dir = config.data_dir / "html"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Generate the HTML content
    html_content = _generate_html_content(assessment)

    # Write the HTML file
    report_path = report_dir / "report.html"
    with open(report_path, "w") as f:
        f.write(html_content)

    # Copy CSS and JS assets
    _copy_assets(report_dir)

    return str(report_path)


def _generate_html_content(assessment: Assessment) -> str:
    themes = assessment.themes
    timestamp = assessment.timestamp

    # Calculate summary statistics
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    error_checks = 0

    for _, findings in themes.items():
        for finding in findings:
            total_checks += 1
            status = finding.get("status", "UNKNOWN")
            if status == "PASS":
                passed_checks += 1
            elif status == "FAIL":
                failed_checks += 1
            elif status == "ERROR":
                error_checks += 1

    # Generate the HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kite Security Assessment Report</title>
    <link rel="stylesheet" href="styles.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🪁 Kite Security Assessment Report</h1>
            <p class="timestamp">Generated on {_format_timestamp(timestamp)}</p>
        </header>

        <div class="summary-section">
            <h2>Executive Summary</h2>
            <div class="summary-cards">
                <div class="summary-card total">
                    <div class="card-number">{total_checks}</div>
                    <div class="card-label">Total Checks</div>
                </div>
                <div class="summary-card pass">
                    <div class="card-number">{passed_checks}</div>
                    <div class="card-label">Passed</div>
                </div>
                <div class="summary-card fail">
                    <div class="card-number">{failed_checks}</div>
                    <div class="card-label">Failed</div>
                </div>
                <div class="summary-card error">
                    <div class="card-number">{error_checks}</div>
                    <div class="card-label">Errors</div>
                </div>
            </div>

            <div class="chart-container">
                <canvas id="statusChart" width="400" height="200"></canvas>
            </div>
        </div>

        <div class="themes-section">
            <h2>Assessment Results by Theme</h2>
            {_generate_themes_html(themes)}
        </div>
    </div>

    <script src="script.js"></script>
    <script>
        // Initialize the chart
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Passed', 'Failed', 'Errors'],
                datasets: [{{
                    data: [{passed_checks}, {failed_checks}, {error_checks}],
                    backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    return html


def _generate_themes_html(themes: dict[str, list[dict[str, Any]]]) -> str:
    themes_html = ""

    for theme_name, findings in themes.items():
        themes_html += f"""
            <div class="theme-section">
                <h3 class="theme-title">{theme_name}</h3>
                <div class="findings-container">
                    {_generate_findings_html(findings)}
                </div>
            </div>
        """

    return themes_html


def _generate_findings_html(findings: list[dict[str, Any]]) -> str:
    findings_html = ""

    for finding in findings:
        status = finding.get("status", "UNKNOWN")
        check_id = finding.get("check_id", "")
        check_name = finding.get("check_name", "")
        description = finding.get("description", "")
        reason = finding.get("reason", "")

        status_class = status.lower()
        status_icon = _get_status_icon(status)

        findings_html += f"""
            <div class="finding-card {status_class}">
                <div class="finding-header">
                    <div class="finding-status">
                        <span class="status-icon">{status_icon}</span>
                        <span class="status-text">{status}</span>
                    </div>
                    <div class="finding-id">{check_id}</div>
                </div>
                <div class="finding-content">
                    <h4 class="finding-title">{check_name}</h4>
                    <p class="finding-description">{description}</p>
                    <div class="finding-reason">
                        <strong>Reason:</strong> {reason}
                    </div>
                </div>
            </div>
        """

    return findings_html


def _get_status_icon(status: str) -> str:
    """Get the appropriate icon for a status."""
    icons = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "UNKNOWN": "❓"}
    return icons.get(status, "❓")


def _format_timestamp(timestamp: str) -> str:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %I:%M %p")
    except (ValueError, TypeError):
        return timestamp


def _copy_assets(report_dir: Path):
    # Create CSS file
    css_content = _get_css_content()
    css_path = report_dir / "styles.css"
    with open(css_path, "w") as f:
        f.write(css_content)

    # Create JS file
    js_content = _get_js_content()
    js_path = report_dir / "script.js"
    with open(js_path, "w") as f:
        f.write(js_content)


def _get_css_content() -> str:
    return """/* Kite Security Assessment Report Styles */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                 Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f8fafc;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    text-align: center;
    margin-bottom: 40px;
    padding: 30px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.header h1 {
    font-size: 2.5rem;
    margin-bottom: 10px;
    font-weight: 700;
}

.timestamp {
    font-size: 1.1rem;
    opacity: 0.9;
}

.summary-section {
    background: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 30px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.summary-section h2 {
    margin-bottom: 20px;
    color: #1f2937;
    font-size: 1.8rem;
}

.summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.summary-card {
    padding: 20px;
    border-radius: 8px;
    text-align: center;
    color: white;
    font-weight: 600;
}

.summary-card.total {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.summary-card.pass {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
}

.summary-card.fail {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
}

.summary-card.error {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
}

.card-number {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 5px;
}

.card-label {
    font-size: 1rem;
    opacity: 0.9;
}

.chart-container {
    height: 300px;
    margin-top: 20px;
}

.themes-section {
    background: white;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.themes-section h2 {
    margin-bottom: 30px;
    color: #1f2937;
    font-size: 1.8rem;
}

.theme-section {
    margin-bottom: 40px;
}

.theme-title {
    font-size: 1.5rem;
    color: #374151;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 2px solid #e5e7eb;
}

.findings-container {
    display: grid;
    gap: 20px;
}

.finding-card {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 20px;
    transition: all 0.3s ease;
}

.finding-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.finding-card.pass {
    border-left: 4px solid #10b981;
    background-color: #f0fdf4;
}

.finding-card.fail {
    border-left: 4px solid #ef4444;
    background-color: #fef2f2;
}

.finding-card.error {
    border-left: 4px solid #f59e0b;
    background-color: #fffbeb;
}

.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.finding-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
}

.status-icon {
    font-size: 1.2rem;
}

.finding-id {
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
    color: #6b7280;
    background-color: #f3f4f6;
    padding: 4px 8px;
    border-radius: 4px;
}

.finding-title {
    font-size: 1.2rem;
    color: #1f2937;
    margin-bottom: 10px;
    font-weight: 600;
}

.finding-description {
    color: #4b5563;
    margin-bottom: 15px;
    line-height: 1.6;
}

.finding-reason {
    background-color: #f9fafb;
    padding: 12px;
    border-radius: 6px;
    border-left: 3px solid #d1d5db;
}

.finding-reason strong {
    color: #374151;
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }

    .header h1 {
        font-size: 2rem;
    }

    .summary-cards {
        grid-template-columns: repeat(2, 1fr);
    }

    .finding-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
}

@media (max-width: 480px) {
    .summary-cards {
        grid-template-columns: 1fr;
    }

    .card-number {
        font-size: 2rem;
    }
}"""


def _get_js_content() -> str:
    """Get the JavaScript content for the report."""
    return """// Kite Security Assessment Report JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add animation to summary cards
    const cards = document.querySelectorAll('.summary-card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
        card.classList.add('animate-in');
    });

    // Add animation to finding cards
    const findingCards = document.querySelectorAll('.finding-card');
    findingCards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.05}s`;
        card.classList.add('animate-in');
    });
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    .animate-in {
        animation: fadeInUp 0.6s ease-out forwards;
        opacity: 0;
        transform: translateY(20px);
    }

    @keyframes fadeInUp {
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);"""
