"""
Executive HTML Security Assessment Report Generator.
Produces modern, visually stunning, self-contained HTML reports featuring dark-mode styling, executive summary metrics, dynamic charts, finding details, evidence lists, and remediation guidance.
"""

from typing import List, Optional
from datetime import datetime, timezone
from lpe_autoscan.models import Finding, Severity
from lpe_autoscan.reporters.base import BaseReporter
from lpe_autoscan import __version__


class HtmlReporter(BaseReporter):
    """Generates professional HTML security assessment reports."""

    def generate(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1

        findings_html_list = []
        for idx, f in enumerate(findings, 1):
            sev_class = f.severity.value.lower()
            evidence_items = "".join([f"<li><code>{ev}</code></li>" for ev in f.evidence])
            references_items = "".join([f'<li><a href="{ref}" target="_blank" rel="noopener">{ref}</a></li>' for ref in f.references])

            findings_html_list.append(f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="finding-id">{f.finding_id}</span>
                    <span class="badge badge-{sev_class}">{f.severity.value}</span>
                    <span class="badge badge-conf">{f.confidence.value} CONFIDENCE</span>
                    <h3 class="finding-title">{f.title}</h3>
                </div>
                <div class="finding-body">
                    <p class="finding-desc">{f.description}</p>
                    <div class="finding-section">
                        <h4>Impact</h4>
                        <p>{f.impact}</p>
                    </div>
                    <div class="finding-section">
                        <h4>Evidence</h4>
                        <ul>{evidence_items}</ul>
                    </div>
                    <div class="finding-section">
                        <h4>Remediation Guidance</h4>
                        <div class="remediation-box">{f.mitigation}</div>
                    </div>
                    {f'<div class="finding-section"><h4>References</h4><ul>{references_items}</ul></div>' if f.references else ''}
                </div>
            </div>
            """)

        findings_html = "".join(findings_html_list) if findings_html_list else "<p>No privilege escalation conditions detected.</p>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LPE-AutoScan Security Assessment Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #06b6d4;
            --border-color: #334155;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .title-area h1 {{
            margin: 0;
            font-size: 1.8rem;
            color: #38bdf8;
        }}
        .title-area p {{
            margin: 0.2rem 0 0 0;
            color: var(--text-muted);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .metric-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2rem;
            font-weight: bold;
            margin-top: 0.3rem;
        }}
        .metric-critical {{ color: var(--critical); }}
        .metric-high {{ color: var(--high); }}
        .metric-medium {{ color: var(--medium); }}
        .metric-low {{ color: var(--low); }}
        .metric-info {{ color: var(--info); }}
        .finding-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 6px solid var(--text-muted);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            padding: 1.5rem;
        }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-card.info {{ border-left-color: var(--info); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.8rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}
        .finding-id {{
            font-family: monospace;
            background: #0f172a;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
            color: #38bdf8;
        }}
        .finding-title {{
            margin: 0;
            font-size: 1.2rem;
            flex-grow: 1;
        }}
        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .badge-info {{ background: rgba(6, 182, 212, 0.2); color: var(--info); border: 1px solid var(--info); }}
        .badge-conf {{ background: #334155; color: #cbd5e1; }}
        .finding-section {{
            margin-top: 1rem;
        }}
        .finding-section h4 {{
            margin: 0 0 0.4rem 0;
            font-size: 0.95rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        code {{
            background-color: #0f172a;
            color: #f1f5f9;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }}
        .remediation-box {{
            background: #064e3b;
            color: #a7f3d0;
            padding: 0.8rem 1rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.9rem;
        }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-area">
                <h1>LPE-AutoScan Assessment Report</h1>
                <p>Detection-Only Linux Privilege Escalation Audit • v{__version__}</p>
            </div>
            <div>
                <p style="text-align: right; margin: 0; color: var(--text-muted);">Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            </div>
        </header>

        <section class="summary-grid">
            <div class="metric-card">
                <div>CRITICAL</div>
                <div class="metric-value metric-critical">{counts['CRITICAL']}</div>
            </div>
            <div class="metric-card">
                <div>HIGH</div>
                <div class="metric-value metric-high">{counts['HIGH']}</div>
            </div>
            <div class="metric-card">
                <div>MEDIUM</div>
                <div class="metric-value metric-medium">{counts['MEDIUM']}</div>
            </div>
            <div class="metric-card">
                <div>LOW</div>
                <div class="metric-value metric-low">{counts['LOW']}</div>
            </div>
            <div class="metric-card">
                <div>INFO</div>
                <div class="metric-value metric-info">{counts['INFO']}</div>
            </div>
        </section>

        <section>
            <h2>Detailed Assessment Findings</h2>
            {findings_html}
        </section>
    </div>
</body>
</html>
"""

        if output_path:
            with open(output_path, "w") as f:
                f.write(html_content)

        return html_content
