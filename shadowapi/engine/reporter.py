"""
CLI and Standalone Interactive HTML5 Report Generator for ShadowAPI.
"""

import json
from shadowapi.core.models import DriftReport


class ReportGenerator:
    """Renders DriftReports to terminal, JSON, and standalone HTML5 dashboards."""

    @staticmethod
    def print_terminal_summary(report: DriftReport):
        print("\n" + "=" * 76)
        print("🔍 [SHADOWAPI] API DRIFT & ZOMBIE ENDPOINT ANALYSIS REPORT")
        print("=" * 76)
        print(f"  Observed Transactions:    {report.total_transactions}")
        print(f"  Observed Endpoints:       {report.observed_endpoints_count}")
        print(f"  Declared Endpoints:       {report.declared_endpoints_count}")
        print(f"  Total Drift Findings:     {len(report.findings)}")

        score_color = "🟢" if report.risk_score < 30 else ("🟡" if report.risk_score < 70 else "🔴")
        print(f"  API Surface Risk Score:   {score_color} {report.risk_score}/100")
        print("-" * 76)

        if not report.findings:
            print("  ✅ No shadow endpoints or schema drift detected! APIs in full compliance.")
        else:
            for idx, f in enumerate(report.findings, 1):
                sev_badge = {
                    "CRITICAL": "💥 CRITICAL",
                    "HIGH": "🚨 HIGH    ",
                    "MEDIUM": "⚠️  MEDIUM  ",
                    "LOW": "ℹ️  LOW     ",
                }.get(f.severity, f.severity)
                print(f"[{idx:02d}] {sev_badge} | {f.drift_type.value:<22} | {f.method:<6} {f.path}")
                print(f"     Description: {f.description}")
                if f.details:
                    print(f"     Details:     {json.dumps(f.details)}")
                print()

        print("=" * 76 + "\n")

    @staticmethod
    def generate_html_report(report: DriftReport, title: str = "ShadowAPI Drift Audit Report") -> str:
        report_data_json = json.dumps(report.to_dict())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --success: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
    .stat-title {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }}
    .risk-score {{ color: {("#ef4444" if report.risk_score >= 70 else ("#f59e0b" if report.risk_score >= 30 else "#10b981"))}; }}
    .findings-section {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }}
    .findings-header {{ font-size: 1.2rem; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ padding: 0.85rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
    th {{ color: var(--text-muted); font-weight: 600; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .method {{ font-family: monospace; font-weight: 700; }}
    .path {{ font-family: monospace; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🔍 ShadowAPI Audit Report</h1>
        <p style="color: var(--text-muted); margin-top: 0.25rem;">Autonomous API Drift & Zombie Endpoint Discovery Engine</p>
      </div>
      <div>
        <span style="font-size: 0.85rem; color: var(--text-muted);">{report.timestamp}</span>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Risk Index</div>
        <div class="stat-val risk-score">{report.risk_score} / 100</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Observed Endpoints</div>
        <div class="stat-val">{report.observed_endpoints_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Declared Endpoints</div>
        <div class="stat-val">{report.declared_endpoints_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Drift Findings</div>
        <div class="stat-val">{len(report.findings)}</div>
      </div>
    </div>

    <div class="findings-section">
      <div class="findings-header">
        <span>Drift & Inventory Violations</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Endpoint</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
"""

        for f in report.findings:
            b_class = f"badge-{f.severity.lower()}"
            html += f"""          <tr>
            <td><span class="badge {b_class}">{f.severity}</span></td>
            <td><code>{f.drift_type.value}</code></td>
            <td><span class="method">{f.method}</span> <span class="path">{f.path}</span></td>
            <td>{f.description}</td>
          </tr>
"""

        html += f"""        </tbody>
      </table>
    </div>
  </div>
  <script>
    const reportData = {report_data_json};
    console.log("ShadowAPI Report Loaded:", reportData);
  </script>
</body>
</html>"""
        return html
