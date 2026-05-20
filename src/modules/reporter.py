from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

def generate_report(target: str, recon_data: dict,
                    port_data: list, vuln_data: list):

    # Count severities
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in vuln_data:
        severity = f.get("severity", "INFO")
        counts[severity] = counts.get(severity, 0) + 1

    # Overall risk
    if counts["HIGH"] > 0:
        overall_risk = "HIGH"
    elif counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Load template
    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    # Render
    html = template.render(
        target=target,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        recon=recon_data,
        ports=port_data,
        findings=vuln_data,
        counts=counts,
        overall_risk=overall_risk
    )

    # Save report
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename