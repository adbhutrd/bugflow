"""
BugFlow - Phase 5: Report Writing
===================================
Hermes-powered bug bounty report generator.
Turns raw findings into professional, submission-ready reports.
Uses your existing report_template.md format.
"""

import json
import logging
import random
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from core.humanize import random_delay
from core.utils import save_results, load_config, get_output_dir

logger = logging.getLogger("bugflow.phase5_report")


class ReportWriter:
    """Professional bug bounty report writer.
    
    Uses Hermes AI to transform raw findings into submission-ready reports.
    Follows the structure top hunters use (Haddix + InsiderPhD both emphasize
    clear, reproducible reports).
    """

    def __init__(self, config: dict):
        self.config = config
        r_config = config.get("reporting", {})
        self.use_hermes = r_config.get("use_hermes", True)
        self.include_cvss = r_config.get("include_cvss", True)
        self.include_remediation = r_config.get("include_remediation", True)
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))

        # Report template (matches your existing report_template.md)
        self.report_template = """# Vulnerability Report: {title}

**Program:** {program}
**Target:** {target}
**Date:** {date}
**Severity:** {severity}
**CVSS Score:** {cvss}

---

## Summary
{summary}

---

## Steps to Reproduce
{steps}

---

## Proof of Concept
{poc}

---

## Impact
{impact}

---

## Remediation
{remediation}

---

## Technical Details
- **Vulnerability Type:** {vuln_type}
- **Affected Component:** {component}
- **HTTP Method:** {method}
- **Endpoint:** {endpoint}

---

## References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/4.0)
"""

    def run(self, findings: list[dict], target_info: dict = None) -> list[dict]:
        """Generate reports for all findings.
        
        Each finding gets its own professional report.
        Uses Hermes for AI-powered report generation if available.
        """
        logger.info("=" * 50)
        logger.info("PHASE 5: Report Writing (Hermes-powered)")
        logger.info("=" * 50)

        reports = []
        target_info = target_info or {}

        for i, finding in enumerate(findings):
            logger.info(f"  Generating report {i+1}/{len(findings)}...")
            
            if self.use_hermes:
                report = self._generate_hermes_report(finding, target_info)
            else:
                report = self._generate_template_report(finding, target_info)
            
            if report:
                reports.append(report)
            
            random_delay(1, 3)  # Human-like delay between reports

        # Save all reports
        out_dir = get_output_dir("reports", "phase5_reports", str(self.output_dir))
        
        for i, report in enumerate(reports):
            fname = f"report_{i+1}_{report.get('severity','unknown').lower()}.md"
            with open(out_dir / fname, "w") as f:
                f.write(report.get("full_report", ""))
        
        # Save summary
        summary_path = out_dir / "reports_summary.md"
        with open(summary_path, "w") as f:
            f.write("# Bug Bounty Reports Summary\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"**Total Reports:** {len(reports)}\n\n")
            f.write("| # | Severity | Type | Endpoint |\n")
            f.write("|---|---|---|---|\n")
            for i, r in enumerate(reports, 1):
                f.write(f"| {i} | {r.get('severity','?')} | {r.get('vuln_type','?')} | {r.get('endpoint','?')} |\n")

        logger.info(f"Phase 5 complete: {len(reports)} reports generated")
        logger.info(f"  Reports saved to: {out_dir}")
        return reports

    def _generate_hermes_report(self, finding: dict, target_info: dict) -> dict:
        """Generate a professional report using Hermes AI.
        
        Calls the hermes-agent.sh sub-agent to write the report.
        This produces high-quality, human-readable reports.
        """
        severity = finding.get("severity", "medium").upper()
        vuln_type = finding.get("type", "vulnerability")
        endpoint = finding.get("endpoint", finding.get("host", finding.get("url", "unknown")))
        target = target_info.get("name", endpoint)

        # Build a prompt for Hermes
        prompt = self._build_hermes_prompt(finding, target_info)

        try:
            # Call Hermes via the sub-agent script
            result = subprocess.run(
                ["bash", str(Path.home() / "bin" / "hermes-agent.sh"),
                 "--max-turns", "3", prompt],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0 and result.stdout.strip():
                hermes_report = result.stdout.strip()
            else:
                hermes_report = f"Found {severity} {vuln_type} at {endpoint}"
                if result.stderr:
                    logger.warning(f"  Hermes stderr: {result.stderr[:200]}")
        except Exception as e:
            logger.warning(f"  Hermes report generation failed: {e}")
            hermes_report = f"Found {severity} {vuln_type} at {endpoint}"

        # Build the full report
        full_report = self.report_template.format(
            title=f"{severity} {vuln_type} on {target}",
            program=target_info.get("program", target_info.get("name", "Unknown")),
            target=endpoint,
            date=datetime.now().strftime("%Y-%m-%d"),
            severity=severity,
            cvss=self._estimate_cvss(finding),
            summary=hermes_report[:500] if len(hermes_report) > 500 else hermes_report,
            steps=f"1. Navigate to {endpoint}\n2. {hermes_report[:300]}",
            poc=f"```\nRequest: GET {endpoint}\nResponse: {finding.get('status_code', '?')}\n```",
            impact=f"An attacker could exploit this {vuln_type} vulnerability to compromise the {target} application.",
            remediation=f"1. Implement proper access controls\n2. Validate all user input\n3. Follow OWASP guidelines for {vuln_type}",
            vuln_type=vuln_type,
            component=endpoint.split("/")[-1] if "/" in str(endpoint) else str(endpoint),
            method=finding.get("method", "GET"),
            endpoint=endpoint,
        )

        return {
            "full_report": full_report,
            "severity": severity,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "target": target,
            "timestamp": datetime.now().isoformat(),
        }

    def _generate_template_report(self, finding: dict, target_info: dict) -> dict:
        """Generate a report using the standard template (no AI)."""
        severity = finding.get("severity", "medium").upper()
        vuln_type = finding.get("type", "vulnerability")
        endpoint = finding.get("endpoint", finding.get("host", "unknown"))

        full_report = self.report_template.format(
            title=f"{severity} {vuln_type} on {endpoint}",
            program=target_info.get("name", "Unknown"),
            target=endpoint,
            date=datetime.now().strftime("%Y-%m-%d"),
            severity=severity,
            cvss=self._estimate_cvss(finding),
            summary=f"Discovered {vuln_type} vulnerability at {endpoint}",
            steps=f"1. Send request to {endpoint}\n2. Observe the response",
            poc=f"Endpoint: {endpoint}\nStatus: {finding.get('status_code', '?')}",
            impact=f"Potential security impact from {vuln_type}",
            remediation="Implement proper security controls",
            vuln_type=vuln_type,
            component=endpoint.split("/")[-1] if "/" in str(endpoint) else str(endpoint),
            method="GET",
            endpoint=endpoint,
        )

        return {
            "full_report": full_report,
            "severity": severity,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
        }

    def _build_hermes_prompt(self, finding: dict, target_info: dict) -> str:
        """Build a concise prompt for Hermes to write a bug report."""
        severity = finding.get("severity", "medium")
        vuln_type = finding.get("type", "vulnerability")
        endpoint = finding.get("endpoint", finding.get("host", "unknown"))
        
        prompt = (
            f"Write a professional bug bounty vulnerability report for: "
            f"[{severity.upper()}] {vuln_type} found at {endpoint}. "
            f"Include: 1) clear summary 2) steps to reproduce 3) impact assessment. "
            f"Keep it under 200 words. Be specific and technical."
        )
        return prompt

    def _estimate_cvss(self, finding: dict) -> str:
        """Estimate CVSS score based on finding severity."""
        scores = {
            "critical": "9.0 - 10.0",
            "high": "7.0 - 8.9",
            "medium": "4.0 - 6.9",
            "low": "1.0 - 3.9",
            "info": "0.0",
        }
        return scores.get(finding.get("severity", "").lower(), "N/A")


# ==============================================================================
# Standalone report sub-agent
# ==============================================================================

class ReportSubAgent:
    """Standalone sub-agent: Write a report for a single finding."""
    
    def __init__(self, finding: dict):
        self.finding = finding
    
    def run(self) -> dict:
        logger.info(f"  [SUB-AGENT] Writing report for {self.finding.get('type','?')}")
        engine = ReportWriter(load_config())
        reports = engine.run([self.finding])
        return reports[0] if reports else {}


if __name__ == "__main__":
    from core.utils import setup_logging, print_banner, load_config
    setup_logging()
    print_banner()
    
    config = load_config()
    writer = ReportWriter(config)
    
    # Demo with sample finding
    sample = {
        "type": "IDOR",
        "name": "Potential IDOR in user profile endpoint",
        "endpoint": "https://example.com/api/users/123/profile",
        "severity": "high",
        "status_code": 200,
        "method": "GET",
    }
    
    reports = writer.run([sample], {"name": "Example Program"})
    if reports:
        print(f"\nSample report generated. Preview:")
        print(reports[0].get("full_report", "")[:500])
        print("...")
