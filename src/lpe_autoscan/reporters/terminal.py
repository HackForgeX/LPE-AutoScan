"""
Terminal Report Generator module.
Formats security findings into structured terminal summary tables and detailed visual output.
"""

from typing import List, Optional
from lpe_autoscan.models import Finding, Severity
from lpe_autoscan.reporters.base import BaseReporter


class TerminalReporter(BaseReporter):
    """Generates formatted terminal text reports."""

    COLOR_MAP = {
        "CRITICAL": "\033[91m\033[1m",  # Bold Red
        "HIGH": "\033[91m",              # Red
        "MEDIUM": "\033[93m",            # Yellow
        "LOW": "\033[94m",               # Blue
        "INFO": "\033[96m",              # Cyan
        "RESET": "\033[0m"
    }

    def generate(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        lines = []
        lines.append("================================================================================")
        lines.append("          LPE-AUTOSCAN: LINUX PRIVILEGE ESCALATION ASSESSMENT REPORT           ")
        lines.append("================================================================================")
        lines.append("")

        # Severity count summary
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1

        lines.append("FINDINGS SUMMARY BY SEVERITY:")
        lines.append(f"  CRITICAL : {counts['CRITICAL']}")
        lines.append(f"  HIGH     : {counts['HIGH']}")
        lines.append(f"  MEDIUM   : {counts['MEDIUM']}")
        lines.append(f"  LOW      : {counts['LOW']}")
        lines.append(f"  INFO     : {counts['INFO']}")
        lines.append(f"  TOTAL    : {len(findings)}")
        lines.append("--------------------------------------------------------------------------------")
        lines.append("")

        if not findings:
            lines.append("No privilege escalation findings detected.")
        else:
            for idx, f in enumerate(findings, 1):
                lines.append(f"[{idx}] {f.title} ({f.finding_id})")
                lines.append(f"    Severity     : {f.severity.value}")
                lines.append(f"    Confidence   : {f.confidence.value}")
                lines.append(f"    Category     : {f.category.value}")
                lines.append(f"    Description  : {f.description}")
                lines.append("    Evidence     :")
                for ev in f.evidence:
                    lines.append(f"      - {ev}")
                lines.append(f"    Impact       : {f.impact}")
                lines.append(f"    Exploitable  : {'Yes' if f.exploitation_possible else 'No / Needs Verification'}")
                lines.append(f"    Mitigation   : {f.mitigation}")
                if f.references:
                    lines.append("    References   :")
                    for ref in f.references:
                        lines.append(f"      - {ref}")
                lines.append("--------------------------------------------------------------------------------")

        report_str = "\n".join(lines)

        if output_path:
            with open(output_path, "w") as out:
                out.write(report_str)

        return report_str
