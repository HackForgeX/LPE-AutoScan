"""
Kernel Information & Local CVE Database Correlation Scanner.
Extracts running kernel version strings and correlates against maintained local CVE vulnerability database, flagging potential vulnerability matches with appropriate confidence ratings.
"""

import os
import platform
import json
import re
from typing import List, Dict, Any
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class KernelCveScanner(BaseScanner):
    name = "kernel_cve"
    category = Category.KERNEL_CVE
    description = "Audit kernel release version against local CVE vulnerability reference database"

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "cve_db.json")

        self.cve_db = []
        if os.path.exists(db_path):
            with open(db_path, "r") as f:
                self.cve_db = json.load(f)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        kernel_version = platform.release()

        version_tuple = self._parse_version(kernel_version)
        if not version_tuple:
            return findings

        for entry in self.cve_db:
            min_v = self._parse_version(entry.get("min_version", "0.0.0"))
            max_v = self._parse_version(entry.get("max_version", "99.99.99"))

            if min_v <= version_tuple <= max_v:
                sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
                sev = sev_map.get(entry.get("severity"), Severity.HIGH)

                findings.append(
                    Finding(
                        finding_id=f"CVE-{entry['cve_id'].replace('-', '_')}",
                        category=self.category,
                        title=f"Potential Kernel Vulnerability Match: {entry['cve_id']} ({entry['product']})",
                        severity=sev,
                        confidence=Confidence.MEDIUM,  # Always set MEDIUM confidence until manual patch verification
                        description=f"Running kernel release '{kernel_version}' falls within affected version range ({entry.get('min_version')} - {entry.get('max_version')}) for {entry['cve_id']}.",
                        evidence=[
                            f"Kernel Version: {kernel_version}",
                            f"CVE ID: {entry['cve_id']}",
                            f"Vulnerability Description: {entry['description']}",
                            f"Affected Version Range: {', '.join(entry.get('affected_versions', []))}"
                        ],
                        impact=f"If unpatched distribution backports are absent, {entry['cve_id']} may permit privilege escalation.",
                        exploitation_possible=False,  # LPE-AutoScan policy: requires verification
                        references=[entry.get("reference", "https://nvd.nist.gov/")],
                        mitigation=entry.get("mitigation", "Update kernel to latest distribution security release.")
                    )
                )

        return findings

    def _parse_version(self, v_str: str) -> tuple:
        match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", v_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            return (major, minor, patch)
        return (0, 0, 0)
