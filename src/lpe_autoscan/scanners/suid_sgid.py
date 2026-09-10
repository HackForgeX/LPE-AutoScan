"""
SUID / SGID Binary Discovery and GTFOBins Mapping Scanner.
Recursively audits binaries with SUID/SGID permission bits enabled, checks against expected system allowlist, and maps against local GTFOBins database.
"""

import os
import stat
import json
import pwd
import grp
from typing import List, Dict, Any
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class SuidSgidScanner(BaseScanner):
    name = "suid_sgid"
    category = Category.SUID_SGID
    description = "Audit SUID/SGID binaries and map against GTFOBins database"

    SEARCH_DIRS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"]

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "data", "gtfobins.json")
        
        self.allowlist = set()
        self.gtfobins_db = {}
        if os.path.exists(db_path):
            with open(db_path, "r") as f:
                data = json.load(f)
                self.allowlist = set(data.get("allowlist", []))
                self.gtfobins_db = data.get("gtfobins", {})

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        suid_binaries = []
        sgid_binaries = []

        for base_dir in self.SEARCH_DIRS:
            if not os.path.exists(base_dir):
                continue

            for root, _, files in os.walk(base_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        st = os.lstat(filepath)
                        if stat.S_ISREG(st.st_mode):
                            mode = st.st_mode
                            owner = pwd.getpwuid(st.st_uid).pw_name
                            group = grp.getgrgid(st.st_gid).gr_name

                            # SUID bit set
                            if mode & stat.S_ISUID:
                                suid_binaries.append((filepath, owner, group, mode))

                            # SGID bit set
                            if mode & stat.S_ISGID:
                                sgid_binaries.append((filepath, owner, group, mode))
                    except (PermissionError, FileNotFoundError, KeyError):
                        continue

        # Process SUID binaries
        for path, owner, group, mode in suid_binaries:
            basename = os.path.basename(path)
            real_path = os.path.realpath(path)

            # Map GTFOBins
            if basename in self.gtfobins_db:
                gtfo_info = self.gtfobins_db[basename]
                sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
                sev = sev_map.get(gtfo_info.get("risk_level"), Severity.HIGH)

                findings.append(
                    Finding(
                        finding_id=f"SUID-GTFO-{basename.upper()}",
                        category=self.category,
                        title=f"SUID Binary Identified in GTFOBins Database: '{basename}'",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        description=f"The SUID binary '{path}' (Owner: {owner}) matches a known GTFOBins entry.",
                        evidence=[f"Path: {path}", f"Owner: {owner}", f"GTFOBins Risk: {gtfo_info.get('risk_level')}", f"Reason: {gtfo_info.get('reason')}"],
                        impact=f"If misconfigured or unprivileged execution is permitted, '{basename}' could allow privilege escalation. {gtfo_info.get('reason')}",
                        exploitation_possible=True,
                        references=[gtfo_info.get("reference", "https://gtfobins.github.io/")],
                        mitigation=f"Remove SUID permission bit if not strictly required: chmod u-s {path}"
                    )
                )
            elif path not in self.allowlist and real_path not in self.allowlist and basename not in [os.path.basename(a) for a in self.allowlist]:
                findings.append(
                    Finding(
                        finding_id=f"SUID-UNCOMMON-{basename.upper()}",
                        category=self.category,
                        title=f"Uncommon / Non-Standard SUID Binary: '{basename}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=f"The binary '{path}' has SUID bit set (Owner: {owner}) and is not in standard baseline allowlist.",
                        evidence=[f"Path: {path}", f"Owner: {owner}", f"Permissions: {oct(stat.S_IMODE(mode))}"],
                        impact="Custom or non-standard SUID binaries increase attack surface for privilege escalation.",
                        exploitation_possible=False,
                        references=["https://man7.org/linux/man-pages/man2/stat.2.html"],
                        mitigation=f"Verify business requirement for SUID bit on '{path}'."
                    )
                )

        return findings
