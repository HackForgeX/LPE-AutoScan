"""
Linux Capabilities Audit Scanner.
Runs getcap or parses file capability attributes to identify dangerous capability assignments (cap_setuid, cap_dac_override, cap_sys_admin, cap_net_raw).
"""

import os
import subprocess
import shutil
from typing import List, Tuple
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class CapabilitiesScanner(BaseScanner):
    name = "capabilities"
    category = Category.CAPABILITIES
    description = "Audit Linux POSIX file capabilities"

    SENSITIVE_CAPABILITIES = {
        "cap_setuid": (Severity.CRITICAL, "Allows binary to manipulate UIDs and escalate to root"),
        "cap_setgid": (Severity.HIGH, "Allows binary to manipulate GIDs"),
        "cap_dac_override": (Severity.CRITICAL, "Bypasses all file read/write permission checks"),
        "cap_dac_read_search": (Severity.HIGH, "Bypasses all file read permission checks"),
        "cap_sys_admin": (Severity.CRITICAL, "Provides extensive root administrative capabilities"),
        "cap_sys_ptrace": (Severity.HIGH, "Allows debugging and memory inspection of process memory"),
        "cap_sys_module": (Severity.CRITICAL, "Allows loading arbitrary kernel modules"),
        "cap_net_raw": (Severity.MEDIUM, "Allows raw packet sniffing and binding to sockets"),
    }

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        getcap_bin = shutil.which("getcap")
        if not getcap_bin:
            return findings

        # Run safe getcap read-only scan
        caps_output = self._run_getcap(getcap_bin)

        for filepath, cap_str in caps_output:
            cap_str_lower = cap_str.lower()
            for cap_name, (sev, desc) in self.SENSITIVE_CAPABILITIES.items():
                if cap_name in cap_str_lower:
                    findings.append(
                        Finding(
                            finding_id=f"CAP-{cap_name.upper()}",
                            category=self.category,
                            title=f"Sensitive File Capability Assigned: '{cap_name}' on '{filepath}'",
                            severity=sev,
                            confidence=Confidence.HIGH,
                            description=f"The binary '{filepath}' has sensitive capability '{cap_name}' ({cap_str}) enabled.",
                            evidence=[f"Binary Path: {filepath}", f"Capability String: {cap_str}", f"Risk Details: {desc}"],
                            impact=f"If executable is vulnerable or supports interactive execution, '{cap_name}' allows privilege escalation or security boundary bypass.",
                            exploitation_possible=True,
                            references=["https://man7.org/linux/man-pages/man7/capabilities.7.html", "https://gtfobins.github.io/"],
                            mitigation=f"Remove unnecessary capability from binary: setcap -r {filepath}"
                        )
                    )

        return findings

    def _run_getcap(self, getcap_bin: str) -> List[Tuple[str, str]]:
        results = []
        try:
            res = subprocess.run(
                [getcap_bin, "-r", "/bin", "/sbin", "/usr/bin", "/usr/sbin"],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in res.stdout.splitlines():
                if "=" in line:
                    parts = line.rsplit("=", 1)
                    filepath = parts[0].strip()
                    cap_str = "=" + parts[1].strip()
                    results.append((filepath, cap_str))
        except Exception:
            pass
        return results
