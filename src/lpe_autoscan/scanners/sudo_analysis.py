"""
Sudo Configuration Analysis Scanner.
Safely audits effective sudo privileges, /etc/sudoers file, /etc/sudoers.d, NOPASSWD directives, wildcard binary rules (*), and sensitive commands.
"""

import os
import re
import subprocess
from typing import List, Tuple
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class SudoScanner(BaseScanner):
    name = "sudo"
    category = Category.SUDO
    description = "Audit sudoers configuration, NOPASSWD directives, and wildcard binary rules"

    DANGEROUS_SUDO_COMMANDS = [
        "ALL", "find", "vim", "nano", "less", "more", "bash", "sh", "python", "python3",
        "perl", "ruby", "lua", "awk", "gdb", "cp", "mv", "nmap", "tcpdump", "zip", "tar"
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        sudo_lines = self._get_sudoers_lines()

        for line, source in sudo_lines:
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            # Detect NOPASSWD rule
            if "NOPASSWD:" in line_clean:
                # Check for NOPASSWD: ALL
                if "ALL" in line_clean.split("NOPASSWD:")[1]:
                    findings.append(
                        Finding(
                            finding_id="SUDO-NOPASSWD-ALL",
                            category=self.category,
                            title="Sudo NOPASSWD: ALL Rule Detected",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"A sudo rule permitting unrestricted root command execution without password was found in {source}.",
                            evidence=[f"Rule: {line_clean}", f"Source: {source}"],
                            impact="Allows full privilege escalation to root without requiring user credentials.",
                            exploitation_possible=True,
                            references=["https://attack.mitre.org/techniques/T1548/003/"],
                            mitigation="Require password authentication for administrative sudo actions or restrict permitted commands."
                        )
                    )
                else:
                    # Specific command NOPASSWD
                    permitted_cmds = line_clean.split("NOPASSWD:")[1].strip()
                    for danger in self.DANGEROUS_SUDO_COMMANDS:
                        if danger in permitted_cmds:
                            findings.append(
                                Finding(
                                    finding_id=f"SUDO-NOPASSWD-{danger.upper()}",
                                    category=self.category,
                                    title=f"Sudo NOPASSWD Rule for Dangerous Command '{danger}'",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    description=f"Sudo permits passwordless execution of potentially dangerous binary '{danger}'.",
                                    evidence=[f"Rule: {line_clean}", f"Permitted Command: {permitted_cmds}", f"Source: {source}"],
                                    impact=f"If '{danger}' supports shell escaping or arbitrary file operations, unprivileged users can escalate privileges.",
                                    exploitation_possible=True,
                                    references=["https://gtfobins.github.io/"],
                                    mitigation=f"Restrict argument options or require password authentication for '{danger}'."
                                )
                            )

            # Detect wildcard permissions
            if "*" in line_clean and "NOPASSWD" in line_clean:
                findings.append(
                    Finding(
                        finding_id="SUDO-WILDCARD",
                        category=self.category,
                        title="Wildcard '*' Pattern in Sudo Command Specification",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description=f"Sudo rule uses wildcard '*' pattern in permitted command parameters.",
                        evidence=[f"Rule: {line_clean}", f"Source: {source}"],
                        impact="Wildcard matching in sudo parameters often allows path traversal or option injection bypasses.",
                        exploitation_possible=True,
                        references=["https://www.sudo.ws/docs/man/sudoers.man/"],
                        mitigation="Replace wildcard patterns with explicit, absolute command specifications."
                    )
                )

        return findings

    def _get_sudoers_lines(self) -> List[Tuple[str, str]]:
        lines: List[Tuple[str, str]] = []

        # Read /etc/sudoers if accessible
        if os.path.exists("/etc/sudoers") and os.access("/etc/sudoers", os.R_OK):
            try:
                with open("/etc/sudoers", "r") as f:
                    lines.extend([(l, "/etc/sudoers") for l in f.readlines()])
            except Exception:
                pass

        # Read /etc/sudoers.d/ files if accessible
        sudoers_d = "/etc/sudoers.d"
        if os.path.exists(sudoers_d) and os.access(sudoers_d, os.R_OK):
            try:
                for file in os.listdir(sudoers_d):
                    filepath = os.path.join(sudoers_d, file)
                    if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                        with open(filepath, "r") as f:
                            lines.extend([(l, filepath) for l in f.readlines()])
            except Exception:
                pass

        # Try `sudo -l -n` non-interactive run if sudo command is available
        try:
            res = subprocess.run(
                ["sudo", "-l", "-n"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if res.returncode == 0:
                for l in res.stdout.splitlines():
                    if "User " in l or "(ALL" in l or "NOPASSWD:" in l:
                        lines.append((l, "sudo -l -n output"))
        except Exception:
            pass

        return lines
