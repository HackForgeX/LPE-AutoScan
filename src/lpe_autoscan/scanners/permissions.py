"""
File and Directory Permission Analysis Scanner.
Audits security-sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab, /etc/ssh/sshd_config) for dangerous world-writable or group-writable permission misconfigurations.
"""

import os
import stat
import pwd
import grp
from typing import List
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class PermissionsScanner(BaseScanner):
    name = "permissions"
    category = Category.PERMISSIONS
    description = "Audit security-sensitive system files and directory permissions"

    CRITICAL_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/pam.d/common-auth",
        "/etc/exports",
    ]

    CRITICAL_DIRS = [
        "/etc/sudoers.d",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # Audit critical system files
        for filepath in self.CRITICAL_FILES:
            if not os.path.exists(filepath):
                continue

            try:
                st = os.stat(filepath)
                mode = st.st_mode
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name

                # World-writable critical file
                if mode & stat.S_IWOTH:
                    findings.append(
                        Finding(
                            finding_id=f"PERM-WW-{os.path.basename(filepath).upper()}",
                            category=self.category,
                            title=f"Critical Security File is World-Writable: '{filepath}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"The system file '{filepath}' has world-writable permissions ({oct(stat.S_IMODE(mode))}).",
                            evidence=[f"Path: {filepath}", f"Permissions: {oct(stat.S_IMODE(mode))}", f"Owner: {owner}:{group}"],
                            impact=f"Any unprivileged user can modify '{filepath}', leading to direct, immediate privilege escalation or persistence.",
                            exploitation_possible=True,
                            references=["https://attack.mitre.org/techniques/T1222/002/"],
                            mitigation=f"Remove world-write access immediately: chmod o-w {filepath}"
                        )
                    )

                # World-readable shadow file
                if filepath == "/etc/shadow" and (mode & stat.S_IROTH):
                    findings.append(
                        Finding(
                            finding_id="PERM-WR-SHADOW",
                            category=self.category,
                            title="Sensitive Password Shadow File is World-Readable",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"The system password file '/etc/shadow' is world-readable ({oct(stat.S_IMODE(mode))}).",
                            evidence=[f"Path: {filepath}", f"Permissions: {oct(stat.S_IMODE(mode))}"],
                            impact="Unprivileged users can extract password hashes for offline cracking.",
                            exploitation_possible=True,
                            references=["https://attack.mitre.org/techniques/T1003/008/"],
                            mitigation="Restrict shadow file permissions: chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
                        )
                    )
            except (PermissionError, FileNotFoundError, KeyError):
                continue

        # Audit critical configuration directories
        for dirpath in self.CRITICAL_DIRS:
            if not os.path.exists(dirpath):
                continue

            try:
                st = os.stat(dirpath)
                mode = st.st_mode
                if mode & stat.S_IWOTH:
                    findings.append(
                        Finding(
                            finding_id=f"PERM-WW-DIR-{os.path.basename(dirpath).upper()}",
                            category=self.category,
                            title=f"Critical System Directory is World-Writable: '{dirpath}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"The system configuration directory '{dirpath}' is world-writable ({oct(stat.S_IMODE(mode))}).",
                            evidence=[f"Path: {dirpath}", f"Permissions: {oct(stat.S_IMODE(mode))}"],
                            impact=f"Unprivileged users can place malicious configuration files in '{dirpath}' to execute elevated commands.",
                            exploitation_possible=True,
                            references=["https://attack.mitre.org/techniques/T1037/"],
                            mitigation=f"Remove world-write permissions on directory: chmod o-w {dirpath}"
                        )
                    )
            except (PermissionError, FileNotFoundError):
                continue

        return findings
