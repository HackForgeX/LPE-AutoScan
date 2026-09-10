"""
System Information Enumeration Scanner.
Collects OS distribution, kernel release, architecture, current UID/GID, group membership, PATH, shell, and root status.
"""

import os
import platform
import pwd
import grp
import subprocess
from typing import List, Dict, Any
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class SysInfoScanner(BaseScanner):
    name = "sysinfo"
    category = Category.SYSINFO
    description = "System, OS, kernel, and environment enumeration"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        info = self.collect_info()

        # Check if current user is root
        if info["uid"] == 0:
            findings.append(
                Finding(
                    finding_id="SYS-001",
                    category=self.category,
                    title="Audit Executed as Root User",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description="The security scanner is currently running with root privileges (UID 0).",
                    evidence=[f"Username: {info['username']}", f"UID: {info['uid']}"],
                    impact="Full system access is already established. Assessment reflects root perspective.",
                    exploitation_possible=False,
                    references=["https://man7.org/linux/man-pages/man7/credentials.7.html"],
                    mitigation="Running as unprivileged user is recommended when evaluating normal user security context."
                )
            )

        # Check for dangerous paths in PATH environment variable
        path_dirs = info["path"].split(":")
        suspicious_paths = [p for p in path_dirs if p == "." or p == "" or (os.path.exists(p) and os.access(p, os.W_OK) and info["uid"] != 0)]
        if suspicious_paths:
            findings.append(
                Finding(
                    finding_id="SYS-002",
                    category=self.category,
                    title="Writable or Relative Path in Environment PATH",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="The PATH environment variable contains relative entries ('.' or empty) or directories writable by the current user.",
                    evidence=[f"Suspicious PATH entries: {', '.join(suspicious_paths)}", f"Full PATH: {info['path']}"],
                    impact="Binary hijacking or PATH prepending attacks could allow arbitrary command execution when commands are run without full paths.",
                    exploitation_possible=True,
                    references=["https://attack.mitre.org/techniques/T1574/007/"],
                    mitigation="Remove relative directories ('.') and ensure all PATH directories are owned by root and read-only to normal users."
                )
            )

        return findings

    def collect_info(self) -> Dict[str, Any]:
        uid = os.getuid()
        gid = os.getgid()
        username = pwd.getpwuid(uid).pw_name
        groupname = grp.getgrgid(gid).gr_name

        groups = [grp.getgrgid(g).gr_name for g in os.getgroups() if g in [g_entry.gr_gid for g_entry in grp.getgrall()]]

        os_release = {}
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        os_release[k] = v.strip('"')

        return {
            "username": username,
            "uid": uid,
            "gid": gid,
            "groupname": groupname,
            "groups": groups,
            "hostname": platform.node(),
            "os_name": os_release.get("PRETTY_NAME", platform.system()),
            "kernel_version": platform.release(),
            "architecture": platform.machine(),
            "shell": os.environ.get("SHELL", "/bin/sh"),
            "path": os.environ.get("PATH", ""),
            "is_root": uid == 0,
        }
