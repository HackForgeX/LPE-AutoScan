"""
User and Group Security Scanner module.
Audits local users, system accounts, interactive shells, privileged groups (wheel, sudo, docker, lxd, shadow, disk), and unusual membership configurations.
"""

import pwd
import grp
import os
from typing import List, Dict, Set
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class UsersGroupsScanner(BaseScanner):
    name = "users_groups"
    category = Category.USERS_GROUPS
    description = "Audit user accounts, interactive shells, and sensitive group memberships"

    SENSITIVE_GROUPS = {
        "sudo": ("Full sudo administrative access", Severity.HIGH),
        "wheel": ("System administration privileges", Severity.HIGH),
        "root": ("Root group privilege level", Severity.CRITICAL),
        "docker": ("Docker daemon socket access (Equivalent to root)", Severity.CRITICAL),
        "lxd": ("LXD container management (Privilege escalation vector)", Severity.CRITICAL),
        "lxc": ("LXC container management privileges", Severity.HIGH),
        "shadow": ("Read access to encrypted password hashes", Severity.HIGH),
        "disk": ("Raw block device read/write access", Severity.CRITICAL),
        "adm": ("Access to system log files", Severity.LOW),
        "kmem": ("Kernel memory access", Severity.CRITICAL),
    }

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        
        users = pwd.getpwall()
        groups = grp.getgrall()

        current_uid = os.getuid()
        current_user = pwd.getpwuid(current_uid).pw_name

        # 1. Enumerate UID 0 accounts other than 'root'
        uid_zero_users = [u.pw_name for u in users if u.pw_uid == 0 and u.pw_name != "root"]
        if uid_zero_users:
            findings.append(
                Finding(
                    finding_id="USR-001",
                    category=self.category,
                    title="Non-Root Account with UID 0 Discovered",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=f"User account(s) {', '.join(uid_zero_users)} have UID 0 assigned.",
                    evidence=[f"Accounts with UID 0: {', '.join(uid_zero_users)}"],
                    impact="Accounts with UID 0 possess complete root privileges on the Linux system.",
                    exploitation_possible=True,
                    references=["https://attack.mitre.org/techniques/T1078/003/"],
                    mitigation="Change UID of non-root accounts to standard unprivileged UID range (>=1000) or lock accounts."
                )
            )

        # 2. Check current user membership in sensitive groups
        current_user_groups = set()
        for g in groups:
            if current_user in g.gr_mem or g.gr_gid == pwd.getpwuid(current_uid).pw_gid:
                current_user_groups.add(g.gr_name)

        for g_name, (desc, sev) in self.SENSITIVE_GROUPS.items():
            if g_name in current_user_groups:
                findings.append(
                    Finding(
                        finding_id=f"USR-GRP-{g_name.upper()}",
                        category=self.category,
                        title=f"Current User is Member of Sensitive Group '{g_name}'",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        description=f"Current user '{current_user}' belongs to privileged group '{g_name}' ({desc}).",
                        evidence=[f"User: {current_user}", f"Group: {g_name}", f"Details: {desc}"],
                        impact=f"Membership in group '{g_name}' provides elevated capabilities: {desc}.",
                        exploitation_possible=True,
                        references=["https://gtfobins.github.io/"],
                        mitigation=f"Review whether user '{current_user}' strictly requires group '{g_name}' access."
                    )
                )

        # 3. Enumerate all interactive users (UID >= 1000 with valid shell)
        interactive_users = []
        for u in users:
            if u.pw_uid >= 1000 and not u.pw_shell.endswith(("nologin", "false", "sync")):
                interactive_users.append(f"{u.pw_name} (UID: {u.pw_uid}, Shell: {u.pw_shell})")

        findings.append(
            Finding(
                finding_id="USR-002",
                category=self.category,
                title="Interactive User Account Summary",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=f"Identified {len(interactive_users)} interactive user accounts with active login shells.",
                evidence=interactive_users if interactive_users else ["No interactive non-root users found"],
                impact="User accounts define attack surface for credential reuse or local access.",
                exploitation_possible=False,
                references=["https://cisecurity.org/benchmarks"],
                mitigation="Ensure unused or service accounts are set to /usr/sbin/nologin."
            )
        )

        return findings
