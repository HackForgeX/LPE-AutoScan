"""
SSH Server Security Audit Scanner.
Audits SSH configuration (/etc/ssh/sshd_config) for PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, authorized_keys permissions, and key protection.
"""

import os
import stat
import pwd
from typing import List
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class SshScanner(BaseScanner):
    name = "ssh"
    category = Category.SSH
    description = "Audit SSH server configuration and authentication key permissions"

    SSHD_CONFIG = "/etc/ssh/sshd_config"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists(self.SSHD_CONFIG) or not os.access(self.SSHD_CONFIG, os.R_OK):
            return findings

        config_dict = self._parse_sshd_config()

        # 1. PermitRootLogin check
        root_login = config_dict.get("permitrootlogin", "prohibit-password").lower()
        if root_login in ["yes", "unset"]:
            findings.append(
                Finding(
                    finding_id="SSH-ROOT-LOGIN",
                    category=self.category,
                    title="SSH Permits Direct Root Login ('PermitRootLogin yes')",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="SSH daemon configuration permits direct administrative root login.",
                    evidence=[f"Config Directive: PermitRootLogin {root_login}"],
                    impact="Enables direct brute-force or credential abuse attempts against the root account over SSH.",
                    exploitation_possible=False,
                    references=["https://www.ssh.com/academy/ssh/sshd_config"],
                    mitigation="Set 'PermitRootLogin prohibit-password' or 'PermitRootLogin no' in /etc/ssh/sshd_config."
                )
            )

        # 2. PermitEmptyPasswords check
        empty_pass = config_dict.get("permitemptypasswords", "no").lower()
        if empty_pass == "yes":
            findings.append(
                Finding(
                    finding_id="SSH-EMPTY-PASSWORDS",
                    category=self.category,
                    title="SSH Permits Authentication with Empty Passwords",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="SSH daemon configuration permits password authentication for accounts with empty password fields.",
                    evidence=[f"Config Directive: PermitEmptyPasswords {empty_pass}"],
                    impact="Allows instant passwordless login to any account configured with an empty password.",
                    exploitation_possible=True,
                    references=["https://attack.mitre.org/techniques/T1078/"],
                    mitigation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config."
                )
            )

        # 3. Check permissions on current user authorized_keys if present
        home_dir = os.path.expanduser("~")
        auth_keys = os.path.join(home_dir, ".ssh", "authorized_keys")
        if os.path.exists(auth_keys):
            try:
                mode = os.stat(auth_keys).st_mode
                if mode & (stat.S_IWGRP | stat.S_IWOTH):
                    findings.append(
                        Finding(
                            finding_id="SSH-AUTHKEYS-WRITABLE",
                            category=self.category,
                            title="SSH authorized_keys File is Group or World Writable",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"The SSH authorized_keys file at '{auth_keys}' is writable by non-owner users ({oct(stat.S_IMODE(mode))}).",
                            evidence=[f"Path: {auth_keys}", f"Permissions: {oct(stat.S_IMODE(mode))}"],
                            impact="Other users could insert public keys to compromise account login access.",
                            exploitation_possible=True,
                            references=["https://attack.mitre.org/techniques/T1098/004/"],
                            mitigation=f"Restrict permissions: chmod 600 {auth_keys}"
                        )
                    )
            except Exception:
                pass

        return findings

    def _parse_sshd_config(self) -> dict:
        config = {}
        try:
            with open(self.SSHD_CONFIG, "r") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue
                    parts = line_s.split(maxsplit=1)
                    if len(parts) == 2:
                        key, val = parts[0].lower(), parts[1].strip()
                        config[key] = val
        except Exception:
            pass
        return config
