"""
Cron Scheduled Tasks Analysis Scanner.
Parses /etc/crontab, /etc/cron.* directories, and user cron spools to identify privileged cron jobs referencing writable scripts or executables.
"""

import os
import re
import stat
import pwd
import grp
from typing import List, Tuple
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class CronScanner(BaseScanner):
    name = "cron"
    category = Category.CRON
    description = "Audit cron jobs and scheduled task file permissions"

    CRON_FILES = [
        "/etc/crontab",
        "/etc/anacrontab",
    ]

    CRON_DIRS = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        cron_entries = self._collect_cron_entries()

        current_uid = os.getuid()

        for user, cmd, source in cron_entries:
            # Extract executable file paths from command string
            exec_paths = self._extract_paths_from_command(cmd)

            for path in exec_paths:
                if not os.path.exists(path):
                    continue

                try:
                    st = os.stat(path)
                    mode = st.st_mode
                    
                    # If cron job runs as root (or privileged user) and script is writable by current user or world
                    if user in ["root", "ALL"] or st.st_uid == 0:
                        if (mode & stat.S_IWOTH) or (os.access(path, os.W_OK) and current_uid != 0):
                            findings.append(
                                Finding(
                                    finding_id="CRON-WRITABLE-SCRIPT",
                                    category=self.category,
                                    title=f"Root Cron Job Executes Writable Target: '{path}'",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.HIGH,
                                    description=f"Privileged cron task '{cmd}' in {source} executes script '{path}' which is writable by unprivileged users.",
                                    evidence=[f"Cron Entry: {cmd}", f"User: {user}", f"Script Path: {path}", f"Source: {source}"],
                                    impact="Unprivileged users can modify the script content to execute arbitrary commands as root when cron runs.",
                                    exploitation_possible=True,
                                    references=["https://attack.mitre.org/techniques/T1053/003/"],
                                    mitigation=f"Ensure '{path}' is owned by root and writable only by root: chown root:root {path} && chmod 755 {path}"
                                )
                            )
                except (PermissionError, FileNotFoundError):
                    continue

        return findings

    def _collect_cron_entries(self) -> List[Tuple[str, str, str]]:
        entries: List[Tuple[str, str, str]] = []

        for cfile in self.CRON_FILES:
            if os.path.exists(cfile) and os.access(cfile, os.R_OK):
                try:
                    with open(cfile, "r") as f:
                        for line in f:
                            line_s = line.strip()
                            if not line_s or line_s.startswith("#") or "=" in line_s.split()[0]:
                                continue
                            parts = line_s.split()
                            if len(parts) >= 7:
                                user = parts[5]
                                cmd = " ".join(parts[6:])
                                entries.append((user, cmd, cfile))
                except Exception:
                    pass

        for cdir in self.CRON_DIRS:
            if os.path.exists(cdir) and os.access(cdir, os.R_OK):
                try:
                    for filename in os.listdir(cdir):
                        filepath = os.path.join(cdir, filename)
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            with open(filepath, "r") as f:
                                for line in f:
                                    line_s = line.strip()
                                    if not line_s or line_s.startswith("#") or "=" in line_s.split()[0]:
                                        continue
                                    parts = line_s.split()
                                    if len(parts) >= 7:
                                        user = parts[5]
                                        cmd = " ".join(parts[6:])
                                        entries.append((user, cmd, filepath))
                                    elif len(parts) >= 6:
                                        cmd = " ".join(parts[5:])
                                        entries.append(("root", cmd, filepath))
                except Exception:
                    pass

        return entries

    def _extract_paths_from_command(self, cmd: str) -> List[str]:
        paths = []
        tokens = cmd.split()
        for tok in tokens:
            tok_clean = tok.strip("'\"")
            if tok_clean.startswith("/") and os.path.isabs(tok_clean):
                paths.append(tok_clean)
        return paths
